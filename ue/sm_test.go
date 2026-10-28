package ue

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/free-ran-ue/free-ran-ue/v2/model"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/go-playground/assert"
)

// fakeGnb is the gNB end of the UE control connection, with the AMF's NAS security context.
type fakeGnb struct {
	t      *testing.T
	conn   net.Conn
	secCtx *message.SecCtx
}

// newSmTestUe returns a registered UE whose control connection ends at a fake gNB.
func newSmTestUe(t *testing.T) (*Ue, *fakeGnb) {
	t.Helper()

	u := newTestUe(t, ueIeForSmTest())
	knasEnc := [16]byte{1, 2, 3}
	knasInt := [16]byte{4, 5, 6}
	u.secCtx.CipheringAlg = message.AlgCiphering128NEA2
	u.secCtx.IntegrityAlg = message.AlgIntegrity128NIA2
	u.secCtx.KnasEnc = knasEnc
	u.secCtx.KnasInt = knasInt

	ueEnd, gnbEnd := net.Pipe()
	u.ranControlPlaneConn = ueEnd
	t.Cleanup(func() { _ = ueEnd.Close(); _ = gnbEnd.Close() })

	return u, &fakeGnb{
		t:    t,
		conn: gnbEnd,
		secCtx: message.NewSecCtx(message.CoreNetworkSide, message.OnlyOneBearer,
			message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2, knasEnc[:], knasInt[:]),
	}
}

// sendSm sends a 5GSM message to the UE in a DL NAS Transport.
func (g *fakeGnb) sendSm(m message.GSMMessage) {
	g.t.Helper()

	sm, err := m.MarshalBinary()
	assert.Equal(g.t, nil, err)
	dlNasTransport := &message.DLNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Pct: ie.PayloadCntrType_N1SMInfo, Contents: sm},
		PDUSessID:       &ie.PDUSessId2{Value: m.PDUSessionID()},
	}
	nas, err := message.Marshal(dlNasTransport, g.secCtx, message.SecHdrTypeIntegrityProtectedAndCiphered)
	assert.Equal(g.t, nil, err)
	assert.Equal(g.t, nil, g.conn.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err = g.conn.Write(nas)
	assert.Equal(g.t, nil, err)
}

// receiveSm returns the 5GSM message of the next UL NAS Transport from the UE.
func (g *fakeGnb) receiveSm() message.GSMMessage {
	g.t.Helper()

	buffer := make([]byte, 65535)
	assert.Equal(g.t, nil, g.conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err := g.conn.Read(buffer)
	if err != nil {
		g.t.Fatalf("no uplink NAS from the UE: %v", err)
	}
	nas, err := message.Parse(buffer[:n], g.secCtx)
	assert.Equal(g.t, nil, err)
	ulNasTransport, ok := nas.(*message.ULNASTransport)
	if !ok {
		g.t.Fatalf("uplink NAS is %T, expected UL NAS Transport", nas)
	}
	sm, err := message.ParseGSM(ulNasTransport.PayloadCntr.Contents)
	assert.Equal(g.t, nil, err)
	return sm
}

// recordingObserver records the NAS events and answers Modification Commands with reply.
type recordingObserver struct {
	reply  ModificationCommandReply
	events chan any
}

type establishmentAccepted struct{ containers []ie.OperatorContainer }

type modificationCommand struct {
	pti        uint8
	containers []ie.OperatorContainer
}

type modificationRejected struct {
	pti        uint8
	cause      uint8
	containers []ie.OperatorContainer
}

type pduSessionReleased struct{ cause uint8 }

type ueContextReleased struct{}

type dataPlaneError struct{}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{events: make(chan any, 8)}
}

func (o *recordingObserver) PduSessionEstablishmentAccepted(c []ie.OperatorContainer) {
	o.events <- establishmentAccepted{c}
}

func (o *recordingObserver) PduSessionModificationCommand(pti uint8, c []ie.OperatorContainer) ModificationCommandReply {
	o.events <- modificationCommand{pti, c}
	return o.reply
}

func (o *recordingObserver) PduSessionModificationRejected(pti, cause uint8, c []ie.OperatorContainer) {
	o.events <- modificationRejected{pti, cause, c}
}

func (o *recordingObserver) PduSessionReleased(cause uint8) {
	o.events <- pduSessionReleased{cause}
}

func (o *recordingObserver) UeContextReleased() {
	o.events <- ueContextReleased{}
}

func (o *recordingObserver) DataPlaneError(error) {
	o.events <- dataPlaneError{}
}

func (o *recordingObserver) next(t *testing.T) any {
	t.Helper()
	select {
	case event := <-o.events:
		return event
	case <-time.After(2 * time.Second):
		t.Fatal("observer got no event")
		return nil
	}
}

var (
	capabilityContainer = ie.OperatorContainer{ID: 0xFF00, Contents: []byte{}}
	ruleSetContainer    = ie.OperatorContainer{ID: 0xFF01, Contents: []byte{0x02, 0xF8, 0x39, 0x01, 0x10, 0x02, 0xAB, 0xCD}}
	dlStateContainer    = ie.OperatorContainer{ID: 0xFF03, Contents: []byte{0x02, 0xF8, 0x39, 0x01, 0x05, 0x00}}
	switchContainer     = ie.OperatorContainer{ID: 0xFF02, Contents: []byte{0x02, 0xF8, 0x39, 0x01, 0x07, 0x01, 0x01}}
)

func TestEstablishmentRequestCarriesOperatorContainers(t *testing.T) {
	u, gnb := newSmTestUe(t)
	observer := newRecordingObserver()
	u.SetNasObserver(observer)
	u.SetEstablishmentRequestContainers([]ie.OperatorContainer{capabilityContainer})

	established := make(chan error, 1)
	go func() { established <- u.processPduSessionEstablishment() }()

	estReq, ok := gnb.receiveSm().(*message.PDUSessEstReq)
	if !ok {
		t.Fatal("UE did not send an Establishment Request")
	}
	assert.Equal(t, []ie.OperatorContainer{capabilityContainer}, estReq.ExtendedProtCfgOpts.FromMs.OperatorContainers)

	gnb.sendSm(&message.PDUSessEstAccept{
		PDUSessId:           estReq.PDUSessId,
		SelectedPDUSessType: &ie.PDUSessType{Value: ie.PDUSessType_IPv4},
		SelectedSSCMode:     &ie.SSCMode{Mode: ie.SSCMODE1},
		AuthoQosRules: &ie.QosRules{Rules: []ie.QosRule{{
			RuleId:       1,
			OpCode:       ie.OpCode_CreateNewQosRule,
			IsDefaultDQR: true,
			Precedence:   255,
			QFI:          1,
			PktFilterList: []ie.PacketFilter{{
				Dir:      ie.PFD_BiDir,
				Id:       1,
				Contents: ie.PacketFilterContents{MatchAll: true, RemoteAddr: "any", LocalAddr: "assigned"},
			}},
		}}},
		SessAMBR: &ie.SessAMBR{},
		PDUAddr:  &ie.PDUAddr{IPv4: []byte{10, 60, 0, 1}},
		ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{FromNw: &ie.ExtCfgOptFromNw{
			OperatorContainers: []ie.OperatorContainer{ruleSetContainer, dlStateContainer},
		}},
	})

	assert.Equal(t, nil, <-established)
	assert.Equal(t, establishmentAccepted{[]ie.OperatorContainer{ruleSetContainer, dlStateContainer}}, observer.next(t))
	assert.Equal(t, "10.60.0.1", u.GetUeIp())
}

// startSmTestUe starts the downlink NAS dispatcher of a UE with an established PDU session.
func startSmTestUe(t *testing.T, observer NasObserver) (*Ue, *fakeGnb) {
	t.Helper()

	u, gnb := newSmTestUe(t)
	u.SetNasObserver(observer)
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	u.startNasDispatcher(ctx, &wg)
	t.Cleanup(cancel)
	return u, gnb
}

func ueIeForSmTest() model.UeIE {
	ueIe := model.UeIE{}
	ueIe.PduSession.Dnn = "internet"
	return ueIe
}

func TestModificationCommandIsAnsweredAsTheObserverDecides(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		observer := newRecordingObserver()
		_, gnb := startSmTestUe(t, observer)

		gnb.sendSm(&message.PDUSessModCmd{
			PDUSessId: 1,
			PTI:       0,
			ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{FromNw: &ie.ExtCfgOptFromNw{
				OperatorContainers: []ie.OperatorContainer{ruleSetContainer, dlStateContainer},
			}},
		})

		assert.Equal(t, modificationCommand{0, []ie.OperatorContainer{ruleSetContainer, dlStateContainer}}, observer.next(t))
		modComplete, ok := gnb.receiveSm().(*message.PDUSessModComplete)
		if !ok {
			t.Fatal("UE did not send a Modification Complete")
		}
		assert.Equal(t, uint8(1), modComplete.PDUSessId)
		assert.Equal(t, uint8(0), modComplete.PTI)
	})

	t.Run("reject with cause", func(t *testing.T) {
		observer := newRecordingObserver()
		observer.reply = ModificationCommandReply{Reject: true, Cause: 0x6F}
		_, gnb := startSmTestUe(t, observer)

		gnb.sendSm(&message.PDUSessModCmd{
			PDUSessId: 1,
			PTI:       0,
			ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{FromNw: &ie.ExtCfgOptFromNw{
				OperatorContainers: []ie.OperatorContainer{ruleSetContainer},
			}},
		})

		assert.Equal(t, modificationCommand{0, []ie.OperatorContainer{ruleSetContainer}}, observer.next(t))
		modCmdReject, ok := gnb.receiveSm().(*message.PDUSessModCmdRej)
		if !ok {
			t.Fatal("UE did not send a Modification Command Reject")
		}
		assert.Equal(t, uint8(1), modCmdReject.PDUSessId)
		assert.Equal(t, uint8(0), modCmdReject.PTI)
		assert.Equal(t, uint8(0x6F), modCmdReject.Cause5GSM.Value)
	})
}

func TestModificationRejectReachesTheObserver(t *testing.T) {
	observer := newRecordingObserver()
	u, gnb := startSmTestUe(t, observer)

	sent := make(chan uint8, 1)
	go func() {
		pti, err := u.SendPduSessionModificationRequest([]ie.OperatorContainer{switchContainer})
		assert.Equal(t, nil, err)
		sent <- pti
	}()
	modReq, ok := gnb.receiveSm().(*message.PDUSessModReq)
	if !ok {
		t.Fatal("UE did not send a Modification Request")
	}
	pti := <-sent
	assert.Equal(t, pti, modReq.PTI)
	assert.Equal(t, []ie.OperatorContainer{switchContainer}, modReq.ExtendedProtCfgOpts.FromMs.OperatorContainers)

	gnb.sendSm(&message.PDUSessModRej{
		PDUSessId: modReq.PDUSessId,
		PTI:       pti,
		Cause5GSM: &ie.Cause5GSM{Value: 0x1F},
		ExtendedProtCfgOpts: &ie.ExtendedProtCfgOpts{FromNw: &ie.ExtCfgOptFromNw{
			OperatorContainers: []ie.OperatorContainer{dlStateContainer, ruleSetContainer},
		}},
	})

	assert.Equal(t, modificationRejected{pti, 0x1F, []ie.OperatorContainer{dlStateContainer, ruleSetContainer}}, observer.next(t))
	assert.NotEqual(t, nil, u.ResendPduSessionModificationRequest(pti))
}

func TestModificationRequestResendKeepsItsPti(t *testing.T) {
	u, gnb := startSmTestUe(t, newRecordingObserver())

	sent := make(chan uint8, 1)
	go func() {
		pti, err := u.SendPduSessionModificationRequest([]ie.OperatorContainer{switchContainer})
		assert.Equal(t, nil, err)
		sent <- pti
	}()
	first := gnb.receiveSm().(*message.PDUSessModReq)
	pti := <-sent

	go func() { assert.Equal(t, nil, u.ResendPduSessionModificationRequest(pti)) }()
	resent := gnb.receiveSm().(*message.PDUSessModReq)
	assert.Equal(t, first.PTI, resent.PTI)
	assert.Equal(t, first.ExtendedProtCfgOpts.FromMs.OperatorContainers, resent.ExtendedProtCfgOpts.FromMs.OperatorContainers)

	go func() {
		_, err := u.SendPduSessionModificationRequest([]ie.OperatorContainer{switchContainer})
		assert.Equal(t, nil, err)
	}()
	next := gnb.receiveSm().(*message.PDUSessModReq)
	assert.NotEqual(t, first.PTI, next.PTI)
}

func TestNetworkReleasesAreReported(t *testing.T) {
	t.Run("PDU session release", func(t *testing.T) {
		observer := newRecordingObserver()
		_, gnb := startSmTestUe(t, observer)

		gnb.sendSm(&message.PDUSessRelCmd{PDUSessId: 1, PTI: 0, Cause5GSM: &ie.Cause5GSM{Value: 0x24}})

		releaseComplete, ok := gnb.receiveSm().(*message.PDUSessRelComplete)
		if !ok {
			t.Fatal("UE did not send a Release Complete")
		}
		assert.Equal(t, uint8(1), releaseComplete.PDUSessId)
		assert.Equal(t, pduSessionReleased{0x24}, observer.next(t))
	})

	t.Run("UE context release", func(t *testing.T) {
		observer := newRecordingObserver()
		_, gnb := startSmTestUe(t, observer)

		assert.Equal(t, nil, gnb.conn.Close())

		assert.Equal(t, ueContextReleased{}, observer.next(t))
	})
}

func TestDataPlaneSocketErrorIsReported(t *testing.T) {
	// a port nobody listens on, so the gNB host answers with ICMP port unreachable
	unused, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	assert.Equal(t, nil, err)
	port := unused.LocalAddr().(*net.UDPAddr).Port
	assert.Equal(t, nil, unused.Close())

	ueIe := ueIeForSmTest()
	ueIe.RanDataPlaneIp = "127.0.0.1"
	ueIe.RanDataPlanePort = port
	ueIe.ExternalDataPlane = true
	u := newTestUe(t, ueIe)
	observer := newRecordingObserver()
	u.SetNasObserver(observer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := sync.WaitGroup{}
	assert.Equal(t, nil, u.connectToRanDataPlane())
	defer func() { _ = u.ranDataPlaneConn.Close() }()
	assert.Equal(t, nil, u.startDataPlane(ctx, &wg))

	assert.Equal(t, dataPlaneError{}, observer.next(t))
}

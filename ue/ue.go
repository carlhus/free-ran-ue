package ue

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free-ran-ue/free-ran-ue/v2/logger"
	"github.com/free-ran-ue/free-ran-ue/v2/model"
	"github.com/free-ran-ue/util"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/songgao/water"
)

type authentication struct {
	supi string

	kAmf []uint8

	secCtx *message.SecCtx
}

type authenticationSubscription struct {
	authenticationMethod          models.Udr_DR_AuthMethod
	encPermanentKey               string
	encOpcKey                     string
	authenticationManagementField string
	sequenceNumber                string
}

type pduSession struct {
	dnn    string
	sNssai *models.Snssai
}

type pduSessionEstablishmentAccept struct {
	ueIp    string
	qosRule []uint8
	dnn     string
	sst     uint8
	sd      [3]uint8
}

type dcRanDataPlane struct {
	ip   string
	port int
}

type nrdc struct {
	enable bool
	dcRanDataPlane
	dcLocalDataPlaneIp string
	specifiedFlow      []string
	rwLock             sync.RWMutex
}

type Ue struct {
	ranControlPlaneIp   string
	ranDataPlaneIp      string
	localDataPlaneIp    string
	localControlPlaneIp string

	ranControlPlanePort int
	ranDataPlanePort    int

	ranControlPlaneConn net.Conn
	ranDataPlaneConn    net.Conn
	dcRanDataPlaneConn  net.Conn

	mcc  string
	mnc  string
	msin string

	authentication

	accessType models.AccessType
	authenticationSubscription

	pduSession

	nrdc

	ueTunnelDeviceName string
	externalDataPlane  bool
	ueTunnelDevice     *water.Interface

	// uplink packets from the TUN, or from the embedding process with an external data plane
	uplink chan []byte
	// downlink packets to the TUN, or to the embedding process with an external data plane
	downlink chan []byte
	// closed by Stop so the data plane goroutines exit
	stopped chan struct{}

	pduSessionEstablishmentAccept

	nasObserver                    NasObserver
	establishmentRequestContainers []ie.OperatorContainer

	// serializes uplink NAS after registration, which shares the uplink NAS COUNT
	uplinkNasMtx sync.Mutex
	// guards lastPti and pendingModificationRequests
	smMtx sync.Mutex
	// the PTI of the latest Modification Request
	lastPti uint8
	// plain 5GSM bytes of each Modification Request not yet answered, by PTI
	pendingModificationRequests map[uint8][]byte
	// closed when the downlink NAS dispatcher exits; nil until it starts
	nasDispatcherDone chan struct{}

	*logger.UeLogger
}

func NewUe(config *model.UeConfig, logger *logger.UeLogger) *Ue {
	supi := config.Ue.PlmnId.Mcc + config.Ue.PlmnId.Mnc + config.Ue.Msin

	var integrityAlgorithm ie.AlgIntegrity
	if config.Ue.IntegrityAlgorithm.Nia0 {
		integrityAlgorithm = message.AlgIntegrity128NIA0
	} else if config.Ue.IntegrityAlgorithm.Nia1 {
		integrityAlgorithm = message.AlgIntegrity128NIA1
	} else if config.Ue.IntegrityAlgorithm.Nia2 {
		integrityAlgorithm = message.AlgIntegrity128NIA2
	} else if config.Ue.IntegrityAlgorithm.Nia3 {
		integrityAlgorithm = message.AlgIntegrity128NIA3
	}

	var cipheringAlgorithm ie.AlgCiphering
	if config.Ue.CipheringAlgorithm.Nea0 {
		cipheringAlgorithm = message.AlgCiphering128NEA0
	} else if config.Ue.CipheringAlgorithm.Nea1 {
		cipheringAlgorithm = message.AlgCiphering128NEA1
	} else if config.Ue.CipheringAlgorithm.Nea2 {
		cipheringAlgorithm = message.AlgCiphering128NEA2
	} else if config.Ue.CipheringAlgorithm.Nea3 {
		cipheringAlgorithm = message.AlgCiphering128NEA3
	}

	bearer := message.OnlyOneBearer
	switch models.AccessType(config.Ue.AccessType) {
	case models.AccessType_3_GPP_ACCESS:
		bearer = message.Bearer3GPP
	case models.AccessType_NON_3_GPP_ACCESS:
		bearer = message.BearerNon3GPP
	}

	sstInt, err := strconv.Atoi(config.Ue.PduSession.Snssai.Sst)
	if err != nil {
		logger.CfgLog.Errorf("Error converting sst to int: %v", err)
	}

	return &Ue{
		ranControlPlaneIp:   config.Ue.RanControlPlaneIp,
		ranDataPlaneIp:      config.Ue.RanDataPlaneIp,
		localDataPlaneIp:    config.Ue.LocalDataPlaneIp,
		localControlPlaneIp: config.Ue.LocalControlPlaneIp,

		ranControlPlanePort: config.Ue.RanControlPlanePort,
		ranDataPlanePort:    config.Ue.RanDataPlanePort,

		mcc:  config.Ue.PlmnId.Mcc,
		mnc:  config.Ue.PlmnId.Mnc,
		msin: config.Ue.Msin,

		authentication: authentication{
			supi: supi,

			secCtx: &message.SecCtx{
				Side:          message.UESide,
				Bearer:        bearer,
				UplinkCount:   &message.Count{},
				DownlinkCount: &message.Count{},
				CipheringAlg:  cipheringAlgorithm,
				IntegrityAlg:  integrityAlgorithm,
			},
		},

		accessType: models.AccessType(config.Ue.AccessType),
		authenticationSubscription: authenticationSubscription{
			authenticationMethod:          models.Udr_DR_AuthMethod_5_G_AKA,
			encPermanentKey:               config.Ue.AuthenticationSubscription.EncPermanentKey,
			encOpcKey:                     config.Ue.AuthenticationSubscription.EncOpcKey,
			authenticationManagementField: config.Ue.AuthenticationSubscription.AuthenticationManagementField,
			sequenceNumber:                config.Ue.AuthenticationSubscription.SequenceNumber,
		},

		pduSession: pduSession{
			dnn: config.Ue.PduSession.Dnn,
			sNssai: &models.Snssai{
				Sst: int32(sstInt),
				Sd:  config.Ue.PduSession.Snssai.Sd,
			},
		},

		nrdc: nrdc{
			enable: config.Ue.Nrdc.Enable,
			dcRanDataPlane: dcRanDataPlane{
				ip:   config.Ue.Nrdc.DcRanDataPlane.Ip,
				port: config.Ue.Nrdc.DcRanDataPlane.Port,
			},
			dcLocalDataPlaneIp: config.Ue.Nrdc.DcLocalDataPlaneIp,
			specifiedFlow:      make([]string, 0),
			rwLock:             sync.RWMutex{},
		},

		ueTunnelDeviceName: config.Ue.UeTunnelDevice,
		externalDataPlane:  config.Ue.ExternalDataPlane,

		uplink:   make(chan []byte),
		downlink: make(chan []byte, 2),
		stopped:  make(chan struct{}),

		nasObserver:                 nopNasObserver{},
		pendingModificationRequests: make(map[uint8][]byte),

		UeLogger: logger,
	}
}

// SetNasObserver sets the observer of the PDU session events. Call it before Start.
func (u *Ue) SetNasObserver(observer NasObserver) {
	u.nasObserver = observer
}

// SetEstablishmentRequestContainers sets the operator containers that the
// Establishment Request carries in its ePCO. Call it before Start.
func (u *Ue) SetEstablishmentRequestContainers(operatorContainers []ie.OperatorContainer) {
	u.establishmentRequestContainers = operatorContainers
}

func (u *Ue) Start(ctx context.Context, wg *sync.WaitGroup) error {
	u.UeLog.Infof("Starting UE: imsi-%s", u.supi)

	if err := u.connectToRanControlPlane(); err != nil {
		u.UeLog.Errorf("Error connecting to RAN: %v", err)
		return err
	}

	if err := u.processUeRegistration(); err != nil {
		u.UeLog.Errorf("Error processing UE registration: %v", err)
		if err := u.ranControlPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing RAN connection: %v", err)
		}
		return err
	}

	if err := u.processPduSessionEstablishment(); err != nil {
		u.UeLog.Errorf("Error processing PDU session establishment: %v", err)
		if err := u.ranControlPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing RAN connection: %v", err)
		}
		return err
	}

	if err := u.connectToRanDataPlane(); err != nil {
		u.UeLog.Errorf("Error connecting to RAN data plane: %v", err)
		if err := u.ranControlPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing RAN connection: %v", err)
		}
		return err
	}

	if err := u.startDataPlane(ctx, wg); err != nil {
		u.UeLog.Errorf("Error starting data plane: %v", err)
		if err := u.ranDataPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing RAN connection: %v", err)
		}
		if err := u.ranControlPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing RAN connection: %v", err)
		}
		return err
	}

	u.startNasDispatcher(ctx, wg)

	u.UeLog.Infoln("UE started")
	return nil
}

func (u *Ue) Stop() {
	u.UeLog.Infof("Stopping UE: imsi-%s", u.supi)

	close(u.stopped)

	// deregistration reads its accept itself, so the dispatcher must not race it for downlink NAS
	if u.nasDispatcherDone != nil {
		<-u.nasDispatcherDone
	}

	if err := u.processUeDeregistration(); err != nil {
		u.UeLog.Errorf("Error processing UE deregistration: %v", err)
	}

	if err := u.cleanUpTunnelDevice(); err != nil {
		u.UeLog.Errorf("Error cleaning up tunnel device: %v", err)
	}

	if err := u.ranDataPlaneConn.Close(); err != nil {
		u.UeLog.Errorf("Error closing RAN connection: %v", err)
	}

	if u.isNrdcEnabled() {
		if err := u.dcRanDataPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing DC RAN connection: %v", err)
		}
	}

	if err := u.ranControlPlaneConn.Close(); err != nil {
		u.UeLog.Errorf("Error closing RAN connection: %v", err)
	}

	u.UeLog.Infoln("UE stopped")
}

func (u *Ue) connectToRanControlPlane() error {
	u.RanLog.Infoln("Connecting to RAN control plane")

	u.RanLog.Tracef("RAN control plane address: %s:%d", u.ranControlPlaneIp, u.ranControlPlanePort)

	conn, err := util.TcpDialWithOptionalLocalAddress(u.ranControlPlaneIp, u.ranControlPlanePort, u.localControlPlaneIp)
	if err != nil {
		return err
	}

	u.RanLog.Debugln("Dial TCP to RAN control plane success")

	u.ranControlPlaneConn = conn

	u.RanLog.Infof("Connected to RAN control plane: %s:%d", u.ranControlPlaneIp, u.ranControlPlanePort)
	return nil
}

func (u *Ue) connectToRanDataPlane() error {
	u.RanLog.Infoln("Connecting to RAN data plane")

	u.RanLog.Tracef("RAN data plane address: %s:%d", u.ranDataPlaneIp, u.ranDataPlanePort)

	conn, err := util.UdpDialWithOptionalLocalAddress(u.ranDataPlaneIp, u.ranDataPlanePort, u.localDataPlaneIp)
	if err != nil {
		return err
	}
	u.ranDataPlaneConn = conn
	u.RanLog.Debugln("Dial UDP to RAN data plane success")

	_, err = u.ranDataPlaneConn.Write([]byte(constant.UE_DATA_PLANE_INITIAL_PACKET + " " + constant.UE_IMSI_PREFIX + u.supi))
	if err != nil {
		return fmt.Errorf("error send initial packet: %+v", err)
	}
	u.RanLog.Debugln("Sent initial packet to RAN data plane UDP server")

	if u.isNrdcEnabled() {
		conn, err := util.UdpDialWithOptionalLocalAddress(u.nrdc.dcRanDataPlane.ip, u.nrdc.dcRanDataPlane.port, u.nrdc.dcLocalDataPlaneIp)
		if err != nil {
			return err
		}
		u.dcRanDataPlaneConn = conn
		u.RanLog.Debugln("Dial UDP to DC RAN data plane success")

		_, err = u.dcRanDataPlaneConn.Write([]byte(constant.UE_DATA_PLANE_INITIAL_PACKET + " " + constant.UE_IMSI_PREFIX + u.supi))
		if err != nil {
			return fmt.Errorf("error send initial packet: %+v", err)
		}
		u.RanLog.Debugln("Sent initial packet to DC RAN data plane UDP server")
	}

	u.RanLog.Infof("Connected to RAN data plane: %s:%d", u.ranDataPlaneIp, u.ranDataPlanePort)
	return nil
}

func (u *Ue) processUeRegistration() error {
	u.RanLog.Infoln("Processing UE Registration")

	mobileIdentity5GS, err := buildUeMobileIdentity5GS(len(u.mcc), len(u.mnc), u.supi)
	if err != nil {
		return fmt.Errorf("error build mobile identity 5gs: %+v", err)
	}
	u.NasLog.Tracef("Mobile identity 5GS: %+v", mobileIdentity5GS)

	ueSecurityCapability := buildUeSecurityCapability(u.secCtx.CipheringAlg, u.secCtx.IntegrityAlg)
	u.NasLog.Tracef("UE security capability: %+v", ueSecurityCapability)

	// send ue registration request
	registrationRequest, err := getUeRegistrationRequest(ie.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("error get ue registration request: %+v", err)
	}
	u.NasLog.Tracef("Get UE %s registration request: %+v", u.supi, registrationRequest)

	n, err := u.ranControlPlaneConn.Write(registrationRequest)
	if err != nil {
		return fmt.Errorf("error send ue registration request: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of UE %s registration request", n, u.supi)
	u.NasLog.Debugln("Send UE registration request")

	// receive nas authentication request
	authenticationRequest, err := readAndDecodeNas[*message.AuthReq](u, "NAS Authentication Request")
	if err != nil {
		return err
	}

	// calculate for RES* and send nas authentication response
	rand, autn := authenticationRequest.AuthParamRAND5GAuthChlg.Rand, authenticationRequest.AuthParamAUTN5GAuthChlg.Autn

	mcc := u.mcc
	if len(mcc) == 2 {
		mcc = "0" + mcc
	}
	mnc := u.mnc
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	snName := fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)

	kAmf, kenc, kint, resStar, newSqn, err := deriveResStarAndSetKey(fmt.Sprintf("supi-%s", u.supi), u.secCtx.CipheringAlg, u.secCtx.IntegrityAlg, u.authenticationSubscription.sequenceNumber, u.authenticationSubscription.authenticationManagementField, u.authenticationSubscription.encPermanentKey, u.authenticationSubscription.encOpcKey, rand, autn, snName)
	if err != nil {
		return fmt.Errorf("error derive res star and set key: %+v", err)
	} else {
		u.kAmf = kAmf
		copy(u.secCtx.KnasEnc[:], kenc[16:32])
		copy(u.secCtx.KnasInt[:], kint[16:32])
		u.authenticationSubscription.sequenceNumber = newSqn

		u.NasLog.Tracef("RES*: %+v", resStar)
		u.NasLog.Tracef("kAMF: %+v", kAmf)
		u.NasLog.Tracef("kNAS_ENC: %+v", kenc)
		u.NasLog.Tracef("kNAS_INT: %+v", kint)
		u.NasLog.Tracef("New SQN: %s", newSqn)
	}

	authenticationResponse, err := getAuthenticationResponse(resStar)
	if err != nil {
		return fmt.Errorf("error get authentication response: %+v", err)
	}
	u.NasLog.Tracef("Authentication response: %+v", authenticationResponse)

	n, err = u.ranControlPlaneConn.Write(authenticationResponse)
	if err != nil {
		return fmt.Errorf("error send authentication response: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of Authentication Response to RAN", n)
	u.NasLog.Debugln("Send Authentication Response to RAN")

	// receive nas security mode command message
	securityModeCommand, err := readAndDecodeNas[*message.SecModeCmd](u, "NAS Security Mode Command")
	if err != nil {
		return err
	}

	u.secCtx.CipheringAlg = securityModeCommand.SelectedNASSecAlgos.CipheringAlgo
	u.secCtx.IntegrityAlg = securityModeCommand.SelectedNASSecAlgos.MsgIntAlgo

	kenc, kint, errAlg := deriveAlgorithmKey(u.kAmf, u.secCtx.CipheringAlg, u.secCtx.IntegrityAlg)
	if errAlg != nil {
		return fmt.Errorf("error deriving algorithm key: %v", errAlg)
	}
	copy(u.secCtx.KnasEnc[:], kenc[16:32])
	copy(u.secCtx.KnasInt[:], kint[16:32])

	// send nas security mode complete message
	registrationRequestWith5Gmm, err := getUeRegistrationRequest(ie.RegType_InitialReg, mobileIdentity5GS, nil, ueSecurityCapability, u.get5GmmCapability(), nil, nil)
	if err != nil {
		return fmt.Errorf("error get ue registration request with 5GMM: %+v", err)
	}
	u.NasLog.Tracef("Registration request with 5GMM: %+v", registrationRequestWith5Gmm)

	nasSecurityModeCompleteMessage := getNasSecurityModeCompleteMessage(registrationRequestWith5Gmm)
	u.NasLog.Tracef("NAS security mode complete message: %+v", nasSecurityModeCompleteMessage)

	encodedNasSecurityModeCompleteMessage, err := nasEncode(nasSecurityModeCompleteMessage, u.secCtx, message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx)
	if err != nil {
		return fmt.Errorf("error encode nas security mode complete message: %+v", err)
	}
	u.NasLog.Tracef("Encoded NAS security mode complete message: %+v", encodedNasSecurityModeCompleteMessage)

	n, err = u.ranControlPlaneConn.Write(encodedNasSecurityModeCompleteMessage)
	if err != nil {
		return fmt.Errorf("error send nas security mode complete message: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of NAS Security Mode Complete Message to RAN", n)
	u.NasLog.Debugln("Send NAS Security Mode Complete Message to RAN")

	// receive nas registration accept
	if _, err := readAndDecodeNas[*message.RegAccept](u, "NAS Registration Accept"); err != nil {
		return err
	}

	// send nas registration complete message to RAN
	nasRegistrationCompleteMessage := getNasRegistrationCompleteMessage()
	u.NasLog.Tracef("NAS registration complete message: %+v", nasRegistrationCompleteMessage)

	encodedNasRegistrationCompleteMessage, err := nasEncode(nasRegistrationCompleteMessage, u.secCtx, message.SecHdrTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encode nas registration complete message: %+v", err)
	}
	u.NasLog.Tracef("Encoded NAS registration complete message: %+v", encodedNasRegistrationCompleteMessage)

	n, err = u.ranControlPlaneConn.Write(encodedNasRegistrationCompleteMessage)
	if err != nil {
		return fmt.Errorf("error send nas registration complete message: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of NAS Registration Complete Message to RAN", n)
	u.NasLog.Debugln("Send NAS Registration Complete Message to RAN")

	// receive nas configuration update command
	if _, err := readAndDecodeNas[*message.CfgUpdateCmd](u, "NAS Configuration Update Command"); err != nil {
		return err
	}

	u.RanLog.Infoln("UE Registration finished")
	return nil
}

func (u *Ue) processPduSessionEstablishment() error {
	u.PduLog.Infoln("Processing PDU session establishment")

	// send pdu session establishment request
	pduSessionEstablishmentRequest, err := getPduSessionEstablishmentRequest(constant.PDU_SESSION_ID, u.establishmentRequestContainers)
	if err != nil {
		return fmt.Errorf("error get pdu session establishment request: %+v", err)
	}
	u.NasLog.Tracef("PDU session establishment request: %+v", pduSessionEstablishmentRequest)

	ulNasTransportPduSessionEstablishmentRequest := getUlNasTransportMessage(pduSessionEstablishmentRequest, constant.PDU_SESSION_ID, ie.ReqType_InitialReq, u.pduSession.dnn, u.pduSession.sNssai)
	u.NasLog.Tracef("UL NAS transport pdu session establishment request: %+v", ulNasTransportPduSessionEstablishmentRequest)

	encodedUlNasTransportPduSessionEstablishmentRequest, err := nasEncode(ulNasTransportPduSessionEstablishmentRequest, u.secCtx, message.SecHdrTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encode ul nas transport pdu session establishment request: %+v", err)
	}
	u.NasLog.Tracef("Encoded UL NAS transport pdu session establishment request: %+v", encodedUlNasTransportPduSessionEstablishmentRequest)

	n, err := u.ranControlPlaneConn.Write(encodedUlNasTransportPduSessionEstablishmentRequest)
	if err != nil {
		return fmt.Errorf("error send ul nas transport pdu session establishment request: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of UL NAS transport pdu session establishment request to RAN", n)
	u.NasLog.Debugln("Send UL NAS transport pdu session establishment request to RAN")

	// receive pdu session establishment accept
	dlNasTransport, err := readAndDecodeNas[*message.DLNASTransport](u, "NAS PDU Session Establishment Accept")
	if err != nil {
		return err
	}

	// store ue information
	if err := u.extractUeInformationFromNasPduSessionEstablishmentAccept(dlNasTransport); err != nil {
		return fmt.Errorf("error extract ue information from nas pdu session establishment accept: %+v", err)
	}

	u.PduLog.Infof("UE %s PDU session establishment complete", u.supi)
	return nil
}

func (u *Ue) processUeDeregistration() error {
	u.RanLog.Infoln("Processing UE deregistration")

	mobileIdentity5GS, err := buildUeMobileIdentity5GS(len(u.mcc), len(u.mnc), u.supi)
	if err != nil {
		return fmt.Errorf("error build mobile identity 5gs: %+v", err)
	}
	u.NasLog.Tracef("Mobile identity 5GS: %+v", mobileIdentity5GS)

	// send ue deregistration request
	deregistrationRequest := getUeDeRegistrationRequest(ie.AccessType_3gpp, 0x00, ie.NASKeyNA, mobileIdentity5GS)
	u.NasLog.Tracef("Get UE deregistration request: %+v", deregistrationRequest)

	u.uplinkNasMtx.Lock()
	encodedDeregistrationRequest, err := nasEncode(deregistrationRequest, u.secCtx, message.SecHdrTypeIntegrityProtectedAndCiphered)
	if err != nil {
		u.uplinkNasMtx.Unlock()
		return fmt.Errorf("error encode ue deregistration request: %+v", err)
	}
	u.NasLog.Tracef("Encoded UE deregistration request: %+v", encodedDeregistrationRequest)

	n, err := u.ranControlPlaneConn.Write(encodedDeregistrationRequest)
	u.uplinkNasMtx.Unlock()
	if err != nil {
		return fmt.Errorf("error send ue deregistration request: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of UE deregistration request to RAN", n)
	u.NasLog.Debugln("Send UE deregistration request to RAN")

	// receive ue deregistration accept
	if _, err := readAndDecodeNas[*message.DeregAcceptUEOrig](u, "NAS UE Deregistration Accept"); err != nil {
		return err
	}

	u.RanLog.Infoln("UE deregistration complete")
	return nil
}

func (u *Ue) extractUeInformationFromNasPduSessionEstablishmentAccept(dlNasTransport *message.DLNASTransport) error {
	gsmMessage, err := getNasPduFromNasPduSessionEstablishmentAccept(dlNasTransport)
	if err != nil {
		return fmt.Errorf("error get nas pdu from nas pdu session establishment accept: %+v", err)
	}
	u.NasLog.Tracef("NAS message: %+v", gsmMessage)

	switch pduSessionEstablishmentAccept := gsmMessage.(type) {
	case *message.PDUSessEstAccept:
		if pduSessionEstablishmentAccept.PDUAddr != nil {
			pduAddress := pduSessionEstablishmentAccept.PDUAddr.IPv4
			u.pduSessionEstablishmentAccept.ueIp = fmt.Sprintf("%d.%d.%d.%d", pduAddress[0], pduAddress[1], pduAddress[2], pduAddress[3])
		}
		u.PduLog.Infof("PDU session UE IP: %s", u.pduSessionEstablishmentAccept.ueIp)

		if pduSessionEstablishmentAccept.AuthoQosRules != nil {
			qosRuleBytes, err := pduSessionEstablishmentAccept.AuthoQosRules.MarshalBinary()
			if err != nil {
				return fmt.Errorf("error marshal authorized qos rules: %+v", err)
			}
			u.pduSessionEstablishmentAccept.qosRule = qosRuleBytes
		}
		u.nrdc.specifiedFlow = append(u.nrdc.specifiedFlow, util.GetQosRule(u.pduSessionEstablishmentAccept.qosRule, u.UeLogger)...)
		u.PduLog.Infof("PDU session QoS rule: %+v", u.nrdc.specifiedFlow)

		if pduSessionEstablishmentAccept.DNN != nil {
			u.pduSessionEstablishmentAccept.dnn = pduSessionEstablishmentAccept.DNN.Value
		}
		u.PduLog.Infof("PDU session DNN: %s", u.pduSessionEstablishmentAccept.dnn)

		if pduSessionEstablishmentAccept.SNSSAI != nil {
			u.pduSessionEstablishmentAccept.sst = pduSessionEstablishmentAccept.SNSSAI.SST
			if sd, err := hex.DecodeString(pduSessionEstablishmentAccept.SNSSAI.SD); err == nil {
				copy(u.pduSessionEstablishmentAccept.sd[:], sd)
			}
		}
		u.PduLog.Infof("PDU session SNSSAI, sst: %d, sd: %s", u.pduSessionEstablishmentAccept.sst, fmt.Sprintf("%x%x%x", u.pduSessionEstablishmentAccept.sd[0], u.pduSessionEstablishmentAccept.sd[1], u.pduSessionEstablishmentAccept.sd[2]))

		u.nasObserver.PduSessionEstablishmentAccepted(operatorContainersFromNw(pduSessionEstablishmentAccept.ExtendedProtCfgOpts))
	case *message.PDUSessRelCmd:
		return fmt.Errorf("not implemented: PDUSessionReleaseCommand")
	case *message.PDUSessEstRej:
		return fmt.Errorf("not implemented: PDUSessionEstablishmentReject")
	default:
		return fmt.Errorf("not implemented: %T", gsmMessage)
	}

	return nil
}

// startNasDispatcher reads downlink messages from the RAN control plane until
// ctx is done or Stop is called.
func (u *Ue) startNasDispatcher(ctx context.Context, wg *sync.WaitGroup) {
	u.nasDispatcherDone = make(chan struct{})
	wg.Add(1)
	go u.dispatchRanMessages(ctx, wg)
}

func (u *Ue) dispatchRanMessages(ctx context.Context, wg *sync.WaitGroup) {
	u.RanLog.Infoln("Waiting for RAN message")
	defer wg.Done()
	defer close(u.nasDispatcherDone)

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
		case <-u.stopped:
		case <-stopWatch:
			return
		}
		if err := u.ranControlPlaneConn.SetReadDeadline(time.Now()); err != nil {
			u.RanLog.Errorf("Error set read deadline: %+v", err)
		}
	}()

	buffer := make([]byte, constant.NAS_MESSAGE_BUFFER_SIZE)
	for {
		n, err := u.ranControlPlaneConn.Read(buffer)
		if err != nil {
			if ctx.Err() != nil || u.isStopping() {
				break
			}
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				// the gNB closes the control connection when it releases the UE context
				u.RanLog.Infoln("RAN closed the control connection")
				u.nasObserver.UeContextReleased()
				break
			}
			u.RanLog.Warnf("Error read from ran control plane: %+v", err)
			continue
		}

		switch string(buffer[:n]) {
		case constant.UE_TUNNEL_UPDATE:
			go u.updateDataPlane()
		default:
			if err := u.handleDownlinkNas(buffer[:n]); err != nil {
				u.NasLog.Warnf("Error handle downlink NAS: %+v", err)
			}
		}
	}

	if err := u.ranControlPlaneConn.SetReadDeadline(time.Time{}); err != nil {
		u.RanLog.Errorf("Error set read deadline: %+v", err)
	}
	u.RanLog.Infoln("Stop waiting for RAN message")
}

func (u *Ue) isStopping() bool {
	select {
	case <-u.stopped:
		return true
	default:
		return false
	}
}

// handleDownlinkNas dispatches a downlink NAS message by its type.
func (u *Ue) handleDownlinkNas(payload []byte) error {
	nasPdu, err := nasDecode(u, payload)
	if err != nil {
		return fmt.Errorf("error decode downlink NAS: %+v", err)
	}

	dlNasTransport, ok := nasPdu.(*message.DLNASTransport)
	if !ok {
		u.NasLog.Warnf("Ignore downlink NAS %T", nasPdu)
		return nil
	}
	if dlNasTransport.PayloadCntr == nil || dlNasTransport.PayloadCntrType == nil ||
		dlNasTransport.PayloadCntrType.Value != ie.PayloadCntrType_N1SMInfo {
		u.NasLog.Warnln("Ignore DL NAS Transport without 5GSM payload")
		return nil
	}
	gsmMessage, err := message.ParseGSM(dlNasTransport.PayloadCntr.Contents)
	if err != nil {
		return fmt.Errorf("error decode 5GSM message: %+v", err)
	}
	u.NasLog.Debugf("Receive 5GSM %T from RAN", gsmMessage)

	switch gsm := gsmMessage.(type) {
	case *message.PDUSessModCmd:
		u.resolveModificationRequest(gsm.PTI)
		reply := u.nasObserver.PduSessionModificationCommand(gsm.PTI, operatorContainersFromNw(gsm.ExtendedProtCfgOpts))
		var answer []byte
		if reply.Reject {
			answer, err = buildPduSessionModificationCommandReject(gsm.PDUSessId, gsm.PTI, reply.Cause)
		} else {
			answer, err = buildPduSessionModificationComplete(gsm.PDUSessId, gsm.PTI)
		}
		if err != nil {
			return fmt.Errorf("error build modification command answer: %+v", err)
		}
		return u.sendUplinkSm(answer, gsm.PDUSessId)
	case *message.PDUSessModRej:
		u.resolveModificationRequest(gsm.PTI)
		u.nasObserver.PduSessionModificationRejected(gsm.PTI, cause5gsmValue(gsm.Cause5GSM), operatorContainersFromNw(gsm.ExtendedProtCfgOpts))
		return nil
	case *message.PDUSessRelCmd:
		releaseComplete, err := buildPduSessionReleaseComplete(gsm.PDUSessId, gsm.PTI)
		if err != nil {
			return fmt.Errorf("error build release complete: %+v", err)
		}
		if err := u.sendUplinkSm(releaseComplete, gsm.PDUSessId); err != nil {
			return err
		}
		u.nasObserver.PduSessionReleased(cause5gsmValue(gsm.Cause5GSM))
		return nil
	default:
		u.NasLog.Warnf("Ignore 5GSM %T", gsmMessage)
		return nil
	}
}

// sendUplinkSm sends a 5GSM message of an established PDU session in an UL NAS Transport.
func (u *Ue) sendUplinkSm(gsmPayload []byte, pduSessionId uint8) error {
	u.uplinkNasMtx.Lock()
	defer u.uplinkNasMtx.Unlock()

	encoded, err := nasEncode(buildUlNasTransportForPduSession(gsmPayload, pduSessionId), u.secCtx, message.SecHdrTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encode ul nas transport: %+v", err)
	}
	n, err := u.ranControlPlaneConn.Write(encoded)
	if err != nil {
		return fmt.Errorf("error send ul nas transport: %+v", err)
	}
	u.NasLog.Tracef("Sent %d bytes of UL NAS transport to RAN", n)
	return nil
}

// SendPduSessionModificationRequest sends a PDU Session Modification Request that
// carries the operator containers in its ePCO, under a new PTI, which it returns.
// The request can be resent under the same PTI until a Modification Command or
// Reject answers it, also when sending it returned an error.
func (u *Ue) SendPduSessionModificationRequest(operatorContainers []ie.OperatorContainer) (uint8, error) {
	u.smMtx.Lock()
	pti, err := u.allocatePti()
	if err != nil {
		u.smMtx.Unlock()
		return 0, err
	}
	modificationRequest, err := buildPduSessionModificationRequest(constant.PDU_SESSION_ID, pti, operatorContainers)
	if err != nil {
		u.smMtx.Unlock()
		return 0, fmt.Errorf("error build pdu session modification request: %+v", err)
	}
	u.pendingModificationRequests[pti] = modificationRequest
	u.smMtx.Unlock()

	u.NasLog.Debugf("Send PDU Session Modification Request with PTI %d", pti)
	return pti, u.sendUplinkSm(modificationRequest, constant.PDU_SESSION_ID)
}

// ResendPduSessionModificationRequest resends the unanswered Modification Request with that PTI.
func (u *Ue) ResendPduSessionModificationRequest(pti uint8) error {
	u.smMtx.Lock()
	modificationRequest, ok := u.pendingModificationRequests[pti]
	u.smMtx.Unlock()
	if !ok {
		return fmt.Errorf("no unanswered modification request with PTI %d", pti)
	}

	u.NasLog.Debugf("Resend PDU Session Modification Request with PTI %d", pti)
	return u.sendUplinkSm(modificationRequest, constant.PDU_SESSION_ID)
}

// allocatePti returns the next UE-allocated PTI (1-254, TS 24.007) not held by an
// unanswered request. The caller holds smMtx.
func (u *Ue) allocatePti() (uint8, error) {
	for range 254 {
		u.lastPti = u.lastPti%254 + 1
		if _, pending := u.pendingModificationRequests[u.lastPti]; !pending {
			return u.lastPti, nil
		}
	}
	return 0, errors.New("every PTI is held by an unanswered modification request")
}

func (u *Ue) resolveModificationRequest(pti uint8) {
	u.smMtx.Lock()
	defer u.smMtx.Unlock()

	delete(u.pendingModificationRequests, pti)
}

func (u *Ue) startDataPlane(ctx context.Context, wg *sync.WaitGroup) error {
	if err := u.setupTunnelDevice(); err != nil {
		return err
	}

	u.startReadFromRan()

	go u.handleDataPlane(ctx, wg)
	return nil
}

func (u *Ue) setupTunnelDevice() error {
	u.TunLog.Infoln("Setting up UE tunnel device")

	if u.externalDataPlane {
		u.TunLog.Infoln("External data plane, skip tunnel device setup")
		return nil
	}

	waterInterface, err := bringUpUeTunnelDevice(u.ueTunnelDeviceName, u.ueIp)
	if err != nil {
		return fmt.Errorf("error bring up ue tunnel device: %+v", err)
	}
	u.TunLog.Debugln("Bring up ue tunnel device success")

	u.ueTunnelDevice = waterInterface

	// go routine for read data from TUN
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := u.ueTunnelDevice.Read(buffer)
			if err != nil {
				u.TunLog.Errorf("Error read from ue tunnel device: %+v", err)
				return
			}
			version := buffer[0] >> 4
			if version == 6 {
				continue
			}

			tmp := make([]byte, n)
			copy(tmp, buffer[:n])
			u.uplink <- tmp
		}
	}()
	u.TunLog.Debugln("Read from TUN started")

	u.TunLog.Infof("UE tunnel device setup as %s", u.ueTunnelDeviceName)
	return nil
}

func (u *Ue) startReadFromRan() {
	// go routing for read data from RAN
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := u.ranDataPlaneConn.Read(buffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
					u.TunLog.Debugln("RAN data plane connection closed")
					return
				}
				u.RanLog.Errorf("Error read from ran data plane: %+v", err)
				u.nasObserver.DataPlaneError(err)
				return
			}

			tmp := make([]byte, n)
			copy(tmp, buffer[:n])
			select {
			case u.downlink <- tmp:
			case <-u.stopped:
				return
			}
		}
	}()
	u.TunLog.Debugln("Read from RAN started")

	if u.isNrdcEnabled() {
		go func() {
			buffer := make([]byte, 4096)
			for {
				n, err := u.dcRanDataPlaneConn.Read(buffer)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
						u.TunLog.Debugln("DC RAN data plane connection closed")
						return
					}
					u.RanLog.Errorf("Error read from dc ran data plane: %+v", err)
				}

				tmp := make([]byte, n)
				copy(tmp, buffer[:n])
				select {
				case u.downlink <- tmp:
				case <-u.stopped:
					return
				}
			}
		}()
		u.TunLog.Debugln("Read from DC RAN data plane started")
	}
}

func (u *Ue) cleanUpTunnelDevice() error {
	u.TunLog.Infoln("Cleaning up UE tunnel device")

	if u.externalDataPlane {
		// the channels stay open: the embedding process owns the uplink side
		u.TunLog.Infoln("External data plane, skip tunnel device cleanup")
		return nil
	}

	close(u.uplink)
	close(u.downlink)

	if err := bringDownUeTunnelDevice(u.ueTunnelDeviceName); err != nil {
		return fmt.Errorf("error bring down ue tunnel device: %+v", err)
	}
	u.TunLog.Debugln("Bring down ue tunnel device success")

	u.TunLog.Infoln("UE tunnel device cleaned up")
	return nil
}

func (u *Ue) handleDataPlane(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)

	// with an external data plane, the embedding process reads downlink packets itself
	toTun := u.downlink
	if u.externalDataPlane {
		toTun = nil
	}

	// forward data from TUN to RAN and RAN to TUN
	for {
		select {
		case <-ctx.Done():
			goto HANDLE_DATA_PLANE_FINISH
		case <-u.stopped:
			goto HANDLE_DATA_PLANE_FINISH
		case buffer := <-u.uplink:
			if !u.isNrdcEnabled() {
				n, err := u.ranDataPlaneConn.Write(buffer)
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						goto HANDLE_DATA_PLANE_FINISH
					}
					u.RanLog.Warnf("Error sent to ran data plane: %+v", err)
					u.nasObserver.DataPlaneError(err)
				}
				u.RanLog.Tracef("Sent %d bytes of data to RAN: %+v", n, buffer[:n])
			} else {
				if util.IsIpInSpecifiedFlow(buffer, u.nrdc.specifiedFlow) {
					n, err := u.dcRanDataPlaneConn.Write(buffer)
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							goto HANDLE_DATA_PLANE_FINISH
						}
						u.RanLog.Warnf("Error sent to dc ran data plane: %+v", err)
						u.nasObserver.DataPlaneError(err)
					}
					u.RanLog.Tracef("Sent %d bytes of data to DC RAN: %+v", n, buffer[:n])
				} else {
					n, err := u.ranDataPlaneConn.Write(buffer)
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							goto HANDLE_DATA_PLANE_FINISH
						}
						u.RanLog.Warnf("Error sent to ran data plane: %+v", err)
						u.nasObserver.DataPlaneError(err)
					}
					u.RanLog.Tracef("Sent %d bytes of data to RAN: %+v", n, buffer[:n])
				}
			}
		case buffer := <-toTun:
			n, err := u.ueTunnelDevice.Write(buffer)
			if err != nil {
				u.TunLog.Warnf("Error write to ue tunnel device: %+v", err)
			}
			u.TunLog.Tracef("Wrote %d bytes of data to TUN: %+v", n, buffer[:n])
		}
	}

HANDLE_DATA_PLANE_FINISH:
	wg.Done()
}

func (u *Ue) updateDataPlane() {
	u.TunLog.Infoln("Updating data plane")

	u.rwLock.Lock()
	defer u.rwLock.Unlock()

	if !u.nrdc.enable {
		conn, err := util.UdpDialWithOptionalLocalAddress(u.nrdc.dcRanDataPlane.ip, u.nrdc.dcRanDataPlane.port, u.nrdc.dcLocalDataPlaneIp)
		if err != nil {
			u.TunLog.Errorf("Error connect to dc ran data plane: %+v", err)
			return
		}
		u.dcRanDataPlaneConn = conn

		_, err = u.dcRanDataPlaneConn.Write([]byte(constant.UE_DATA_PLANE_INITIAL_PACKET + " " + constant.UE_IMSI_PREFIX + u.supi))
		if err != nil {
			u.TunLog.Errorf("Error send initial packet: %+v", err)
			return
		}
		u.RanLog.Debugln("Sent initial packet to DC RAN data plane UDP server")

		go func() {
			buffer := make([]byte, 4096)
			for {
				n, err := u.dcRanDataPlaneConn.Read(buffer)
				if err != nil {
					if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
						u.TunLog.Debugln("DC RAN data plane connection closed")
						return
					}
					u.RanLog.Errorf("Error read from dc ran data plane: %+v", err)
				}

				tmp := make([]byte, n)
				copy(tmp, buffer[:n])
				select {
				case u.downlink <- tmp:
				case <-u.stopped:
					return
				}
			}
		}()
		u.TunLog.Debugln("Read from DC RAN data plane started")

		u.nrdc.enable = true
		u.TunLog.Infoln("Data plane is updated to NRDC mode")
	} else {
		if err := u.dcRanDataPlaneConn.Close(); err != nil {
			u.UeLog.Errorf("Error closing DC RAN connection: %v", err)
		}

		u.nrdc.enable = false
		u.TunLog.Infoln("Data plane is updated to non-NRDC mode")
	}
}

func (u *Ue) GetRanDataPlaneConn() net.Conn {
	return u.ranDataPlaneConn
}

// UplinkPackets returns the uplink packet sink of an external data plane:
// each IP packet sent on it goes to the RAN data plane, and the UE takes ownership of the slice.
// Nothing receives after Stop, so senders should also select on their own shutdown signal.
// It is nil when the UE owns a TUN.
func (u *Ue) UplinkPackets() chan<- []byte {
	if !u.externalDataPlane {
		return nil
	}
	return u.uplink
}

// DownlinkPackets returns the downlink packet source of an external data plane:
// it yields each IP packet received from the RAN data plane. It must be drained like a TUN,
// or downlink reading stalls. It is never closed. It is nil when the UE owns a TUN.
func (u *Ue) DownlinkPackets() <-chan []byte {
	if !u.externalDataPlane {
		return nil
	}
	return u.downlink
}

func (u *Ue) GetUeIp() string {
	return u.pduSessionEstablishmentAccept.ueIp
}

func (u *Ue) get5GmmCapability() *ie.Capability5GMM {
	return &ie.Capability5GMM{
		Length:   1,
		S1Mode:   true,
		HOAttach: true,
		LPP:      true,
	}
}

func (u *Ue) isNrdcEnabled() bool {
	u.rwLock.RLock()
	defer u.rwLock.RUnlock()

	return u.nrdc.enable
}

package ue

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	loggergoUtil "github.com/Alonza0314/logger-go/v2/util"
	"github.com/free-ran-ue/free-ran-ue/v2/constant"
	"github.com/free-ran-ue/free-ran-ue/v2/logger"
	"github.com/free-ran-ue/free-ran-ue/v2/model"
	"github.com/go-playground/assert"
)

func newTestUe(t *testing.T, ueIe model.UeIE) *Ue {
	t.Helper()

	ueIe.PlmnId = model.PlmnIdIE{Mcc: "208", Mnc: "93"}
	ueIe.Msin = "0000000001"
	ueIe.PduSession.Snssai.Sst = "1"
	ueLogger := logger.NewUeLogger(loggergoUtil.LogLevelString("error"), "", true)
	return NewUe(&model.UeConfig{Ue: ueIe}, &ueLogger)
}

func TestControlPlaneLocalBind(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Equal(t, nil, err)
	defer func() { _ = listener.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	u := newTestUe(t, model.UeIE{
		RanControlPlaneIp:   "127.0.0.1",
		RanControlPlanePort: listener.Addr().(*net.TCPAddr).Port,
		LocalControlPlaneIp: "127.0.0.2",
	})

	assert.Equal(t, nil, u.connectToRanControlPlane())
	defer func() { _ = u.ranControlPlaneConn.Close() }()

	conn := <-accepted
	defer func() { _ = conn.Close() }()
	assert.Equal(t, "127.0.0.2", conn.RemoteAddr().(*net.TCPAddr).IP.String())
}

func TestExternalDataPlane(t *testing.T) {
	gnbDataPlane, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	assert.Equal(t, nil, err)
	defer func() { _ = gnbDataPlane.Close() }()
	assert.Equal(t, nil, gnbDataPlane.SetReadDeadline(time.Now().Add(2*time.Second)))

	u := newTestUe(t, model.UeIE{
		RanDataPlaneIp:    "127.0.0.1",
		RanDataPlanePort:  gnbDataPlane.LocalAddr().(*net.UDPAddr).Port,
		UeTunnelDevice:    "extDpTun0",
		ExternalDataPlane: true,
	})
	u.pduSessionEstablishmentAccept.ueIp = "10.60.0.1"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := sync.WaitGroup{}

	assert.Equal(t, nil, u.connectToRanDataPlane())
	defer func() { _ = u.ranDataPlaneConn.Close() }()
	assert.Equal(t, nil, u.startDataPlane(ctx, &wg))

	buffer := make([]byte, 4096)
	n, ueAddress, err := gnbDataPlane.ReadFromUDP(buffer)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, strings.HasPrefix(string(buffer[:n]), constant.UE_DATA_PLANE_INITIAL_PACKET))

	uplinkPacket := []byte{0x45, 0x00, 0x00, 0x14, 0x01}
	select {
	case u.UplinkPackets() <- uplinkPacket:
	case <-time.After(2 * time.Second):
		t.Fatal("uplink sink did not accept the packet")
	}
	n, _, err = gnbDataPlane.ReadFromUDP(buffer)
	assert.Equal(t, nil, err)
	assert.Equal(t, uplinkPacket, buffer[:n])

	downlinkPacket := []byte{0x45, 0x00, 0x00, 0x14, 0x02}
	_, err = gnbDataPlane.WriteToUDP(downlinkPacket, ueAddress)
	assert.Equal(t, nil, err)
	select {
	case packet := <-u.DownlinkPackets():
		assert.Equal(t, downlinkPacket, packet)
	case <-time.After(2 * time.Second):
		t.Fatal("downlink packet did not reach the downlink source")
	}

	_, err = net.InterfaceByName("extDpTun0")
	assert.NotEqual(t, nil, err)
	assert.Equal(t, nil, u.cleanUpTunnelDevice())
}

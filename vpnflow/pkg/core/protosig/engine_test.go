package protosig

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"vpnflow/pkg/model"
)

var (
	testClient = net.ParseIP("192.0.2.10")
	testServer = net.ParseIP("198.51.100.20")
	testTime   = time.Unix(1_700_000_000, 0)
)

func udpPacket(src, dst net.IP, srcPort, dstPort uint16, payload []byte, offset time.Duration) model.Packet {
	return model.Packet{
		Timestamp: testTime.Add(offset), SrcIP: src, DstIP: dst,
		Protocol: model.ProtoUDP, SrcPort: srcPort, DstPort: dstPort,
		Payload: payload, PayloadLen: len(payload),
	}
}

func TestWireGuardHandshakeConfirmed(t *testing.T) {
	init := make([]byte, 148)
	init[0] = 1
	binary.LittleEndian.PutUint32(init[4:8], 0x11223344)
	resp := make([]byte, 92)
	resp[0] = 2
	binary.LittleEndian.PutUint32(resp[4:8], 0x55667788)
	binary.LittleEndian.PutUint32(resp[8:12], 0x11223344)

	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 51820, init, 0))
	e.Observe(udpPacket(testServer, testClient, 51820, 50000, resp, time.Millisecond))
	results := e.FlushAll()
	assertSingleConfirmed(t, results, "wireguard")
}

func TestWireGuardReservedBytesRejectRandomPacket(t *testing.T) {
	payload := make([]byte, 148)
	payload[0], payload[1] = 1, 1
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 1, 2, payload, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("malformed WireGuard produced result: %+v", got)
	}
}

func TestOpenVPNBidirectionalControlConfirmed(t *testing.T) {
	clientReset := make([]byte, 9)
	clientReset[0] = 7 << 3
	copy(clientReset[1:], []byte("CLIENT01"))
	serverReset := make([]byte, 9)
	serverReset[0] = 8 << 3
	copy(serverReset[1:], []byte("SERVER01"))
	clientControl := append([]byte(nil), clientReset...)
	clientControl[0] = 4 << 3
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 45000, 1194, clientReset, 0))
	e.Observe(udpPacket(testServer, testClient, 1194, 45000, serverReset, time.Millisecond))
	e.Observe(udpPacket(testClient, testServer, 45000, 1194, clientControl, 2*time.Millisecond))
	assertSingleConfirmed(t, e.FlushAll(), "openvpn")
}

func TestOpenVPNResetPairWithoutRepeatedSessionIDIsSuspected(t *testing.T) {
	clientReset := make([]byte, 9)
	clientReset[0] = 7 << 3
	copy(clientReset[1:], []byte("CLIENT01"))
	serverReset := make([]byte, 9)
	serverReset[0] = 8 << 3
	copy(serverReset[1:], []byte("SERVER01"))
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 45000, 1194, clientReset, 0))
	e.Observe(udpPacket(testServer, testClient, 1194, 45000, serverReset, time.Millisecond))
	results := e.FlushAll()
	if len(results) != 1 || results[0].Verdict != model.VerdictSuspected {
		t.Fatalf("reset opcode pair without repeated session-id must stay suspected: %+v", results)
	}
}

func TestPPTPControlAndGRECallIDConfirmed(t *testing.T) {
	control := make([]byte, 14)
	binary.BigEndian.PutUint16(control[0:2], uint16(len(control)))
	binary.BigEndian.PutUint16(control[2:4], 1)
	binary.BigEndian.PutUint32(control[4:8], pptpMagicCookie)
	binary.BigEndian.PutUint16(control[8:10], 7)
	binary.BigEndian.PutUint16(control[12:14], 0x1234)

	e := New(Config{})
	e.Observe(model.Packet{
		Timestamp: testTime, SrcIP: testClient, DstIP: testServer,
		Protocol: model.ProtoTCP, SrcPort: 50000, DstPort: 1723,
		Payload: control, PayloadLen: len(control),
	})
	e.Observe(model.Packet{
		Timestamp: testTime.Add(time.Millisecond), SrcIP: testServer, DstIP: testClient,
		Protocol: model.ProtoGRE, GREProtocol: pptpGREProtocol, GREVersion: 1,
		GRECallID: 0x1234, GREPayloadLength: 4, Payload: make([]byte, 4), PayloadLen: 4,
	})
	result := assertSingleConfirmed(t, e.FlushAll(), "pptp")
	if len(result.Flows) != 2 {
		t.Fatalf("PPTP must associate TCP and GRE flows, got %v", result.Flows)
	}
}

func TestL2TPControlAndDataConfirmed(t *testing.T) {
	control := make([]byte, 20)
	binary.BigEndian.PutUint16(control[0:2], 0xC802) // T,L,S,version=2
	binary.BigEndian.PutUint16(control[2:4], uint16(len(control)))
	binary.BigEndian.PutUint16(control[4:6], 1) // tunnel
	// session=0, Ns=0, Nr=0
	binary.BigEndian.PutUint16(control[12:14], 8) // AVP length
	binary.BigEndian.PutUint16(control[14:16], 0) // vendor
	binary.BigEndian.PutUint16(control[16:18], 0) // message-type attribute
	binary.BigEndian.PutUint16(control[18:20], 1) // SCCRQ
	data := []byte{0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb}

	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, data, time.Millisecond))
	assertSingleConfirmed(t, e.FlushAll(), "l2tpv2")
}

func TestSessionIDsAreUniqueAtSameTimestamp(t *testing.T) {
	first := make([]byte, 148)
	first[0] = 1
	binary.LittleEndian.PutUint32(first[4:8], 1)
	second := make([]byte, 148)
	second[0] = 1
	binary.LittleEndian.PutUint32(second[4:8], 2)

	e := New(Config{SourceFile: "same-time.pcap"})
	e.Observe(udpPacket(testClient, testServer, 40001, 51820, first, 0))
	e.Observe(udpPacket(testClient, testServer, 40002, 51820, second, 0))
	results := e.FlushAll()
	if len(results) != 2 {
		t.Fatalf("got %d sessions, want 2", len(results))
	}
	if results[0].SessionID == results[1].SessionID {
		t.Fatalf("duplicate session id: %s", results[0].SessionID)
	}
}

func assertSingleConfirmed(
	t *testing.T,
	results []model.ProtocolResult,
	protocol string,
) model.ProtocolResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if results[0].Protocol != protocol || results[0].Verdict != model.VerdictConfirmed {
		t.Fatalf("unexpected result: %+v", results[0])
	}
	return results[0]
}

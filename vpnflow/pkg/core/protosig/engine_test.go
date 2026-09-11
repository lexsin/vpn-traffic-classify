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

func tcpPacket(src, dst net.IP, srcPort, dstPort uint16, payload []byte, offset time.Duration) model.Packet {
	return model.Packet{
		Timestamp: testTime.Add(offset), SrcIP: src, DstIP: dst,
		Protocol: model.ProtoTCP, SrcPort: srcPort, DstPort: dstPort,
		Payload: payload, PayloadLen: len(payload),
	}
}

func pptpControlFrame(controlType uint16, extra []byte) []byte {
	frame := make([]byte, 12+len(extra))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(frame)))
	binary.BigEndian.PutUint16(frame[2:4], 1)
	binary.BigEndian.PutUint32(frame[4:8], pptpMagicCookie)
	binary.BigEndian.PutUint16(frame[8:10], controlType)
	copy(frame[12:], extra)
	return frame
}

func l2tpControlSCCRQ(length int) []byte {
	control := make([]byte, length)
	binary.BigEndian.PutUint16(control[0:2], 0xC802) // T,L,S,version=2
	binary.BigEndian.PutUint16(control[2:4], uint16(len(control)))
	binary.BigEndian.PutUint16(control[4:6], 1) // tunnel
	binary.BigEndian.PutUint16(control[12:14], 8)
	binary.BigEndian.PutUint16(control[18:20], 1) // SCCRQ
	return control
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
	e.Observe(udpPacket(testClient, testServer, 45000, 443, clientReset, 0))
	e.Observe(udpPacket(testServer, testClient, 443, 45000, serverReset, time.Millisecond))
	assertSingleSuspected(t, e.FlushAll(), "openvpn")
}

func TestOpenVPNResetPairOn1194PromotedConfirmed(t *testing.T) {
	clientReset := make([]byte, 9)
	clientReset[0] = 7 << 3
	copy(clientReset[1:], []byte("CLIENT01"))
	serverReset := make([]byte, 9)
	serverReset[0] = 8 << 3
	copy(serverReset[1:], []byte("SERVER01"))
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 45000, 1194, clientReset, 0))
	e.Observe(udpPacket(testServer, testClient, 1194, 45000, serverReset, time.Millisecond))
	result := assertSingleConfirmed(t, e.FlushAll(), "openvpn")
	assertHasEvidence(t, result, "well_known_port")
}

func TestPPTPControlAndGRECallIDConfirmed(t *testing.T) {
	control := pptpControlFrame(7, []byte{0x12, 0x34})

	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 1723, control, 0))
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

func TestPPTPSCCHandshakeConfirmedWithoutGRE(t *testing.T) {
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 1723, pptpControlFrame(1, nil), 0))
	e.Observe(tcpPacket(testServer, testClient, 1723, 50000, pptpControlFrame(2, nil), time.Millisecond))
	assertSingleConfirmed(t, e.FlushAll(), "pptp")
}

func TestPPTPOutgoingCallHandshakeConfirmedWithoutGRE(t *testing.T) {
	req := pptpControlFrame(7, []byte{0x12, 0x34})
	reply := pptpControlFrame(8, []byte{0x12, 0x34, 0x56, 0x78})
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 1723, req, 0))
	e.Observe(tcpPacket(testServer, testClient, 1723, 50000, reply, time.Millisecond))
	assertSingleConfirmed(t, e.FlushAll(), "pptp")
}

func TestPPTPSingleControlWithoutGREIsSuspected(t *testing.T) {
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 8443, pptpControlFrame(1, nil), 0))
	assertSingleSuspected(t, e.FlushAll(), "pptp")
}

func TestPPTPSingleControlOn1723PromotedConfirmed(t *testing.T) {
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 1723, pptpControlFrame(1, nil), 0))
	result := assertSingleConfirmed(t, e.FlushAll(), "pptp")
	assertHasEvidence(t, result, "well_known_port")
}

func TestPPTPReservedFieldRejectsControl(t *testing.T) {
	frame := pptpControlFrame(1, nil)
	binary.BigEndian.PutUint16(frame[10:12], 1)
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 1723, frame, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("PPTP reserved != 0 produced result: %+v", got)
	}
}

func TestPPTPSameDirectionSCCRemainsSuspected(t *testing.T) {
	e := New(Config{})
	e.Observe(tcpPacket(testClient, testServer, 50000, 8443, pptpControlFrame(1, nil), 0))
	e.Observe(tcpPacket(testClient, testServer, 50000, 8443, pptpControlFrame(2, nil), time.Millisecond))
	assertSingleSuspected(t, e.FlushAll(), "pptp")
}

func TestL2TPControlAndDataConfirmed(t *testing.T) {
	control := l2tpControlSCCRQ(20)
	data := []byte{0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb}

	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, data, time.Millisecond))
	assertSingleConfirmed(t, e.FlushAll(), "l2tpv2")
}

func TestL2TPDataOnlyDoesNotEmit(t *testing.T) {
	data := []byte{0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb}
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, data, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("L2TP data-only must not emit: %+v", got)
	}
}

func TestL2TPSingleControlOn1701PromotedConfirmed(t *testing.T) {
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, l2tpControlSCCRQ(20), 0))
	result := assertSingleConfirmed(t, e.FlushAll(), "l2tpv2")
	assertHasEvidence(t, result, "well_known_port")
}

func TestL2TPSingleControlOffPortRemainsSuspected(t *testing.T) {
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1702, l2tpControlSCCRQ(20), 0))
	assertSingleSuspected(t, e.FlushAll(), "l2tpv2")
}

func TestL2TPControlMissingLengthBitRejected(t *testing.T) {
	control := l2tpControlSCCRQ(20)
	binary.BigEndian.PutUint16(control[0:2], 0x8802) // T,S,version=2，缺 L
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("L2TP control without L bit produced result: %+v", got)
	}
}

func TestL2TPControlLengthMismatchRejected(t *testing.T) {
	control := l2tpControlSCCRQ(24)
	binary.BigEndian.PutUint16(control[2:4], 20) // Length 不等于 UDP 载荷
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("L2TP length mismatch produced result: %+v", got)
	}
}

func TestL2TPControlReservedBitsRejected(t *testing.T) {
	control := l2tpControlSCCRQ(20)
	binary.BigEndian.PutUint16(control[0:2], 0xD802) // 置位 reserved bit 12
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("L2TP reserved bits produced result: %+v", got)
	}
}

func TestL2TPControlOffsetBitRejected(t *testing.T) {
	control := l2tpControlSCCRQ(20)
	binary.BigEndian.PutUint16(control[0:2], 0xCA02) // T,L,S,O,version=2
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 1701, control, 0))
	if got := e.FlushAll(); len(got) != 0 {
		t.Fatalf("L2TP control with O bit produced result: %+v", got)
	}
}

func TestParseL2TPv2AcceptsValidControl(t *testing.T) {
	msg, ok := parseL2TPv2(l2tpControlSCCRQ(20))
	if !ok || !msg.control || msg.messageType != 1 {
		t.Fatalf("valid L2TP control rejected: ok=%v msg=%+v", ok, msg)
	}
}

func TestWireGuardInitiationOffPortRemainsSuspected(t *testing.T) {
	init := make([]byte, 148)
	init[0] = 1
	binary.LittleEndian.PutUint32(init[4:8], 0x11223344)
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 12345, init, 0))
	assertSingleSuspected(t, e.FlushAll(), "wireguard")
}

func TestWireGuardInitiationOn51820PromotedConfirmed(t *testing.T) {
	init := make([]byte, 148)
	init[0] = 1
	binary.LittleEndian.PutUint32(init[4:8], 0x11223344)
	e := New(Config{})
	e.Observe(udpPacket(testClient, testServer, 50000, 51820, init, 0))
	result := assertSingleConfirmed(t, e.FlushAll(), "wireguard")
	assertHasEvidence(t, result, "well_known_port")
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

func assertSingleSuspected(
	t *testing.T,
	results []model.ProtocolResult,
	protocol string,
) model.ProtocolResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	if results[0].Protocol != protocol || results[0].Verdict != model.VerdictSuspected {
		t.Fatalf("unexpected result: %+v", results[0])
	}
	return results[0]
}

func assertHasEvidence(t *testing.T, result model.ProtocolResult, want string) {
	t.Helper()
	for _, item := range result.Evidence {
		if item == want {
			return
		}
	}
	t.Fatalf("missing evidence %q in %v", want, result.Evidence)
}

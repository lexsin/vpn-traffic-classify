package reassembly

import (
	"net"
	"testing"
	"time"

	"vpnflow/pkg/model"
)

var (
	testClientIP = net.ParseIP("10.0.0.1").To4()
	testServerIP = net.ParseIP("10.0.0.2").To4()
)

func handshakePacket(fromClient bool, seq, ack uint32, flags uint8, payload []byte, offset int) model.Packet {
	srcIP, dstIP := testClientIP, testServerIP
	srcPort, dstPort := uint16(40000), uint16(8388)
	if !fromClient {
		srcIP, dstIP = testServerIP, testClientIP
		srcPort, dstPort = dstPort, srcPort
	}
	return model.Packet{
		Timestamp:  time.Unix(0, int64(offset)*int64(time.Millisecond)),
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		TCPSeq:     seq,
		TCPAck:     ack,
		TCPFlags:   flags,
		Payload:    payload,
		PayloadLen: len(payload),
		IPLen:      40 + len(payload),
	}
}

func handshakeComplete(t *testing.T, packets ...model.Packet) bool {
	t.Helper()
	r := New()
	for _, pkt := range packets {
		r.Feed(pkt)
	}
	flows := r.FlushAll()
	if len(flows) != 1 {
		t.Fatalf("got %d flows, want 1", len(flows))
	}
	return flows[0].TCPHandshakeComplete
}

func validHandshake(thirdPayload []byte) []model.Packet {
	return []model.Packet{
		handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
		handshakePacket(false, 500, 101, model.TCPFlagSYN|model.TCPFlagACK, nil, 2),
		handshakePacket(true, 101, 501, model.TCPFlagACK, thirdPayload, 3),
	}
}

func TestTCPHandshakeComplete(t *testing.T) {
	if !handshakeComplete(t, validHandshake(nil)...) {
		t.Fatal("valid three-way handshake was not recognized")
	}
}

func TestTCPHandshakeCompleteWithRetransmissions(t *testing.T) {
	packets := []model.Packet{
		handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
		handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 2),
		handshakePacket(false, 500, 101, model.TCPFlagSYN|model.TCPFlagACK, nil, 3),
		handshakePacket(false, 500, 101, model.TCPFlagSYN|model.TCPFlagACK, nil, 4),
		handshakePacket(true, 101, 501, model.TCPFlagACK, nil, 5),
	}
	if !handshakeComplete(t, packets...) {
		t.Fatal("handshake with retransmissions was not recognized")
	}
}

func TestTCPHandshakeCompleteWithPayloadOnThirdACK(t *testing.T) {
	if !handshakeComplete(t, validHandshake([]byte{1, 2, 3})...) {
		t.Fatal("third ACK carrying payload was not recognized")
	}
}

func TestTCPHandshakeIncompleteCases(t *testing.T) {
	tests := map[string][]model.Packet{
		"midstream": {
			handshakePacket(true, 101, 501, model.TCPFlagACK, []byte{1}, 1),
			handshakePacket(false, 501, 102, model.TCPFlagACK, nil, 2),
		},
		"missing syn ack": {
			handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
			handshakePacket(true, 101, 501, model.TCPFlagACK, nil, 2),
		},
		"wrong syn ack direction": {
			handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
			handshakePacket(true, 500, 101, model.TCPFlagSYN|model.TCPFlagACK, nil, 2),
			handshakePacket(true, 101, 501, model.TCPFlagACK, nil, 3),
		},
		"wrong syn ack number": {
			handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
			handshakePacket(false, 500, 999, model.TCPFlagSYN|model.TCPFlagACK, nil, 2),
			handshakePacket(true, 101, 501, model.TCPFlagACK, nil, 3),
		},
		"wrong final ack number": {
			handshakePacket(true, 100, 0, model.TCPFlagSYN, nil, 1),
			handshakePacket(false, 500, 101, model.TCPFlagSYN|model.TCPFlagACK, nil, 2),
			handshakePacket(true, 101, 999, model.TCPFlagACK, nil, 3),
		},
	}
	for name, packets := range tests {
		t.Run(name, func(t *testing.T) {
			if handshakeComplete(t, packets...) {
				t.Fatal("incomplete handshake was recognized as complete")
			}
		})
	}
}

func TestTCPHandshakeRemainsCompleteAfterClose(t *testing.T) {
	packets := append(validHandshake(nil),
		handshakePacket(false, 501, 101, model.TCPFlagRST|model.TCPFlagACK, nil, 4),
		handshakePacket(true, 101, 502, model.TCPFlagFIN|model.TCPFlagACK, nil, 5),
	)
	if !handshakeComplete(t, packets...) {
		t.Fatal("completed handshake was cleared by RST/FIN")
	}
}

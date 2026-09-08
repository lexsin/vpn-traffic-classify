package model

import (
	"net"
	"testing"
)

func TestCanonicalFlowKeyBidirectional(t *testing.T) {
	a := net.ParseIP("192.0.2.10")
	b := net.ParseIP("198.51.100.20")
	forward, fd := CanonicalizeFlowKey(ProtoTCP, a, 54321, b, 443)
	reverse, rd := CanonicalizeFlowKey(ProtoTCP, b, 443, a, 54321)
	if forward != reverse {
		t.Fatalf("forward=%v reverse=%v", forward, reverse)
	}
	if fd == rd {
		t.Fatalf("directions must be opposite: %v %v", fd, rd)
	}
}

func TestCanonicalFlowKeyUnmapsIPv4(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10").To4()
	mapped := net.ParseIP("::ffff:192.0.2.10")
	peer := net.ParseIP("198.51.100.20")
	a, _ := CanonicalizeFlowKey(ProtoUDP, v4, 1000, peer, 2000)
	b, _ := CanonicalizeFlowKey(ProtoUDP, mapped, 1000, peer, 2000)
	if a != b {
		t.Fatalf("IPv4 and mapped IPv6 keys differ: %v %v", a, b)
	}
}

func TestCanonicalFlowKeySeparatesProtocolAndPorts(t *testing.T) {
	a := net.ParseIP("2001:db8::1")
	b := net.ParseIP("2001:db8::2")
	tcp, _ := CanonicalizeFlowKey(ProtoTCP, a, 1000, b, 2000)
	udp, _ := CanonicalizeFlowKey(ProtoUDP, a, 1000, b, 2000)
	otherPort, _ := CanonicalizeFlowKey(ProtoTCP, a, 1001, b, 2000)
	if tcp == udp || tcp == otherPort {
		t.Fatal("protocol or port did not participate in FlowKey")
	}
}

func TestCanonicalGREKeyHasNoPorts(t *testing.T) {
	a := net.ParseIP("192.0.2.10")
	b := net.ParseIP("198.51.100.20")
	forward, fd := CanonicalizeFlowKey(ProtoGRE, a, 10, b, 20)
	reverse, rd := CanonicalizeFlowKey(ProtoGRE, b, 99, a, 88)
	if forward != reverse || fd == rd {
		t.Fatalf("GRE canonicalization failed: %v/%v %v/%v", forward, fd, reverse, rd)
	}
	if forward.A.Port != 0 || forward.B.Port != 0 {
		t.Fatalf("GRE ports must be zero: %+v", forward)
	}
}

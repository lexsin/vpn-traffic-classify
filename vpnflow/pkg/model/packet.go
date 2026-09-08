package model

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TCP flags 位掩码常量。
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// L4Protocol 使用 IANA IP protocol number，保证 TCP/UDP/GRE 同端点不冲突。
type L4Protocol uint8

const (
	ProtoUnknown L4Protocol = 0
	ProtoTCP     L4Protocol = 6
	ProtoUDP     L4Protocol = 17
	ProtoGRE     L4Protocol = 47
)

func (p L4Protocol) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoGRE:
		return "GRE"
	default:
		return fmt.Sprintf("IPPROTO_%d", uint8(p))
	}
}

// FlowDirection 是相对于规范化端点 A/B 的方向，不代表客户端/服务器。
type FlowDirection uint8

const (
	AToB FlowDirection = iota
	BToA
)

// Endpoint 是可比较、可作为 map key 的传输层端点。
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	if !e.IP.IsValid() {
		return net.JoinHostPort("<invalid>", strconv.Itoa(int(e.Port)))
	}
	return net.JoinHostPort(e.IP.String(), strconv.Itoa(int(e.Port)))
}

// FlowKey 对双端点做稳定排序；正反向报文得到同一个 key。
type FlowKey struct {
	Proto L4Protocol
	A     Endpoint
	B     Endpoint
}

func (k FlowKey) String() string {
	return k.A.String() + "-" + k.B.String() + "-" + k.Proto.String()
}

func normalizeEndpoint(ip net.IP, port uint16) Endpoint {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Endpoint{Port: port}
	}
	return Endpoint{IP: addr.Unmap(), Port: port}
}

func endpointLess(x, y Endpoint) bool {
	if c := x.IP.Compare(y.IP); c != 0 {
		return c < 0
	}
	return x.Port < y.Port
}

// CanonicalizeFlowKey 返回结构化 FlowKey 和当前报文相对于 A/B 的方向。
func CanonicalizeFlowKey(
	proto L4Protocol,
	srcIP net.IP,
	srcPort uint16,
	dstIP net.IP,
	dstPort uint16,
) (FlowKey, FlowDirection) {
	if proto == ProtoGRE {
		srcPort, dstPort = 0, 0
	}
	src := normalizeEndpoint(srcIP, srcPort)
	dst := normalizeEndpoint(dstIP, dstPort)
	if endpointLess(src, dst) {
		return FlowKey{Proto: proto, A: src, B: dst}, AToB
	}
	return FlowKey{Proto: proto, A: dst, B: src}, BToA
}

// Packet 是 TCP/UDP/GRE 统一输入单元，由数据接入层负责填充。
type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  L4Protocol
	SrcPort   uint16
	DstPort   uint16

	TCPSeq   uint32
	TCPAck   uint32
	TCPFlags uint8

	// GRE/PPTP 增强头字段。非 GRE 包保持零值。
	GREProtocol      uint16
	GREVersion       uint8
	GREPayloadLength uint16
	GRECallID        uint16
	GRESeqPresent    bool
	GREAckPresent    bool
	GRESeq           uint32
	GREAck           uint32

	Payload    []byte
	PayloadLen int
	IPLen      int // IP 层总字节数（含 IP 头）；0 表示未知
}

func (p Packet) EffectiveProtocol() L4Protocol {
	if p.Protocol == ProtoUnknown {
		// 兼容现有单元测试及旧调用者构造的 TCP Packet。
		return ProtoTCP
	}
	return p.Protocol
}

func (p Packet) IsTCP() bool { return p.EffectiveProtocol() == ProtoTCP }
func (p Packet) IsUDP() bool { return p.EffectiveProtocol() == ProtoUDP }
func (p Packet) IsGRE() bool { return p.EffectiveProtocol() == ProtoGRE }

// CanonicalKey 返回结构化 key 与 A/B 方向。
func (p Packet) CanonicalKey() (FlowKey, FlowDirection) {
	return CanonicalizeFlowKey(
		p.EffectiveProtocol(), p.SrcIP, p.SrcPort, p.DstIP, p.DstPort,
	)
}

// FlowKey 保留旧字符串接口，内部改用结构化规范化 key。
func (p Packet) FlowKey() string {
	key, _ := p.CanonicalKey()
	return key.String()
}

// ComputeFlowKey 保留 TCP 调用兼容性。
func ComputeFlowKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {
	key, _ := CanonicalizeFlowKey(ProtoTCP, srcIP, srcPort, dstIP, dstPort)
	return key.String()
}

// IPPairKey 返回忽略端口和传输层的稳定端点对，用于 PPTP TCP/GRE 跨流关联。
func IPPairKey(srcIP, dstIP net.IP) string {
	a := normalizeEndpoint(srcIP, 0).IP
	b := normalizeEndpoint(dstIP, 0).IP
	if a.Compare(b) <= 0 {
		return strings.Join([]string{a.String(), b.String()}, "|")
	}
	return strings.Join([]string{b.String(), a.String()}, "|")
}

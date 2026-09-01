package model

import (
	"fmt"
	"net"
	"time"
)

// TCP flags 位掩码常量
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// Packet 是核心处理层的统一输入单元，由数据接入层负责填充。
type Packet struct {
	Timestamp  time.Time
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	TCPSeq     uint32
	TCPAck     uint32
	TCPFlags   uint8
	Payload    []byte
	PayloadLen int
	IPLen      int // IP 层总字节数（含 IP 头），用于包大小分布特征；0 表示未知
}

// FlowKey 根据五元组生成规范化 FlowKey 字符串，保证双向包映射到同一 Key。
func (p *Packet) FlowKey() string {
	return ComputeFlowKey(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
}

// ComputeFlowKey 将五元组规范化为唯一字符串，格式："<minEP>-<maxEP>-TCP"。
// 规范化规则：以字典序较小的端点排在前面。
//
// 注：MVP 阶段只处理 TCP，后缀固定 "-TCP"。未来引入 UDP 时需改为按协议区分。
func ComputeFlowKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) string {
	a := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	b := fmt.Sprintf("%s:%d", dstIP.String(), dstPort)
	if a <= b {
		return a + "-" + b + "-TCP"
	}
	return b + "-" + a + "-TCP"
}

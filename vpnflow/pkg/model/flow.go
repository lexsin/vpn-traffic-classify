package model

import (
	"net"
	"time"
)

// PacketInfo 是单包的轻量元数据，按时间顺序累积在 Flow.Packets 中，
// 供流级特征提取使用：包大小分布、IAT、前 N 包序列、TCP flags 统计、方向切换。
//
// 注意：不保留原始 payload，控制内存占用。原始 payload 由 reassembly 重组为
// ClientStream/ServerStream，供 Phase 2 的 TLS 解析与 inner TLS 检测使用。
type PacketInfo struct {
	Timestamp  time.Time
	Direction  int // 0=uplink(client→server), 1=downlink
	IPLen      int // IP 层总字节数（含 IP 头），用于包大小分布特征
	PayloadLen int // TCP payload 字节数（不含 TCP/IP 头），用于 payload 统计
	TCPFlags   uint8
}

// IsAckOnly 判断是否为纯 ACK 包（仅 ACK 标志，无 payload）。
func (p PacketInfo) IsAckOnly() bool {
	return p.PayloadLen == 0 &&
		(p.TCPFlags&TCPFlagACK) != 0 &&
		(p.TCPFlags&(TCPFlagSYN|TCPFlagFIN|TCPFlagRST|TCPFlagPSH)) == 0
}

// Flow 表示一条 TCP 连接的重组结果。
//
// Phase 1 只填充 Packets / ClientStream / ServerStream / 基础统计；
// Records / TLSVersion / SNI 等 TLS 元数据在 Phase 2 由 TLS 解析层填充。
type Flow struct {
	FlowKey    string
	ClientIP   net.IP
	ServerIP   net.IP
	ClientPort uint16
	ServerPort uint16

	// 包级元数据序列（按时间顺序），供流级特征提取
	Packets []PacketInfo

	// 重组后的字节流（每方向独立），供 Phase 2 的 TLS 解析 / inner TLS 检测
	ClientStream []byte
	ServerStream []byte

	// 基础统计（reassembly 时累积）
	StartTime            time.Time
	EndTime              time.Time
	TotalPackets         int
	UplinkPackets        int
	DownlinkPackets      int
	UplinkPayloadBytes   int
	DownlinkPayloadBytes int

	// TCPHandshakeComplete 表示抓包中按顺序观察到并校验了 SYN、SYN+ACK、ACK。
	// 该字段只用于流完整性过滤，不作为模型训练特征。
	TCPHandshakeComplete bool

	// TLS 元数据（Phase 2 由 tlsextract 填充；Phase 1 保持零值）
	Records    []TLSRecord
	TLSVersion uint16
	SNILength  int    // -1 表示未见 ClientHello
	SNIValue   string // "" 表示未见 ClientHello 或解析失败

	// 外层 ClientHello 指纹（Phase 2）
	ClientHelloSize    int // ClientHello handshake 消息字节数；0 表示未见
	CipherCount        int // cipher suite 数量（含 GREASE）
	ExtensionCount     int // extension 数量（含 GREASE）
	HasGREASE          bool
	JA3Hash            string // 标准 JA3 MD5 hex（排除 GREASE）；"" 表示未见 ClientHello
	ExtensionOrderHash string // 扩展顺序（含 GREASE）MD5 hex

	// 外层 AppData 早期长度序列（按 record 出现顺序，跨方向）
	AppDataLens []int

	// 内层 TLS 检测结果（Phase 2 由 innertls.Detect 填充）
	InnerHelloCount  int
	InnerOffsetValue float64 // 秒；无内层握手时 -1
	InnerOffsetValid int
}

// Duration 返回流持续时间（秒）。
func (f *Flow) Duration() float64 {
	if f.StartTime.IsZero() || f.EndTime.IsZero() {
		return 0
	}
	return f.EndTime.Sub(f.StartTime).Seconds()
}

// TotalPayloadBytes 返回双向 payload 总字节数。
func (f *Flow) TotalPayloadBytes() int {
	return f.UplinkPayloadBytes + f.DownlinkPayloadBytes
}

// IsBidirectional 返回是否双向都有包。
func (f *Flow) IsBidirectional() bool {
	return f.UplinkPackets > 0 && f.DownlinkPackets > 0
}

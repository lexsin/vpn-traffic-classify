package model

import (
	"fmt"
	"net"
	"time"
)

// FeatureRow 是输出给 ML 训练/推理的一行特征数据（Phase 1 标量 + Phase 2 TLS/序列）。
type FeatureRow struct {
	// 辅助列（不参与训练）
	SourceFile string
	FlowKey    string
	Label      string
	Proto      string

	// 五元组（定位用，绝不入模型）
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16

	// 时间
	FlowStartTS  time.Time
	FlowEndTS    time.Time
	FlowDuration float64

	// 基础统计
	TotalPackets           int
	TotalPayloadBytes      int
	UplinkPayloadBytes     int
	DownlinkPayloadBytes   int
	UplinkPackets          int
	DownlinkPackets        int
	PayloadPackets         int
	UplinkPayloadPackets   int
	DownlinkPayloadPackets int
	BytesRatio             float64
	PacketCountRatio       float64
	PayloadPacketRatio     float64
	PktsPerSecond          float64
	BytesPerSecond         float64
	PayloadBytesPerSecond  float64

	// 包大小分布
	RatioSmall100                 float64
	Ratio1514                     float64
	PktSizeMean                   float64
	PktSizeStd                    float64
	PktSizeCV                     float64
	PktSizeEntropy                float64
	IsBimodal                     int
	PayloadSizeMean               float64
	PayloadSizeStd                float64
	PayloadSizeCV                 float64
	PayloadSizeEntropy            float64
	AvgPayloadBytesPerPayloadPkt  float64
	AvgUplinkPayloadBytesPerPkt   float64
	AvgDownlinkPayloadBytesPerPkt float64

	// 时序 IAT
	IATMean    float64
	IATStd     float64
	IATP50     float64
	IATP90     float64
	BurstRatio float64

	// TCP flags
	AckOnlyRatio     float64
	ZeroPayloadRatio float64
	PshRatio         float64
	// TCPHandshakeComplete 是质量辅助列，不进入模型特征。
	TCPHandshakeComplete int

	// 方向
	DirectionSwitchRate  float64
	UplinkPayloadRatio   float64
	DownlinkPayloadRatio float64

	// —— Phase 2: 外层 TLS ——
	OuterClientHelloPresent int
	OuterClientHelloSize    int
	OuterTLSVersion         int // 0x0303/0x0304 或 0
	OuterCipherCount        int
	OuterExtensionCount     int
	OuterHasGREASE          int // 0/1
	OuterJA3Hash            string
	OuterJA3HashInt         uint64 // JA3 MD5 前 8 字节，数值化供模型
	OuterExtOrderHash       string
	OuterExtOrderHashInt    uint64

	// —— Phase 2: 外层 AppData 早期序列 ——
	OuterAppDataLen          [6]int
	FirstUplinkAppDataSize   int
	FirstDownlinkAppDataSize int
	FirstAppdataULToDLMs     float64

	// —— Phase 2: 内层 TLS 检测 ——
	InnerHelloCount  int
	InnerOffsetValue float64
	InnerOffsetValid int

	// —— Phase 2: 前 10 包序列 ——
	PktSize        [10]int
	PktDir         [10]int // 1=uplink, -1=downlink, 0=填充
	PktIAT         [10]float64
	ActualPktCount int

	// —— Phase 2: 前 10 个含 payload 包序列 ——
	PayloadPktSize        [10]int
	PayloadPktDir         [10]int
	PayloadPktIAT         [10]float64
	ActualPayloadPktCount int
}

// CSVHeader 返回与 FeatureRow 字段顺序一致的 CSV 表头。
func CSVHeader() []string {
	h := []string{
		"source_file", "flow_key", "label", "proto",
		"src_ip", "src_port", "dst_ip", "dst_port",
		"flow_start_ts", "flow_end_ts", "flow_duration",
		"total_packets", "total_payload_bytes",
		"uplink_payload_bytes", "downlink_payload_bytes",
		"uplink_packets", "downlink_packets",
		"payload_packets", "uplink_payload_packets", "downlink_payload_packets",
		"bytes_ratio", "packet_count_ratio", "payload_packet_ratio",
		"pkts_per_second", "bytes_per_second", "payload_bytes_per_second",
		"ratio_small_100", "ratio_1514",
		"pkt_size_mean", "pkt_size_std", "pkt_size_cv", "pkt_size_entropy", "is_bimodal",
		"payload_size_mean", "payload_size_std", "payload_size_cv", "payload_size_entropy",
		"avg_payload_bytes_per_payload_pkt", "avg_uplink_payload_bytes_per_pkt", "avg_downlink_payload_bytes_per_pkt",
		"iat_mean", "iat_std", "iat_p50", "iat_p90", "burst_ratio",
		"ack_only_ratio", "zero_payload_ratio", "psh_ratio", "tcp_handshake_complete",
		"direction_switch_rate", "uplink_payload_ratio", "downlink_payload_ratio",
		"outer_client_hello_present", "outer_client_hello_size", "outer_tls_version",
		"outer_cipher_count", "outer_extension_count", "outer_has_grease",
		"outer_ja3_hash", "outer_ja3_hash_int",
		"outer_extension_order_hash", "outer_extension_order_hash_int",
	}
	for i := 1; i <= 6; i++ {
		h = append(h, fmt.Sprintf("outer_appdata_len_%d", i))
	}
	h = append(h,
		"first_uplink_appdata_size", "first_downlink_appdata_size", "first_appdata_ul_to_dl_ms",
		"inner_hello_count", "inner_offset_value", "inner_offset_valid",
	)
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("pkt_size_%d", i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("pkt_dir_%d", i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("pkt_iat_%d", i))
	}
	h = append(h, "actual_pkt_count")
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("payload_pkt_size_%d", i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("payload_pkt_dir_%d", i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("payload_pkt_iat_%d", i))
	}
	h = append(h, "actual_payload_pkt_count")
	return h
}

// ToCSVRecord 将 FeatureRow 转换为字符串切片，顺序与 CSVHeader() 一致。
func (r FeatureRow) ToCSVRecord() []string {
	fi := func(v int) string { return fmt.Sprintf("%d", v) }
	ff := func(v float64) string { return fmt.Sprintf("%.6f", v) }
	fu := func(v uint64) string { return fmt.Sprintf("%d", v) }
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339Nano)
	}
	ipStr := func(ip net.IP) string {
		if len(ip) == 0 {
			return ""
		}
		return ip.String()
	}
	out := []string{
		r.SourceFile, r.FlowKey, r.Label, r.Proto,
		ipStr(r.SrcIP), fi(int(r.SrcPort)), ipStr(r.DstIP), fi(int(r.DstPort)),
		ts(r.FlowStartTS), ts(r.FlowEndTS), ff(r.FlowDuration),
		fi(r.TotalPackets), fi(r.TotalPayloadBytes),
		fi(r.UplinkPayloadBytes), fi(r.DownlinkPayloadBytes),
		fi(r.UplinkPackets), fi(r.DownlinkPackets),
		fi(r.PayloadPackets), fi(r.UplinkPayloadPackets), fi(r.DownlinkPayloadPackets),
		ff(r.BytesRatio), ff(r.PacketCountRatio), ff(r.PayloadPacketRatio),
		ff(r.PktsPerSecond), ff(r.BytesPerSecond), ff(r.PayloadBytesPerSecond),
		ff(r.RatioSmall100), ff(r.Ratio1514),
		ff(r.PktSizeMean), ff(r.PktSizeStd), ff(r.PktSizeCV), ff(r.PktSizeEntropy), fi(r.IsBimodal),
		ff(r.PayloadSizeMean), ff(r.PayloadSizeStd), ff(r.PayloadSizeCV), ff(r.PayloadSizeEntropy),
		ff(r.AvgPayloadBytesPerPayloadPkt), ff(r.AvgUplinkPayloadBytesPerPkt), ff(r.AvgDownlinkPayloadBytesPerPkt),
		ff(r.IATMean), ff(r.IATStd), ff(r.IATP50), ff(r.IATP90), ff(r.BurstRatio),
		ff(r.AckOnlyRatio), ff(r.ZeroPayloadRatio), ff(r.PshRatio), fi(r.TCPHandshakeComplete),
		ff(r.DirectionSwitchRate), ff(r.UplinkPayloadRatio), ff(r.DownlinkPayloadRatio),
		fi(r.OuterClientHelloPresent), fi(r.OuterClientHelloSize), fi(r.OuterTLSVersion),
		fi(r.OuterCipherCount), fi(r.OuterExtensionCount), fi(r.OuterHasGREASE),
		r.OuterJA3Hash, fu(r.OuterJA3HashInt),
		r.OuterExtOrderHash, fu(r.OuterExtOrderHashInt),
	}
	for i := 0; i < 6; i++ {
		out = append(out, fi(r.OuterAppDataLen[i]))
	}
	out = append(out,
		fi(r.FirstUplinkAppDataSize), fi(r.FirstDownlinkAppDataSize), ff(r.FirstAppdataULToDLMs),
		fi(r.InnerHelloCount), ff(r.InnerOffsetValue), fi(r.InnerOffsetValid),
	)
	for i := 0; i < 10; i++ {
		out = append(out, fi(r.PktSize[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, fi(r.PktDir[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, ff(r.PktIAT[i]))
	}
	out = append(out, fi(r.ActualPktCount))
	for i := 0; i < 10; i++ {
		out = append(out, fi(r.PayloadPktSize[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, fi(r.PayloadPktDir[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, ff(r.PayloadPktIAT[i]))
	}
	out = append(out, fi(r.ActualPayloadPktCount))
	return out
}

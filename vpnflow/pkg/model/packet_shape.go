package model

import "fmt"

// PacketShape 是从一个指定的包时间窗口计算出的流量形状特征。
// 它不包含地址、端口、TLS 指纹或协议字段，可用于将 shape_sequence
// 同样地应用到 TLS 握手后的载荷窗口。
type PacketShape struct {
	FlowDuration float64

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

	IATMean    float64
	IATStd     float64
	IATP50     float64
	IATP90     float64
	BurstRatio float64

	AckOnlyRatio         float64
	ZeroPayloadRatio     float64
	PshRatio             float64
	DirectionSwitchRate  float64
	UplinkPayloadRatio   float64
	DownlinkPayloadRatio float64

	PktSize        [10]int
	PktDir         [10]int
	PktIAT         [10]float64
	ActualPktCount int

	PayloadPktSize        [10]int
	PayloadPktDir         [10]int
	PayloadPktIAT         [10]float64
	ActualPayloadPktCount int
}

func packetShapeCSVHeader(prefix string) []string {
	h := []string{
		prefix + "flow_duration",
		prefix + "total_packets", prefix + "total_payload_bytes",
		prefix + "uplink_payload_bytes", prefix + "downlink_payload_bytes",
		prefix + "uplink_packets", prefix + "downlink_packets",
		prefix + "payload_packets", prefix + "uplink_payload_packets", prefix + "downlink_payload_packets",
		prefix + "bytes_ratio", prefix + "packet_count_ratio", prefix + "payload_packet_ratio",
		prefix + "pkts_per_second", prefix + "bytes_per_second", prefix + "payload_bytes_per_second",
		prefix + "ratio_small_100", prefix + "ratio_1514",
		prefix + "pkt_size_mean", prefix + "pkt_size_std", prefix + "pkt_size_cv", prefix + "pkt_size_entropy", prefix + "is_bimodal",
		prefix + "payload_size_mean", prefix + "payload_size_std", prefix + "payload_size_cv", prefix + "payload_size_entropy",
		prefix + "avg_payload_bytes_per_payload_pkt", prefix + "avg_uplink_payload_bytes_per_pkt", prefix + "avg_downlink_payload_bytes_per_pkt",
		prefix + "iat_mean", prefix + "iat_std", prefix + "iat_p50", prefix + "iat_p90", prefix + "burst_ratio",
		prefix + "ack_only_ratio", prefix + "zero_payload_ratio", prefix + "psh_ratio",
		prefix + "direction_switch_rate", prefix + "uplink_payload_ratio", prefix + "downlink_payload_ratio",
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spkt_size_%d", prefix, i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spkt_dir_%d", prefix, i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spkt_iat_%d", prefix, i))
	}
	h = append(h, prefix+"actual_pkt_count")
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spayload_pkt_size_%d", prefix, i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spayload_pkt_dir_%d", prefix, i))
	}
	for i := 1; i <= 10; i++ {
		h = append(h, fmt.Sprintf("%spayload_pkt_iat_%d", prefix, i))
	}
	return append(h, prefix+"actual_payload_pkt_count")
}

func appendPacketShapeCSV(out []string, s PacketShape) []string {
	fi := func(v int) string { return fmt.Sprintf("%d", v) }
	ff := func(v float64) string { return fmt.Sprintf("%.6f", v) }
	out = append(out,
		ff(s.FlowDuration),
		fi(s.TotalPackets), fi(s.TotalPayloadBytes),
		fi(s.UplinkPayloadBytes), fi(s.DownlinkPayloadBytes),
		fi(s.UplinkPackets), fi(s.DownlinkPackets),
		fi(s.PayloadPackets), fi(s.UplinkPayloadPackets), fi(s.DownlinkPayloadPackets),
		ff(s.BytesRatio), ff(s.PacketCountRatio), ff(s.PayloadPacketRatio),
		ff(s.PktsPerSecond), ff(s.BytesPerSecond), ff(s.PayloadBytesPerSecond),
		ff(s.RatioSmall100), ff(s.Ratio1514),
		ff(s.PktSizeMean), ff(s.PktSizeStd), ff(s.PktSizeCV), ff(s.PktSizeEntropy), fi(s.IsBimodal),
		ff(s.PayloadSizeMean), ff(s.PayloadSizeStd), ff(s.PayloadSizeCV), ff(s.PayloadSizeEntropy),
		ff(s.AvgPayloadBytesPerPayloadPkt), ff(s.AvgUplinkPayloadBytesPerPkt), ff(s.AvgDownlinkPayloadBytesPerPkt),
		ff(s.IATMean), ff(s.IATStd), ff(s.IATP50), ff(s.IATP90), ff(s.BurstRatio),
		ff(s.AckOnlyRatio), ff(s.ZeroPayloadRatio), ff(s.PshRatio),
		ff(s.DirectionSwitchRate), ff(s.UplinkPayloadRatio), ff(s.DownlinkPayloadRatio),
	)
	for i := 0; i < 10; i++ {
		out = append(out, fi(s.PktSize[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, fi(s.PktDir[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, ff(s.PktIAT[i]))
	}
	out = append(out, fi(s.ActualPktCount))
	for i := 0; i < 10; i++ {
		out = append(out, fi(s.PayloadPktSize[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, fi(s.PayloadPktDir[i]))
	}
	for i := 0; i < 10; i++ {
		out = append(out, ff(s.PayloadPktIAT[i]))
	}
	return append(out, fi(s.ActualPayloadPktCount))
}

package features

import (
	"math"
	"sort"
	"time"

	"vpnflow/pkg/core/innertls"
	"vpnflow/pkg/model"
)

// entropyBinEdges 包大小 16-bin 直方图的分桶边界（上界）。
var entropyBinEdges = []int{54, 60, 100, 200, 300, 400, 500, 600, 800, 1000, 1200, 1300, 1400, 1500, 1514}

func binIndex(s int) int {
	for i, e := range entropyBinEdges {
		if s <= e {
			return i
		}
	}
	return len(entropyBinEdges)
}

func entropy(sizes []int) float64 {
	n := len(sizes)
	if n == 0 {
		return 0
	}
	var bins [16]int
	for _, s := range sizes {
		bins[binIndex(s)]++
	}
	var ent float64
	nf := float64(n)
	for _, c := range bins {
		if c == 0 {
			continue
		}
		p := float64(c) / nf
		ent -= p * math.Log2(p)
	}
	return ent
}

func entropyPayload(sizes []int) float64 {
	n := len(sizes)
	if n == 0 {
		return 0
	}
	var bins [16]int
	for _, s := range sizes {
		bins[binIndex(s)]++
	}
	var ent float64
	nf := float64(n)
	for _, c := range bins {
		if c == 0 {
			continue
		}
		p := float64(c) / nf
		ent -= p * math.Log2(p)
	}
	return ent
}

func meanStd(xs []float64) (mean, std float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	var sq float64
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	std = math.Sqrt(sq / float64(len(xs)))
	return
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// hashHexToInt 将 MD5 hex 字符串前 8 字节转为 uint64，供模型作数值特征。
func hashHexToInt(h string) uint64 {
	if len(h) < 16 {
		return 0
	}
	var v uint64
	for i := 0; i < 16; i++ {
		c := h[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			d = uint64(c - 'A' + 10)
		default:
			return 0
		}
		v = (v << 4) | d
	}
	return v
}

// Extract 从一条 Flow 提取全部特征（Phase 1 标量 + Phase 2 TLS/序列/inner）。
func Extract(flow *model.Flow, sourceFile, label string) model.FeatureRow {
	r := model.FeatureRow{
		SourceFile:           sourceFile,
		FlowKey:              flow.FlowKey,
		Label:                label,
		Proto:                "tcp",
		SrcIP:                flow.ClientIP,
		SrcPort:              flow.ClientPort,
		DstIP:                flow.ServerIP,
		DstPort:              flow.ServerPort,
		FlowStartTS:          flow.StartTime,
		FlowEndTS:            flow.EndTime,
		FlowDuration:         flow.Duration(),
		TotalPackets:         flow.TotalPackets,
		TotalPayloadBytes:    flow.TotalPayloadBytes(),
		UplinkPayloadBytes:   flow.UplinkPayloadBytes,
		DownlinkPayloadBytes: flow.DownlinkPayloadBytes,
		UplinkPackets:        flow.UplinkPackets,
		DownlinkPackets:      flow.DownlinkPackets,
	}
	if flow.TCPHandshakeComplete {
		r.TCPHandshakeComplete = 1
	}

	dur := r.FlowDuration
	if dur > 0 {
		r.PktsPerSecond = float64(r.TotalPackets) / dur
		r.BytesPerSecond = float64(r.TotalPayloadBytes) / dur
		r.PayloadBytesPerSecond = float64(r.TotalPayloadBytes) / dur
	}
	r.BytesRatio = float64(r.UplinkPayloadBytes) / math.Max(float64(r.DownlinkPayloadBytes), 1)
	r.PacketCountRatio = float64(r.UplinkPackets) / math.Max(float64(r.DownlinkPackets), 1)

	pkts := flow.Packets
	n := len(pkts)

	// —— 包大小分布 ——
	if n > 0 {
		sizes := make([]int, n)
		for i, p := range pkts {
			sizes[i] = p.IPLen
		}
		small100, large1514 := 0, 0
		for _, s := range sizes {
			if s <= 100 {
				small100++
			}
			if s >= 1500 {
				large1514++
			}
		}
		r.RatioSmall100 = float64(small100) / float64(n)
		r.Ratio1514 = float64(large1514) / float64(n)
		szf := make([]float64, n)
		for i, s := range sizes {
			szf[i] = float64(s)
		}
		mean, std := meanStd(szf)
		r.PktSizeMean = mean
		r.PktSizeStd = std
		if mean > 0 {
			r.PktSizeCV = std / mean
		} else {
			r.PktSizeCV = -1
		}
		r.PktSizeEntropy = entropy(sizes)
		smallBimodal, largeBimodal := 0, 0
		for _, s := range sizes {
			if s >= 50 && s <= 150 {
				smallBimodal++
			}
			if s >= 1400 && s <= 1514 {
				largeBimodal++
			}
		}
		if float64(smallBimodal)/float64(n) >= 0.10 && float64(largeBimodal)/float64(n) >= 0.10 {
			r.IsBimodal = 1
		}

		// —— IAT 时序 ——
		iats := make([]float64, 0, n-1)
		for i := 1; i < n; i++ {
			d := pkts[i].Timestamp.Sub(pkts[i-1].Timestamp).Seconds()
			if d < 0 {
				d = 0
			}
			iats = append(iats, d)
		}
		if len(iats) > 0 {
			m, s := meanStd(iats)
			r.IATMean = m
			r.IATStd = s
			sorted := append([]float64(nil), iats...)
			sort.Float64s(sorted)
			r.IATP50 = percentile(sorted, 0.50)
			r.IATP90 = percentile(sorted, 0.90)
			burst := 0
			for _, d := range iats {
				if d < 0.010 {
					burst++
				}
			}
			r.BurstRatio = float64(burst) / float64(len(iats))
		}

		// —— TCP flags + payload 包统计 ——
		ackOnly, zeroPay, psh := 0, 0, 0
		payloadSizes := make([]int, 0, n)
		payloadSizeFloats := make([]float64, 0, n)
		payloadPkts := make([]model.PacketInfo, 0, n)
		for _, p := range pkts {
			if p.IsAckOnly() {
				ackOnly++
			}
			if p.PayloadLen == 0 {
				zeroPay++
			} else {
				r.PayloadPackets++
				payloadSizes = append(payloadSizes, p.PayloadLen)
				payloadSizeFloats = append(payloadSizeFloats, float64(p.PayloadLen))
				payloadPkts = append(payloadPkts, p)
				if p.Direction == model.DirectionUplink {
					r.UplinkPayloadPackets++
				} else {
					r.DownlinkPayloadPackets++
				}
			}
			if p.TCPFlags&model.TCPFlagPSH != 0 {
				psh++
			}
		}
		r.AckOnlyRatio = float64(ackOnly) / float64(n)
		r.ZeroPayloadRatio = float64(zeroPay) / float64(n)
		r.PshRatio = float64(psh) / float64(n)
		r.PayloadPacketRatio = float64(r.PayloadPackets) / float64(n)
		if len(payloadSizeFloats) > 0 {
			mean, std := meanStd(payloadSizeFloats)
			r.PayloadSizeMean = mean
			r.PayloadSizeStd = std
			if mean > 0 {
				r.PayloadSizeCV = std / mean
			} else {
				r.PayloadSizeCV = -1
			}
			r.PayloadSizeEntropy = entropyPayload(payloadSizes)
			r.AvgPayloadBytesPerPayloadPkt = float64(r.TotalPayloadBytes) / float64(r.PayloadPackets)
		}
		if r.UplinkPayloadPackets > 0 {
			r.AvgUplinkPayloadBytesPerPkt = float64(r.UplinkPayloadBytes) / float64(r.UplinkPayloadPackets)
		}
		if r.DownlinkPayloadPackets > 0 {
			r.AvgDownlinkPayloadBytesPerPkt = float64(r.DownlinkPayloadBytes) / float64(r.DownlinkPayloadPackets)
		}

		// —— 方向 ——
		switches := 0
		for i := 1; i < n; i++ {
			if pkts[i].Direction != pkts[i-1].Direction {
				switches++
			}
		}
		if n > 1 {
			r.DirectionSwitchRate = float64(switches) / float64(n-1)
		}

		// —— 前 10 个含 payload 包序列 ——
		r.ActualPayloadPktCount = len(payloadPkts)
		for i := 0; i < 10 && i < len(payloadPkts); i++ {
			r.PayloadPktSize[i] = payloadPkts[i].PayloadLen
			if payloadPkts[i].Direction == model.DirectionUplink {
				r.PayloadPktDir[i] = 1
			} else {
				r.PayloadPktDir[i] = -1
			}
			if i == 0 {
				r.PayloadPktIAT[i] = 0
			} else {
				d := payloadPkts[i].Timestamp.Sub(payloadPkts[i-1].Timestamp).Seconds()
				if d < 0 {
					d = 0
				}
				r.PayloadPktIAT[i] = d
			}
		}
	}
	totalPay := r.TotalPayloadBytes
	if totalPay > 0 {
		r.UplinkPayloadRatio = float64(r.UplinkPayloadBytes) / float64(totalPay)
		r.DownlinkPayloadRatio = float64(r.DownlinkPayloadBytes) / float64(totalPay)
	}

	// —— Phase 2: 外层 TLS 指纹 ——
	if flow.ClientHelloSize > 0 {
		r.OuterClientHelloPresent = 1
	}
	r.OuterClientHelloSize = flow.ClientHelloSize
	r.OuterTLSVersion = int(flow.TLSVersion)
	r.OuterCipherCount = flow.CipherCount
	r.OuterExtensionCount = flow.ExtensionCount
	if flow.HasGREASE {
		r.OuterHasGREASE = 1
	}
	r.OuterJA3Hash = flow.JA3Hash
	r.OuterJA3HashInt = hashHexToInt(flow.JA3Hash)
	r.OuterExtOrderHash = flow.ExtensionOrderHash
	r.OuterExtOrderHashInt = hashHexToInt(flow.ExtensionOrderHash)

	// —— Phase 2: 外层 AppData 早期序列 + first appdata 时延 ——
	for i := 0; i < 6 && i < len(flow.AppDataLens); i++ {
		r.OuterAppDataLen[i] = flow.AppDataLens[i]
	}
	var firstUL, firstDL time.Time
	for _, rec := range flow.Records {
		if !rec.IsAppData() {
			continue
		}
		if rec.Direction == model.DirectionUplink && firstUL.IsZero() {
			firstUL = rec.Timestamp
			r.FirstUplinkAppDataSize = int(rec.RecordLength)
		}
		if rec.Direction == model.DirectionDownlink && firstDL.IsZero() {
			firstDL = rec.Timestamp
			r.FirstDownlinkAppDataSize = int(rec.RecordLength)
		}
		if !firstUL.IsZero() && !firstDL.IsZero() {
			break
		}
	}
	if !firstUL.IsZero() && !firstDL.IsZero() {
		r.FirstAppdataULToDLMs = firstDL.Sub(firstUL).Seconds() * 1000
	} else {
		r.FirstAppdataULToDLMs = -1
	}

	// —— Phase 2: 内层 TLS 检测 ——
	cnt, off, valid := innertls.Detect(flow)
	r.InnerHelloCount = cnt
	r.InnerOffsetValue = off
	r.InnerOffsetValid = valid

	// —— Phase 2: 前 10 包序列 ——
	r.ActualPktCount = n
	for i := 0; i < 10 && i < n; i++ {
		r.PktSize[i] = pkts[i].IPLen
		if pkts[i].Direction == model.DirectionUplink {
			r.PktDir[i] = 1
		} else {
			r.PktDir[i] = -1
		}
		if i == 0 {
			r.PktIAT[i] = 0
		} else {
			d := pkts[i].Timestamp.Sub(pkts[i-1].Timestamp).Seconds()
			if d < 0 {
				d = 0
			}
			r.PktIAT[i] = d
		}
	}

	return r
}

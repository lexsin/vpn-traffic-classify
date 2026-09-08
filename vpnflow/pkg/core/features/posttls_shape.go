package features

import (
	"math"
	"sort"

	"vpnflow/pkg/model"
)

// postTLSPayloadPackets returns the packet-level window beginning with the
// first outer TLS application-data record that belongs to post-handshake
// traffic. Packet metadata is the finest retained granularity, so when a
// boundary record is coalesced with another record in the same TCP packet,
// that complete packet is retained rather than guessed apart.
func postTLSPayloadPackets(flow *model.Flow, records []model.TLSRecord) []model.PacketInfo {
	if len(records) == 0 || records[0].Timestamp.IsZero() {
		return nil
	}
	start := records[0].Timestamp
	out := make([]model.PacketInfo, 0, len(flow.Packets))
	for _, pkt := range flow.Packets {
		if !pkt.Timestamp.Before(start) {
			out = append(out, pkt)
		}
	}
	return out
}

// buildPacketShape calculates the same 103 shape_sequence quantities from
// the supplied packet window only. It deliberately has no TLS fields.
func buildPacketShape(pkts []model.PacketInfo) model.PacketShape {
	var s model.PacketShape
	n := len(pkts)
	s.TotalPackets = n
	s.ActualPktCount = n
	if n == 0 {
		return s
	}

	dur := pkts[n-1].Timestamp.Sub(pkts[0].Timestamp).Seconds()
	if dur < 0 {
		dur = 0
	}
	s.FlowDuration = dur

	sizes := make([]int, n)
	payloadSizes := make([]int, 0, n)
	payloadSizeFloats := make([]float64, 0, n)
	payloadPkts := make([]model.PacketInfo, 0, n)
	ackOnly, zeroPayload, psh, small100, large1514 := 0, 0, 0, 0, 0

	for i, pkt := range pkts {
		sizes[i] = pkt.IPLen
		if pkt.Direction == model.DirectionUplink {
			s.UplinkPackets++
		} else {
			s.DownlinkPackets++
		}
		if pkt.IPLen <= 100 {
			small100++
		}
		if pkt.IPLen >= 1500 {
			large1514++
		}
		if pkt.IsAckOnly() {
			ackOnly++
		}
		if pkt.TCPFlags&model.TCPFlagPSH != 0 {
			psh++
		}
		if pkt.PayloadLen == 0 {
			zeroPayload++
			continue
		}

		s.TotalPayloadBytes += pkt.PayloadLen
		s.PayloadPackets++
		payloadSizes = append(payloadSizes, pkt.PayloadLen)
		payloadSizeFloats = append(payloadSizeFloats, float64(pkt.PayloadLen))
		payloadPkts = append(payloadPkts, pkt)
		if pkt.Direction == model.DirectionUplink {
			s.UplinkPayloadBytes += pkt.PayloadLen
			s.UplinkPayloadPackets++
		} else {
			s.DownlinkPayloadBytes += pkt.PayloadLen
			s.DownlinkPayloadPackets++
		}
	}

	s.BytesRatio = float64(s.UplinkPayloadBytes) / math.Max(float64(s.DownlinkPayloadBytes), 1)
	s.PacketCountRatio = float64(s.UplinkPackets) / math.Max(float64(s.DownlinkPackets), 1)
	s.PayloadPacketRatio = float64(s.PayloadPackets) / float64(n)
	s.AckOnlyRatio = float64(ackOnly) / float64(n)
	s.ZeroPayloadRatio = float64(zeroPayload) / float64(n)
	s.PshRatio = float64(psh) / float64(n)
	s.RatioSmall100 = float64(small100) / float64(n)
	s.Ratio1514 = float64(large1514) / float64(n)

	if dur > 0 {
		s.PktsPerSecond = float64(n) / dur
		s.BytesPerSecond = float64(s.TotalPayloadBytes) / dur
		s.PayloadBytesPerSecond = float64(s.TotalPayloadBytes) / dur
	}
	if s.TotalPayloadBytes > 0 {
		s.UplinkPayloadRatio = float64(s.UplinkPayloadBytes) / float64(s.TotalPayloadBytes)
		s.DownlinkPayloadRatio = float64(s.DownlinkPayloadBytes) / float64(s.TotalPayloadBytes)
	}

	sizeFloats := make([]float64, n)
	for i, size := range sizes {
		sizeFloats[i] = float64(size)
	}
	s.PktSizeMean, s.PktSizeStd = meanStd(sizeFloats)
	if s.PktSizeMean > 0 {
		s.PktSizeCV = s.PktSizeStd / s.PktSizeMean
	} else {
		s.PktSizeCV = -1
	}
	s.PktSizeEntropy = entropy(sizes)

	smallBimodal, largeBimodal := 0, 0
	for _, size := range sizes {
		if size >= 50 && size <= 150 {
			smallBimodal++
		}
		if size >= 1400 && size <= 1514 {
			largeBimodal++
		}
	}
	if float64(smallBimodal)/float64(n) >= 0.10 && float64(largeBimodal)/float64(n) >= 0.10 {
		s.IsBimodal = 1
	}

	iats := make([]float64, 0, n-1)
	switches := 0
	for i := 1; i < n; i++ {
		d := pkts[i].Timestamp.Sub(pkts[i-1].Timestamp).Seconds()
		if d < 0 {
			d = 0
		}
		iats = append(iats, d)
		if pkts[i].Direction != pkts[i-1].Direction {
			switches++
		}
	}
	if len(iats) > 0 {
		s.IATMean, s.IATStd = meanStd(iats)
		sorted := append([]float64(nil), iats...)
		sort.Float64s(sorted)
		s.IATP50 = percentile(sorted, 0.50)
		s.IATP90 = percentile(sorted, 0.90)
		burst := 0
		for _, d := range iats {
			if d < 0.010 {
				burst++
			}
		}
		s.BurstRatio = float64(burst) / float64(len(iats))
	}
	if n > 1 {
		s.DirectionSwitchRate = float64(switches) / float64(n-1)
	}

	if len(payloadSizeFloats) > 0 {
		s.PayloadSizeMean, s.PayloadSizeStd = meanStd(payloadSizeFloats)
		if s.PayloadSizeMean > 0 {
			s.PayloadSizeCV = s.PayloadSizeStd / s.PayloadSizeMean
		} else {
			s.PayloadSizeCV = -1
		}
		s.PayloadSizeEntropy = entropyPayload(payloadSizes)
		s.AvgPayloadBytesPerPayloadPkt = float64(s.TotalPayloadBytes) / float64(s.PayloadPackets)
	}
	if s.UplinkPayloadPackets > 0 {
		s.AvgUplinkPayloadBytesPerPkt = float64(s.UplinkPayloadBytes) / float64(s.UplinkPayloadPackets)
	}
	if s.DownlinkPayloadPackets > 0 {
		s.AvgDownlinkPayloadBytesPerPkt = float64(s.DownlinkPayloadBytes) / float64(s.DownlinkPayloadPackets)
	}

	for i := 0; i < 10 && i < n; i++ {
		s.PktSize[i] = pkts[i].IPLen
		if pkts[i].Direction == model.DirectionUplink {
			s.PktDir[i] = 1
		} else {
			s.PktDir[i] = -1
		}
		if i > 0 {
			d := pkts[i].Timestamp.Sub(pkts[i-1].Timestamp).Seconds()
			if d < 0 {
				d = 0
			}
			s.PktIAT[i] = d
		}
	}

	s.ActualPayloadPktCount = len(payloadPkts)
	for i := 0; i < 10 && i < len(payloadPkts); i++ {
		s.PayloadPktSize[i] = payloadPkts[i].PayloadLen
		if payloadPkts[i].Direction == model.DirectionUplink {
			s.PayloadPktDir[i] = 1
		} else {
			s.PayloadPktDir[i] = -1
		}
		if i > 0 {
			d := payloadPkts[i].Timestamp.Sub(payloadPkts[i-1].Timestamp).Seconds()
			if d < 0 {
				d = 0
			}
			s.PayloadPktIAT[i] = d
		}
	}
	return s
}

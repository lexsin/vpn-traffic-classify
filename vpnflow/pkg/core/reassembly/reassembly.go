package reassembly

import (
	"bytes"
	"net"
	"sort"
	"time"

	"vpnflow/pkg/model"
	"vpnflow/pkg/tlsparse"
)

// maxInvalidRecords 是容忍的非法 ContentType Record 上限。
// 超过此阈值，认为该流不是 TLS（如 Shadowsocks / VMess-raw），停止 TLS 解析以省性能。
// 注意：与 ETF/llm-traffic 不同，这里只停止 TLS 解析，不丢弃流本身——
// 非协议流量仍保留 Packets/统计/字节流，供流级特征使用。
const maxInvalidRecords = 3

// flowState 是单条 TCP 流的内部状态。
type flowState struct {
	flow                model.Flow
	clientSegments      []tcpSegment
	serverSegments      []tcpSegment
	firstPacketTime     time.Time
	lastPacketTime      time.Time
	handshakeSynSeen    bool
	handshakeSynSeq     uint32
	handshakeSynAckSeen bool
	handshakeSynAckSeq  uint32
}

type tcpSegment struct {
	seq     uint32
	payload []byte
	ts      time.Time
}

type assembledStream struct {
	data   []byte
	chunks []assembledChunk
}

type assembledChunk struct {
	start int
	end   int
	ts    time.Time
}

// Reassembler 维护所有活跃 TCP 流的状态。
//
// 与 ETF/llm-traffic 版本的区别：
//   - 不判 isNonTLS、不丢弃流。所有 TCP 流都保留，非协议流量（SS/VMess-raw）的 Records 为空。
//   - 累积 []PacketInfo 供流级特征（包大小分布/IAT/TCP flags）使用。
//   - TLS 提取（Records/SNI/Version/JA3/AppDataLens）在重组时顺带完成，record 带准确包时间戳，
//     供 innertls.Detect 计算 inner_offset_value。
type Reassembler struct {
	flows map[string]*flowState
}

func New() *Reassembler {
	return &Reassembler{flows: make(map[string]*flowState)}
}

// Feed 处理单个包：累积包元数据 + 统计 + 按方向收集 TCP 段。
func (r *Reassembler) Feed(pkt model.Packet) {
	key := model.ComputeFlowKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)

	fs, ok := r.flows[key]
	if !ok {
		fs = newFlowState(pkt, key)
		r.flows[key] = fs
	}

	dir := directionOf(pkt, &fs.flow)
	fs.observeTCPHandshake(pkt, dir)

	// 累积包元数据（含纯 ACK）
	fs.flow.Packets = append(fs.flow.Packets, model.PacketInfo{
		Timestamp:  pkt.Timestamp,
		Direction:  dir,
		IPLen:      pkt.IPLen,
		PayloadLen: pkt.PayloadLen,
		TCPFlags:   pkt.TCPFlags,
	})

	// 基础统计
	fs.flow.TotalPackets++
	if dir == model.DirectionUplink {
		fs.flow.UplinkPackets++
		fs.flow.UplinkPayloadBytes += pkt.PayloadLen
	} else {
		fs.flow.DownlinkPackets++
		fs.flow.DownlinkPayloadBytes += pkt.PayloadLen
	}
	if pkt.Timestamp.Before(fs.firstPacketTime) {
		fs.firstPacketTime = pkt.Timestamp
	}
	fs.lastPacketTime = pkt.Timestamp

	// 收集 payload 段，Flush 阶段按 TCP SEQ 排序、去重、裁剪重叠后再重组字节流。
	if pkt.PayloadLen == 0 {
		return
	}
	if dir == model.DirectionUplink {
		fs.clientSegments = append(fs.clientSegments, tcpSegment{
			seq:     pkt.TCPSeq,
			payload: append([]byte(nil), pkt.Payload...),
			ts:      pkt.Timestamp,
		})
	} else {
		fs.serverSegments = append(fs.serverSegments, tcpSegment{
			seq:     pkt.TCPSeq,
			payload: append([]byte(nil), pkt.Payload...),
			ts:      pkt.Timestamp,
		})
	}
}

// observeTCPHandshake 按方向、出现顺序和 TCP 序号确认一次完整三次握手。
// 抓包中途开始、缺少任一步或确认号不匹配时不会置位完成状态。
func (fs *flowState) observeTCPHandshake(pkt model.Packet, dir int) {
	if fs.flow.TCPHandshakeComplete {
		return
	}
	isSYN := (pkt.TCPFlags & model.TCPFlagSYN) != 0
	isACK := (pkt.TCPFlags & model.TCPFlagACK) != 0

	if dir == model.DirectionUplink && isSYN && !isACK {
		// 相同序号是 SYN 重传，不清除已经观察到的合法 SYN+ACK。
		if !fs.handshakeSynSeen || pkt.TCPSeq != fs.handshakeSynSeq {
			fs.handshakeSynSeen = true
			fs.handshakeSynSeq = pkt.TCPSeq
			fs.handshakeSynAckSeen = false
			fs.handshakeSynAckSeq = 0
		}
		return
	}

	if dir == model.DirectionDownlink && isSYN && isACK {
		if fs.handshakeSynSeen && pkt.TCPAck == fs.handshakeSynSeq+1 {
			fs.handshakeSynAckSeen = true
			fs.handshakeSynAckSeq = pkt.TCPSeq
		}
		return
	}

	if dir == model.DirectionUplink && isACK && !isSYN &&
		fs.handshakeSynSeen && fs.handshakeSynAckSeen &&
		pkt.TCPAck == fs.handshakeSynAckSeq+1 && pkt.TCPSeq == fs.handshakeSynSeq+1 {
		fs.flow.TCPHandshakeComplete = true
	}
}

// FlushAll 返回全部流并清空内部状态。
func (r *Reassembler) FlushAll() []model.Flow {
	result := make([]model.Flow, 0, len(r.flows))
	for _, fs := range r.flows {
		fs.flow.StartTime = fs.firstPacketTime
		fs.flow.EndTime = fs.lastPacketTime
		client := assembleSegments(fs.clientSegments)
		server := assembleSegments(fs.serverSegments)
		fs.flow.ClientStream = client.data
		fs.flow.ServerStream = server.data
		parseTLSRecords(&fs.flow, client, model.DirectionUplink)
		parseTLSRecords(&fs.flow, server, model.DirectionDownlink)
		sortTLSRecords(&fs.flow)
		result = append(result, fs.flow)
	}
	r.flows = make(map[string]*flowState)
	return result
}

func sortTLSRecords(flow *model.Flow) {
	if len(flow.Records) == 0 {
		return
	}
	sort.SliceStable(flow.Records, func(i, j int) bool {
		return flow.Records[i].Timestamp.Before(flow.Records[j].Timestamp)
	})
	flow.AppDataLens = flow.AppDataLens[:0]
	for _, rec := range flow.Records {
		if rec.IsAppData() {
			flow.AppDataLens = append(flow.AppDataLens, int(rec.RecordLength))
		}
	}
}

func assembleSegments(segments []tcpSegment) assembledStream {
	if len(segments) == 0 {
		return assembledStream{}
	}
	sort.SliceStable(segments, func(i, j int) bool {
		if segments[i].seq == segments[j].seq {
			return len(segments[i].payload) > len(segments[j].payload)
		}
		return tcpSeqLess(segments[i].seq, segments[j].seq)
	})

	var out assembledStream
	nextSeq := segments[0].seq
	started := false
	for _, seg := range segments {
		if len(seg.payload) == 0 {
			continue
		}
		if !started {
			out.append(seg.payload, seg.ts)
			nextSeq = seg.seq + uint32(len(seg.payload))
			started = true
			continue
		}
		if tcpSeqLess(nextSeq, seg.seq) {
			// 捕获中有缺口时停止当前连续流，避免把不连续字节拼成伪 TLS record。
			break
		}
		overlap := int(seqDistance(seg.seq, nextSeq))
		if overlap >= len(seg.payload) {
			continue
		}
		payload := seg.payload[overlap:]
		out.append(payload, seg.ts)
		nextSeq += uint32(len(payload))
	}
	return out
}

func (s *assembledStream) append(payload []byte, ts time.Time) {
	start := len(s.data)
	s.data = append(s.data, payload...)
	s.chunks = append(s.chunks, assembledChunk{
		start: start,
		end:   len(s.data),
		ts:    ts,
	})
}

func parseTLSRecords(flow *model.Flow, stream assembledStream, dir int) {
	buf := stream.data
	invalidRecordCount := 0
	clientHelloParsed := flow.ClientHelloSize > 0
	serverHelloParsed := flow.TLSVersion != 0
	for offset := 0; ; {
		if len(buf)-offset < 5 {
			return
		}
		contentType := buf[offset]
		version := uint16(buf[offset+1])<<8 | uint16(buf[offset+2])
		recordLen := uint16(buf[offset+3])<<8 | uint16(buf[offset+4])
		totalLen := 5 + int(recordLen)
		if len(buf)-offset < totalLen {
			return
		}
		if !tlsparse.IsValidContentType(contentType) {
			invalidRecordCount++
			if invalidRecordCount > maxInvalidRecords {
				return
			}
			offset += totalLen
			continue
		}

		rec := model.TLSRecord{
			Timestamp:    stream.timestampAt(offset + totalLen),
			Direction:    dir,
			ContentType:  contentType,
			Version:      version,
			RecordLength: recordLen,
		}
		flow.Records = append(flow.Records, rec)
		if rec.IsAppData() {
			flow.AppDataLens = append(flow.AppDataLens, int(rec.RecordLength))
		}

		if rec.IsHandshake() {
			hsPay := buf[offset+5 : offset+totalLen]
			if dir == model.DirectionUplink && !clientHelloParsed &&
				len(hsPay) > 0 && hsPay[0] == model.TLSHandshakeClientHello {
				sni, sniLen := tlsparse.ParseClientHelloSNIWithValue(hsPay)
				flow.SNIValue = sni
				flow.SNILength = sniLen
				flow.ClientHelloSize = len(hsPay)
				fp := tlsparse.ParseClientHelloFingerprint(hsPay)
				flow.CipherCount = len(fp.CipherSuites)
				flow.ExtensionCount = len(fp.Extensions)
				flow.HasGREASE = fp.HasGREASE
				flow.JA3Hash = fp.JA3
				flow.ExtensionOrderHash = fp.ExtensionOrderHash
				clientHelloParsed = true
			}
			if dir == model.DirectionDownlink && !serverHelloParsed &&
				len(hsPay) > 0 && hsPay[0] == model.TLSHandshakeServerHello {
				if ver := tlsparse.ParseServerHelloVersion(hsPay); ver != 0 {
					flow.TLSVersion = ver
				}
				serverHelloParsed = true
			}
		}
		offset += totalLen
	}
}

func (s assembledStream) timestampAt(endOffset int) time.Time {
	for _, c := range s.chunks {
		if endOffset <= c.end {
			return c.ts
		}
	}
	if len(s.chunks) > 0 {
		return s.chunks[len(s.chunks)-1].ts
	}
	return time.Time{}
}

func newFlowState(pkt model.Packet, key string) *flowState {
	clientIP, clientPort, serverIP, serverPort := determineClientServer(pkt)
	return &flowState{
		flow: model.Flow{
			FlowKey:    key,
			ClientIP:   clientIP,
			ServerIP:   serverIP,
			ClientPort: clientPort,
			ServerPort: serverPort,
			SNILength:  -1,
		},
		firstPacketTime: pkt.Timestamp,
		lastPacketTime:  pkt.Timestamp,
	}
}

func determineClientServer(pkt model.Packet) (clientIP net.IP, clientPort uint16, serverIP net.IP, serverPort uint16) {
	isSYN := (pkt.TCPFlags & model.TCPFlagSYN) != 0
	isACK := (pkt.TCPFlags & model.TCPFlagACK) != 0
	if isSYN && !isACK {
		return pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort
	}
	if isSYN && isACK {
		return pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort
	}
	return pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort
}

func directionOf(pkt model.Packet, flow *model.Flow) int {
	if bytes.Equal(pkt.SrcIP, flow.ClientIP) && pkt.SrcPort == flow.ClientPort {
		return model.DirectionUplink
	}
	return model.DirectionDownlink
}

func tcpSeqLess(a, b uint32) bool {
	return int32(a-b) < 0
}

func seqDistance(from, to uint32) uint32 {
	return to - from
}

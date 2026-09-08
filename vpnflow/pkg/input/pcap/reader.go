package pcap

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gopcap "github.com/google/gopacket/pcap"

	"vpnflow/pkg/model"
)

// ReadPackets 打开 PCAP/PCAPNG，按捕获顺序返回 TCP、UDP 和 GRE 报文。
// 标准协议规则分支需要观察短流和非 TCP 报文，因此不能在 reader 层做 typical-flow 过滤。
func ReadPackets(path string) ([]model.Packet, error) {
	handle, err := gopcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	var packets []model.Packet
	for pkt := range packetSource.Packets() {
		base, ok := packetBase(pkt)
		if !ok {
			continue
		}

		switch {
		case pkt.Layer(layers.LayerTypeTCP) != nil:
			tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			base.Protocol = model.ProtoTCP
			base.SrcPort = uint16(tcp.SrcPort)
			base.DstPort = uint16(tcp.DstPort)
			base.TCPSeq = tcp.Seq
			base.TCPAck = tcp.Ack
			base.TCPFlags = tcpFlags(tcp)
			base.Payload = cloneBytes(tcp.Payload)
		case pkt.Layer(layers.LayerTypeUDP) != nil:
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			base.Protocol = model.ProtoUDP
			base.SrcPort = uint16(udp.SrcPort)
			base.DstPort = uint16(udp.DstPort)
			base.Payload = cloneBytes(udp.Payload)
		case pkt.Layer(layers.LayerTypeGRE) != nil:
			gre := pkt.Layer(layers.LayerTypeGRE).(*layers.GRE)
			base.Protocol = model.ProtoGRE
			base.Payload = cloneBytes(gre.Payload)
			fillGREMeta(&base, gre)
		default:
			continue
		}

		base.PayloadLen = len(base.Payload)
		packets = append(packets, base)
	}
	return packets, nil
}

func packetBase(pkt gopacket.Packet) (model.Packet, bool) {
	networkLayer := pkt.NetworkLayer()
	if networkLayer == nil {
		return model.Packet{}, false
	}
	srcIP := cloneIP(networkLayer.NetworkFlow().Src().Raw())
	dstIP := cloneIP(networkLayer.NetworkFlow().Dst().Raw())
	if len(srcIP) == 0 || len(dstIP) == 0 {
		return model.Packet{}, false
	}

	ipLen := 0
	if l, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		ipLen = int(l.Length)
	} else if l, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		// IPv6 Length excludes the fixed 40-byte IPv6 header.
		ipLen = int(l.Length) + 40
	}
	if ipLen == 0 {
		ipLen = pkt.Metadata().CaptureInfo.CaptureLength
	}

	return model.Packet{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		IPLen:     ipLen,
	}, true
}

func fillGREMeta(pkt *model.Packet, gre *layers.GRE) {
	pkt.GREProtocol = uint16(gre.Protocol)
	pkt.GREVersion = gre.Version
	pkt.GRESeqPresent = gre.SeqPresent
	pkt.GREAckPresent = gre.AckPresent
	pkt.GRESeq = gre.Seq
	pkt.GREAck = gre.Ack

	// PPTP Enhanced GRE 把 Payload Length 和 Call ID 放在基础头后的 4 字节。
	// gopacket 将这 4 字节解释为 Key，因此从原始头直接读取更清晰。
	raw := gre.LayerContents()
	if len(raw) >= 8 {
		pkt.GREPayloadLength = binary.BigEndian.Uint16(raw[4:6])
		pkt.GRECallID = binary.BigEndian.Uint16(raw[6:8])
	}
}

func tcpFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.SYN {
		flags |= model.TCPFlagSYN
	}
	if tcp.ACK {
		flags |= model.TCPFlagACK
	}
	if tcp.FIN {
		flags |= model.TCPFlagFIN
	}
	if tcp.RST {
		flags |= model.TCPFlagRST
	}
	if tcp.PSH {
		flags |= model.TCPFlagPSH
	}
	return flags
}

func cloneIP(raw []byte) net.IP {
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return nil
	}
	ip := make(net.IP, len(raw))
	copy(ip, raw)
	return ip
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

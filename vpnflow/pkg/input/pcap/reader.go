package pcap

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	gopcap "github.com/google/gopacket/pcap"

	"vpnflow/pkg/model"
)

// ReadPackets 打开 PCAP 文件并返回所有 TCP 包。
// 非 TCP 包（UDP、ICMP 等）静默跳过。
// 返回按 PCAP 存储顺序排列的包列表（通常为时间顺序）。
//
// MVP 阶段只处理 TCP；UDP 流（WireGuard/Hysteria 等）后续由签名引擎处理，不在此读取。
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
		networkLayer := pkt.NetworkLayer()
		if networkLayer == nil {
			continue
		}
		transportLayer := pkt.TransportLayer()
		if transportLayer == nil {
			continue
		}
		tcp, ok := transportLayer.(*layers.TCP)
		if !ok {
			continue
		}

		srcIP := make(net.IP, len(networkLayer.NetworkFlow().Src().Raw()))
		copy(srcIP, networkLayer.NetworkFlow().Src().Raw())
		dstIP := make(net.IP, len(networkLayer.NetworkFlow().Dst().Raw()))
		copy(dstIP, networkLayer.NetworkFlow().Dst().Raw())

		payload := make([]byte, len(tcp.Payload))
		copy(payload, tcp.Payload)

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

		// IPLen：IP 层总字节数，用于包大小分布特征（ratio_small_100 / is_bimodal 等）。
		// 优先取 gopacket 解析的 IP 层 Length；解析失败时退化为 capture 长度。
		ipLen := 0
		if l, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			ipLen = int(l.Length)
		} else if l, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			ipLen = int(l.Length)
		}
		if ipLen == 0 {
			ipLen = pkt.Metadata().CaptureInfo.CaptureLength
		}

		packets = append(packets, model.Packet{
			Timestamp:  pkt.Metadata().Timestamp,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			SrcPort:    uint16(tcp.SrcPort),
			DstPort:    uint16(tcp.DstPort),
			TCPSeq:     tcp.Seq,
			TCPAck:     tcp.Ack,
			TCPFlags:   flags,
			Payload:    payload,
			PayloadLen: len(tcp.Payload),
			IPLen:      ipLen,
		})
	}

	return packets, nil
}

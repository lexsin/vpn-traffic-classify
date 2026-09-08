package protosig

import (
	"encoding/binary"

	"vpnflow/pkg/model"
)

type wireGuardMessage struct {
	messageType uint8
	sender      uint32
	receiver    uint32
}

func (e *Engine) observeWireGuard(pkt model.Packet, fs *flowState, dir model.FlowDirection) {
	if !pkt.IsUDP() {
		return
	}
	msg, ok := parseWireGuard(pkt.Payload)
	if !ok {
		return
	}
	s := e.session("wireguard", fs.key.String(), pkt, fs)
	s.wg.directions[directionIndex(dir)] = true
	s.addEvidence("wireguard_reserved_zero", "wireguard_length_valid")
	switch msg.messageType {
	case 1:
		s.wg.initSenders[msg.sender] = struct{}{}
		s.setRoles(pkt.SrcIP, pkt.DstIP)
		s.addEvidence("wireguard_handshake_initiation")
	case 2:
		s.wg.respSenders[msg.sender] = struct{}{}
		if _, ok := s.wg.initSenders[msg.receiver]; ok {
			s.wg.handshakePair = true
			s.addEvidence("wireguard_handshake_index_match")
		}
		s.addEvidence("wireguard_handshake_response")
	case 3:
		s.addEvidence("wireguard_cookie_reply")
	case 4:
		if _, ok := s.wg.initSenders[msg.receiver]; ok {
			s.wg.matchedData = true
			s.addEvidence("wireguard_transport_index_match")
		}
		if _, ok := s.wg.respSenders[msg.receiver]; ok {
			s.wg.matchedData = true
			s.addEvidence("wireguard_transport_index_match")
		}
		s.addEvidence("wireguard_transport_data")
	}
}

func parseWireGuard(payload []byte) (wireGuardMessage, bool) {
	if len(payload) < 8 || payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
		return wireGuardMessage{}, false
	}
	msg := wireGuardMessage{messageType: payload[0]}
	switch msg.messageType {
	case 1:
		if len(payload) != 148 {
			return wireGuardMessage{}, false
		}
		msg.sender = binary.LittleEndian.Uint32(payload[4:8])
	case 2:
		if len(payload) != 92 {
			return wireGuardMessage{}, false
		}
		msg.sender = binary.LittleEndian.Uint32(payload[4:8])
		msg.receiver = binary.LittleEndian.Uint32(payload[8:12])
	case 3:
		if len(payload) != 64 {
			return wireGuardMessage{}, false
		}
		msg.receiver = binary.LittleEndian.Uint32(payload[4:8])
	case 4:
		// 16-byte header + Poly1305 tag；密文按 16-byte 块对齐。
		if len(payload) < 32 || len(payload)%16 != 0 {
			return wireGuardMessage{}, false
		}
		msg.receiver = binary.LittleEndian.Uint32(payload[4:8])
	default:
		return wireGuardMessage{}, false
	}
	return msg, true
}

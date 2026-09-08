package protosig

import (
	"encoding/binary"
	"fmt"

	"vpnflow/pkg/model"
)

const maxOpenVPNFrame = 32768

func (e *Engine) observeOpenVPN(pkt model.Packet, fs *flowState, dir model.FlowDirection) {
	switch {
	case pkt.IsUDP():
		opcode, kind, sessionID, ok := parseOpenVPNMessage(pkt.Payload)
		if !ok {
			return
		}
		e.recordOpenVPN(pkt, fs, dir, opcode, kind, sessionID)
	case pkt.IsTCP():
		d := directionIndex(dir)
		stream := fs.streams[d]
		offset := fs.openVPNParsed[d]
		for {
			if len(stream)-offset < 2 {
				return
			}
			frameLen := int(binary.BigEndian.Uint16(stream[offset : offset+2]))
			if frameLen <= 0 || frameLen > maxOpenVPNFrame {
				// 首个长度前缀不合法，该方向不再按 OpenVPN/TCP 解析。
				fs.openVPNParsed[d] = len(stream)
				return
			}
			if len(stream)-offset-2 < frameLen {
				return
			}
			frame := stream[offset+2 : offset+2+frameLen]
			opcode, kind, sessionID, ok := parseOpenVPNMessage(frame)
			offset += 2 + frameLen
			fs.openVPNParsed[d] = offset
			if ok {
				e.recordOpenVPN(pkt, fs, dir, opcode, kind, sessionID)
			}
		}
	}
}

func parseOpenVPNMessage(payload []byte) (opcode uint8, kind, sessionID string, ok bool) {
	if len(payload) < 1 {
		return 0, "", "", false
	}
	opcode = payload[0] >> 3
	switch opcode {
	case 1, 2, 3, 4, 5, 7, 8, 10:
		// 控制类报文包含至少 8-byte session-id，再加 opcode/key-id。
		if len(payload) < 9 {
			return 0, "", "", false
		}
		sessionID = string(payload[1:9])
		if sessionID == "\x00\x00\x00\x00\x00\x00\x00\x00" {
			return 0, "", "", false
		}
		return opcode, "control", sessionID, true
	case 6, 9, 11:
		if len(payload) < 5 {
			return 0, "", "", false
		}
		return opcode, "data", "", true
	default:
		return 0, "", "", false
	}
}

func (e *Engine) recordOpenVPN(
	pkt model.Packet,
	fs *flowState,
	dir model.FlowDirection,
	opcode uint8,
	kind string,
	sessionID string,
) {
	s := e.session("openvpn", fs.key.String(), pkt, fs)
	s.inferTCPRoles(pkt)
	if s.client == "" && (opcode == 1 || opcode == 7 || opcode == 10) {
		s.setRoles(pkt.SrcIP, pkt.DstIP)
	}
	s.openvpn.validPackets++
	d := directionIndex(dir)
	s.openvpn.directions[d] = true
	s.addEvidence("openvpn_valid_opcode", fmt.Sprintf("openvpn_opcode_%d", opcode))
	switch opcode {
	case 1, 7, 10:
		s.openvpn.clientReset = true
		s.openvpn.clientResetDir = uint8(d + 1)
		s.setRoles(pkt.SrcIP, pkt.DstIP)
		s.addEvidence("openvpn_client_hard_reset")
	case 2, 8:
		s.openvpn.serverReset = true
		s.openvpn.serverResetDir = uint8(d + 1)
		s.addEvidence("openvpn_server_hard_reset")
	}
	if kind == "control" {
		s.openvpn.control++
		if s.openvpn.controlSessionID[d] == "" {
			s.openvpn.controlSessionID[d] = sessionID
			s.openvpn.consistentControl[d] = 1
		} else if s.openvpn.controlSessionID[d] == sessionID {
			s.openvpn.consistentControl[d]++
			s.addEvidence("openvpn_session_id_consistent")
		}
		s.addEvidence("openvpn_control_structure")
	} else {
		s.openvpn.data++
		s.addEvidence("openvpn_data_structure")
	}
}

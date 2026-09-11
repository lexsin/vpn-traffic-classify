package protosig

import (
	"encoding/binary"
	"fmt"

	"vpnflow/pkg/model"
)

const (
	l2tpFlagType     = 0x8000
	l2tpFlagLength   = 0x4000
	l2tpFlagSequence = 0x0800
	l2tpFlagOffset   = 0x0200
	l2tpFlagPriority = 0x0100
	// RFC 2661：T/L/S/O/P/Ver 之外的比特必须为 0。
	l2tpReservedBits = 0x34F0
)

type l2tpMessage struct {
	control     bool
	tunnelID    uint16
	sessionID   uint16
	messageType uint16
}

func (e *Engine) observeL2TP(pkt model.Packet, fs *flowState, dir model.FlowDirection) {
	if !pkt.IsUDP() {
		return
	}
	msg, ok := parseL2TPv2(pkt.Payload)
	if !ok {
		return
	}
	var s *sessionState
	if msg.control {
		s = e.session("l2tpv2", fs.key.String(), pkt, fs)
	} else {
		s = e.lookupSession("l2tpv2", fs.key.String())
		if s == nil {
			return
		}
		e.touchSession(s, pkt, fs.key.String())
	}
	s.l2tp.directions[directionIndex(dir)] = true
	s.l2tp.tunnelIDs[msg.tunnelID] = struct{}{}
	if msg.sessionID != 0 {
		s.l2tp.sessionIDs[msg.sessionID] = struct{}{}
	}
	s.addEvidence("l2tpv2_header_valid")
	if msg.control {
		s.l2tp.controlPackets++
		s.addEvidence("l2tpv2_control_avp_valid")
		if msg.messageType != 0 {
			s.addEvidence(fmt.Sprintf("l2tpv2_message_type_%d", msg.messageType))
			if msg.messageType == 1 {
				s.setRoles(pkt.SrcIP, pkt.DstIP)
			}
		}
	} else {
		s.l2tp.dataPackets++
		s.addEvidence("l2tpv2_data_header_valid")
	}
}

func parseL2TPv2(payload []byte) (l2tpMessage, bool) {
	if len(payload) < 6 {
		return l2tpMessage{}, false
	}
	flagsVersion := binary.BigEndian.Uint16(payload[0:2])
	if flagsVersion&0x000f != 2 {
		return l2tpMessage{}, false
	}
	if flagsVersion&l2tpReservedBits != 0 {
		return l2tpMessage{}, false
	}
	control := flagsVersion&l2tpFlagType != 0
	if control &&
		(flagsVersion&l2tpFlagLength == 0 ||
			flagsVersion&l2tpFlagSequence == 0 ||
			flagsVersion&l2tpFlagOffset != 0 ||
			flagsVersion&l2tpFlagPriority != 0) {
		// RFC 2661：控制消息必须 T=1, L=1, S=1, O=0, P=0。
		return l2tpMessage{}, false
	}
	pos := 2
	end := len(payload)
	if flagsVersion&l2tpFlagLength != 0 {
		if len(payload) < pos+2 {
			return l2tpMessage{}, false
		}
		declared := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		if declared != len(payload) || declared < pos+4 {
			return l2tpMessage{}, false
		}
		end = declared
	}
	if end < pos+4 {
		return l2tpMessage{}, false
	}
	msg := l2tpMessage{
		control:   control,
		tunnelID:  binary.BigEndian.Uint16(payload[pos : pos+2]),
		sessionID: binary.BigEndian.Uint16(payload[pos+2 : pos+4]),
	}
	pos += 4
	if flagsVersion&l2tpFlagSequence != 0 {
		if end < pos+4 {
			return l2tpMessage{}, false
		}
		pos += 4 // Ns, Nr
	}
	if flagsVersion&l2tpFlagOffset != 0 {
		if end < pos+2 {
			return l2tpMessage{}, false
		}
		offsetSize := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		if offsetSize > end-pos {
			return l2tpMessage{}, false
		}
		pos += offsetSize
	}
	if !control {
		if msg.tunnelID == 0 || msg.sessionID == 0 {
			return l2tpMessage{}, false
		}
		return msg, true
	}
	if msg.sessionID != 0 {
		return l2tpMessage{}, false
	}
	messageType, ok := parseL2TPAVPs(payload[pos:end])
	if !ok {
		return l2tpMessage{}, false
	}
	msg.messageType = messageType
	return msg, true
}

func parseL2TPAVPs(data []byte) (uint16, bool) {
	if len(data) == 0 {
		// ZLB control acknowledgement: structurally valid but has no message AVP.
		return 0, true
	}
	var messageType uint16
	for pos := 0; pos < len(data); {
		if len(data)-pos < 6 {
			return 0, false
		}
		flagsLen := binary.BigEndian.Uint16(data[pos : pos+2])
		length := int(flagsLen & 0x03ff)
		if length < 6 || length > len(data)-pos {
			return 0, false
		}
		vendorID := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		attrType := binary.BigEndian.Uint16(data[pos+4 : pos+6])
		if vendorID == 0 && attrType == 0 {
			if length < 8 {
				return 0, false
			}
			messageType = binary.BigEndian.Uint16(data[pos+6 : pos+8])
		}
		pos += length
	}
	return messageType, true
}

package protosig

import (
	"encoding/binary"
	"fmt"

	"vpnflow/pkg/model"
)

const (
	pptpMagicCookie = 0x1A2B3C4D
	pptpGREProtocol = 0x880B
	maxPPTPControl  = 4096

	pptpStartControlRequest = 1
	pptpStartControlReply   = 2
	pptpOutgoingCallRequest = 7
	pptpOutgoingCallReply   = 8
	pptpIncomingCallRequest = 9
)

func (e *Engine) observePPTP(pkt model.Packet, fs *flowState, dir model.FlowDirection) {
	if pkt.IsGRE() {
		e.observePPTPGRE(pkt, fs)
		return
	}
	if !pkt.IsTCP() {
		return
	}
	d := directionIndex(dir)
	stream := fs.streams[d]
	offset := fs.pptpParsed[d]
	for {
		if len(stream)-offset < 12 {
			return
		}
		length := int(binary.BigEndian.Uint16(stream[offset : offset+2]))
		if length < 12 || length > maxPPTPControl {
			fs.pptpParsed[d] = len(stream)
			return
		}
		if len(stream)-offset < length {
			return
		}
		frame := stream[offset : offset+length]
		offset += length
		fs.pptpParsed[d] = offset
		controlType, callIDs, ok := parsePPTPControl(frame)
		if !ok {
			continue
		}
		s := e.session("pptp", model.IPPairKey(pkt.SrcIP, pkt.DstIP), pkt, fs)
		s.inferTCPRoles(pkt)
		if s.client == "" &&
			(controlType == pptpStartControlRequest ||
				controlType == pptpOutgoingCallRequest ||
				controlType == pptpIncomingCallRequest) {
			s.setRoles(pkt.SrcIP, pkt.DstIP)
		}
		s.pptp.controlPackets++
		s.addEvidence(
			"pptp_control_magic_cookie",
			fmt.Sprintf("pptp_control_type_%d", controlType),
		)
		dirMark := uint8(directionIndex(dir) + 1)
		switch controlType {
		case pptpStartControlRequest:
			s.pptp.sccRequest = true
			s.pptp.sccRequestDir = dirMark
		case pptpStartControlReply:
			s.pptp.sccReply = true
			s.pptp.sccReplyDir = dirMark
		case pptpOutgoingCallRequest:
			s.pptp.outCallRequest = true
			s.pptp.outCallRequestDir = dirMark
		case pptpOutgoingCallReply:
			s.pptp.outCallReply = true
			s.pptp.outCallReplyDir = dirMark
		}
		if s.pptp.sccHandshake() {
			s.addEvidence("pptp_scc_handshake")
		}
		if s.pptp.outgoingCallHandshake() {
			s.addEvidence("pptp_outgoing_call_handshake")
		}
		for _, callID := range callIDs {
			s.pptp.callIDs[callID] = struct{}{}
		}
		refreshPPTPMatch(s)
	}
}

func parsePPTPControl(frame []byte) (controlType uint16, callIDs []uint16, ok bool) {
	if len(frame) < 12 {
		return 0, nil, false
	}
	length := int(binary.BigEndian.Uint16(frame[0:2]))
	if length != len(frame) ||
		binary.BigEndian.Uint16(frame[2:4]) != 1 ||
		binary.BigEndian.Uint32(frame[4:8]) != pptpMagicCookie {
		return 0, nil, false
	}
	if binary.BigEndian.Uint16(frame[10:12]) != 0 {
		return 0, nil, false
	}
	controlType = binary.BigEndian.Uint16(frame[8:10])
	if controlType < 1 || controlType > 15 {
		return 0, nil, false
	}
	if controlType >= 7 && controlType <= 13 && len(frame) >= 14 {
		if id := binary.BigEndian.Uint16(frame[12:14]); id != 0 {
			callIDs = append(callIDs, id)
		}
	}
	if (controlType == 8 || controlType == 10) && len(frame) >= 16 {
		if id := binary.BigEndian.Uint16(frame[14:16]); id != 0 {
			callIDs = append(callIDs, id)
		}
	}
	return controlType, callIDs, true
}

func (e *Engine) observePPTPGRE(pkt model.Packet, fs *flowState) {
	if pkt.GREProtocol != pptpGREProtocol ||
		pkt.GREVersion != 1 ||
		pkt.GRECallID == 0 ||
		int(pkt.GREPayloadLength) != len(pkt.Payload) {
		return
	}
	s := e.session("pptp", model.IPPairKey(pkt.SrcIP, pkt.DstIP), pkt, fs)
	s.pptp.greCallIDs[pkt.GRECallID] = struct{}{}
	s.addEvidence("pptp_enhanced_gre", "pptp_gre_call_id")
	refreshPPTPMatch(s)
}

func refreshPPTPMatch(s *sessionState) {
	for callID := range s.pptp.callIDs {
		if _, ok := s.pptp.greCallIDs[callID]; ok {
			s.pptp.matchedGRE = true
			s.addEvidence("gre_call_id_match")
			return
		}
	}
}

func (p pptpSession) sccHandshake() bool {
	return p.sccRequest && p.sccReply && p.sccRequestDir != 0 && p.sccRequestDir != p.sccReplyDir
}

func (p pptpSession) outgoingCallHandshake() bool {
	return p.outCallRequest && p.outCallReply && p.outCallRequestDir != 0 && p.outCallRequestDir != p.outCallReplyDir
}

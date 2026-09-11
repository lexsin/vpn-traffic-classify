package protosig

import (
	"container/heap"
	"fmt"
	"net"
	"sort"
	"time"

	"vpnflow/pkg/model"
)

const (
	defaultIdleTimeout   = 120 * time.Second
	defaultMaxPrefixSize = 64 * 1024
)

type Config struct {
	SourceFile     string
	IdleTimeout    time.Duration
	MaxPrefixBytes int
}

// Engine 维护包级 FlowState、协议 SessionState 和过期索引。
// 当前 CLI 单线程调用 Observe；后续并行化时同一分片必须由单 owner 修改。
type Engine struct {
	cfg Config

	flows    map[model.FlowKey]*flowState
	sessions map[string]*sessionState
	active   map[string]string

	flowExpiry    flowExpiryHeap
	sessionExpiry sessionExpiryHeap
	nextSessionID uint64
}

type flowState struct {
	key        model.FlowKey
	firstSeen  time.Time
	lastSeen   time.Time
	generation uint64
	packets    [2]int
	bytes      [2]int
	streams    [2][]byte

	openVPNParsed [2]int
	pptpParsed    [2]int
}

type sessionState struct {
	id            string
	indexKey      string
	protocol      string
	sourceFile    string
	firstSeen     time.Time
	lastSeen      time.Time
	generation    uint64
	client        string
	server        string
	flows         map[string]struct{}
	evidence      map[string]struct{}
	wellKnownPort bool

	openvpn openVPNSession
	pptp    pptpSession
	l2tp    l2tpSession
	wg      wireGuardSession
}

type openVPNSession struct {
	validPackets      int
	control           int
	data              int
	directions        [2]bool
	clientReset       bool
	serverReset       bool
	clientResetDir    uint8 // direction index + 1；0 表示未知
	serverResetDir    uint8
	controlSessionID  [2]string
	consistentControl [2]int
}

type pptpSession struct {
	controlPackets    int
	callIDs           map[uint16]struct{}
	greCallIDs        map[uint16]struct{}
	matchedGRE        bool
	sccRequest        bool
	sccReply          bool
	sccRequestDir     uint8 // direction index + 1；0 表示未知
	sccReplyDir       uint8
	outCallRequest    bool
	outCallReply      bool
	outCallRequestDir uint8
	outCallReplyDir   uint8
}

type l2tpSession struct {
	controlPackets int
	dataPackets    int
	tunnelIDs      map[uint16]struct{}
	sessionIDs     map[uint16]struct{}
	directions     [2]bool
}

type wireGuardSession struct {
	initSenders   map[uint32]struct{}
	respSenders   map[uint32]struct{}
	handshakePair bool
	matchedData   bool
	directions    [2]bool
}

func New(cfg Config) *Engine {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.MaxPrefixBytes <= 0 {
		cfg.MaxPrefixBytes = defaultMaxPrefixSize
	}
	e := &Engine{
		cfg:      cfg,
		flows:    make(map[model.FlowKey]*flowState),
		sessions: make(map[string]*sessionState),
		active:   make(map[string]string),
	}
	heap.Init(&e.flowExpiry)
	heap.Init(&e.sessionExpiry)
	return e
}

// Observe 处理一个报文，并返回因 idle timeout 完结的会话结果。
func (e *Engine) Observe(pkt model.Packet) []model.ProtocolResult {
	results := e.expire(pkt.Timestamp)
	key, dir := pkt.CanonicalKey()
	fs := e.flows[key]
	if fs == nil {
		fs = &flowState{key: key, firstSeen: pkt.Timestamp}
		e.flows[key] = fs
	}
	fs.lastSeen = pkt.Timestamp
	fs.generation++
	d := directionIndex(dir)
	fs.packets[d]++
	fs.bytes[d] += pkt.PayloadLen
	if pkt.IsTCP() && len(pkt.Payload) > 0 {
		fs.streams[d] = appendBounded(fs.streams[d], pkt.Payload, e.cfg.MaxPrefixBytes)
	}
	heap.Push(&e.flowExpiry, flowExpiryItem{
		key: key, at: pkt.Timestamp.Add(e.cfg.IdleTimeout), generation: fs.generation,
	})

	e.observeOpenVPN(pkt, fs, dir)
	e.observePPTP(pkt, fs, dir)
	e.observeL2TP(pkt, fs, dir)
	e.observeWireGuard(pkt, fs, dir)
	return results
}

// FlushAll 输出所有仍活跃的候选会话并清空状态。
func (e *Engine) FlushAll() []model.ProtocolResult {
	ids := make([]string, 0, len(e.sessions))
	for id := range e.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	results := make([]model.ProtocolResult, 0, len(ids))
	for _, id := range ids {
		if result, ok := e.finalizeSession(id); ok {
			results = append(results, result)
		}
	}
	e.flows = make(map[model.FlowKey]*flowState)
	e.sessions = make(map[string]*sessionState)
	e.active = make(map[string]string)
	e.flowExpiry = nil
	e.sessionExpiry = nil
	e.nextSessionID = 0
	heap.Init(&e.flowExpiry)
	heap.Init(&e.sessionExpiry)
	return results
}

func (e *Engine) lookupSession(protocol, index string) *sessionState {
	if id := e.active[protocol+"|"+index]; id != "" {
		return e.sessions[id]
	}
	return nil
}

func (e *Engine) session(protocol, index string, pkt model.Packet, fs *flowState) *sessionState {
	if s := e.lookupSession(protocol, index); s != nil {
		e.touchSession(s, pkt, fs.key.String())
		return s
	}
	e.nextSessionID++
	sourceID := e.cfg.SourceFile
	if sourceID == "" {
		sourceID = "stream"
	}
	activeKey := protocol + "|" + index
	id := fmt.Sprintf(
		"%s:%s:%x:%x",
		protocol,
		sourceID,
		pkt.Timestamp.UnixNano(),
		e.nextSessionID,
	)
	s := &sessionState{
		id:         id,
		indexKey:   activeKey,
		protocol:   protocol,
		sourceFile: e.cfg.SourceFile,
		firstSeen:  pkt.Timestamp,
		flows:      make(map[string]struct{}),
		evidence:   make(map[string]struct{}),
	}
	s.pptp.callIDs = make(map[uint16]struct{})
	s.pptp.greCallIDs = make(map[uint16]struct{})
	s.l2tp.tunnelIDs = make(map[uint16]struct{})
	s.l2tp.sessionIDs = make(map[uint16]struct{})
	s.wg.initSenders = make(map[uint32]struct{})
	s.wg.respSenders = make(map[uint32]struct{})
	e.sessions[id] = s
	e.active[activeKey] = id
	e.touchSession(s, pkt, fs.key.String())
	return s
}

func (e *Engine) touchSession(s *sessionState, pkt model.Packet, flowKey string) {
	ts := pkt.Timestamp
	if s.firstSeen.IsZero() || ts.Before(s.firstSeen) {
		s.firstSeen = ts
	}
	if ts.After(s.lastSeen) || s.lastSeen.IsZero() {
		s.lastSeen = ts
	}
	s.flows[flowKey] = struct{}{}
	if wellKnownPortMatch(s.protocol, pkt) {
		s.wellKnownPort = true
	}
	s.generation++
	heap.Push(&e.sessionExpiry, sessionExpiryItem{
		id: s.id, at: ts.Add(e.cfg.IdleTimeout), generation: s.generation,
	})
}

func wellKnownPortMatch(protocol string, pkt model.Packet) bool {
	switch protocol {
	case "pptp":
		return pkt.IsTCP() && (pkt.SrcPort == 1723 || pkt.DstPort == 1723)
	case "l2tpv2":
		return pkt.IsUDP() && (pkt.SrcPort == 1701 || pkt.DstPort == 1701)
	case "openvpn":
		return (pkt.IsTCP() || pkt.IsUDP()) && (pkt.SrcPort == 1194 || pkt.DstPort == 1194)
	case "wireguard":
		return pkt.IsUDP() && (pkt.SrcPort == 51820 || pkt.DstPort == 51820)
	default:
		return false
	}
}

func (s *sessionState) addEvidence(values ...string) {
	for _, value := range values {
		if value != "" {
			s.evidence[value] = struct{}{}
		}
	}
}

func (s *sessionState) inferTCPRoles(pkt model.Packet) {
	if s.client != "" || !pkt.IsTCP() {
		return
	}
	syn := pkt.TCPFlags&model.TCPFlagSYN != 0
	ack := pkt.TCPFlags&model.TCPFlagACK != 0
	switch {
	case syn && !ack:
		s.client, s.server = endpointIP(pkt.SrcIP), endpointIP(pkt.DstIP)
	case syn && ack:
		s.client, s.server = endpointIP(pkt.DstIP), endpointIP(pkt.SrcIP)
	}
}

func (s *sessionState) setRoles(client, server net.IP) {
	if s.client == "" {
		s.client, s.server = endpointIP(client), endpointIP(server)
	}
}

func (e *Engine) expire(now time.Time) []model.ProtocolResult {
	for e.flowExpiry.Len() > 0 {
		item := e.flowExpiry[0]
		if item.at.After(now) {
			break
		}
		heap.Pop(&e.flowExpiry)
		if fs := e.flows[item.key]; fs != nil && fs.generation == item.generation {
			delete(e.flows, item.key)
		}
	}

	var results []model.ProtocolResult
	for e.sessionExpiry.Len() > 0 {
		item := e.sessionExpiry[0]
		if item.at.After(now) {
			break
		}
		heap.Pop(&e.sessionExpiry)
		s := e.sessions[item.id]
		if s == nil || s.generation != item.generation {
			continue
		}
		if result, ok := e.finalizeSession(item.id); ok {
			results = append(results, result)
		}
	}
	return results
}

func (e *Engine) finalizeSession(id string) (model.ProtocolResult, bool) {
	s := e.sessions[id]
	if s == nil {
		return model.ProtocolResult{}, false
	}
	delete(e.sessions, id)
	if e.active[s.indexKey] == id {
		delete(e.active, s.indexKey)
	}
	if len(s.evidence) == 0 {
		return model.ProtocolResult{}, false
	}
	// 仅数据面头看起来像 L2TPv2 不足以输出会话，避免 HY2/随机 UDP 误报。
	if s.protocol == "l2tpv2" && s.l2tp.controlPackets == 0 {
		return model.ProtocolResult{}, false
	}
	confirmed := s.confirmed()
	if s.wellKnownPort {
		s.addEvidence("well_known_port")
		// 已有 payload 证据的 suspected，命中标准端口则升为 confirmed。
		confirmed = true
	}
	verdict := model.VerdictSuspected
	confidence := 0.60
	if confirmed {
		verdict = model.VerdictConfirmed
		confidence = 0.99
	}
	flows := setKeys(s.flows)
	evidence := setKeys(s.evidence)
	return model.ProtocolResult{
		SourceFile: s.sourceFile,
		SessionID:  s.id,
		Protocol:   s.protocol,
		Verdict:    verdict,
		Confidence: confidence,
		FirstSeen:  s.firstSeen,
		LastSeen:   s.lastSeen,
		Client:     s.client,
		Server:     s.server,
		Flows:      flows,
		Evidence:   evidence,
	}, true
}

func (s *sessionState) confirmed() bool {
	switch s.protocol {
	case "openvpn":
		// 高精度门槛：必须观察到同一会话的客户端和服务端 Hard Reset。
		// 仅数据包或普通 control/ack 只能作为 suspected，防止随机密文误报。
		return s.openvpn.validPackets >= 2 &&
			s.openvpn.clientReset &&
			s.openvpn.serverReset &&
			s.openvpn.clientResetDir != s.openvpn.serverResetDir &&
			(s.openvpn.consistentControl[0] >= 2 ||
				s.openvpn.consistentControl[1] >= 2)
	case "pptp":
		// 控制面双关即可确认；GRE Call-ID 匹配是更强证据，但不再作为必要条件。
		return s.pptp.matchedGRE || s.pptp.sccHandshake() || s.pptp.outgoingCallHandshake()
	case "l2tpv2":
		return s.l2tp.controlPackets >= 2 ||
			(s.l2tp.controlPackets >= 1 && s.l2tp.dataPackets >= 1)
	case "wireguard":
		return s.wg.handshakePair || s.wg.matchedData
	default:
		return false
	}
}

func directionIndex(dir model.FlowDirection) int {
	if dir == model.BToA {
		return 1
	}
	return 0
}

func appendBounded(dst, src []byte, max int) []byte {
	if len(dst) >= max || len(src) == 0 {
		return dst
	}
	n := max - len(dst)
	if len(src) < n {
		n = len(src)
	}
	return append(dst, src[:n]...)
}

func endpointIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func setKeys[T ~string](set map[T]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, string(value))
	}
	sort.Strings(out)
	return out
}

package model

import "time"

type ProtocolVerdict string

const (
	VerdictConfirmed ProtocolVerdict = "confirmed"
	VerdictSuspected ProtocolVerdict = "suspected"
)

// ProtocolResult 是标准协议规则引擎的会话级输出。
type ProtocolResult struct {
	SourceFile string          `json:"source_file,omitempty"`
	SessionID  string          `json:"session_id"`
	Protocol   string          `json:"protocol"`
	Verdict    ProtocolVerdict `json:"verdict"`
	Confidence float64         `json:"confidence"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Client     string          `json:"client,omitempty"`
	Server     string          `json:"server,omitempty"`
	Flows      []string        `json:"flows"`
	Evidence   []string        `json:"evidence"`
}

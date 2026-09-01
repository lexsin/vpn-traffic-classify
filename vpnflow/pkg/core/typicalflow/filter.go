package typicalflow

import (
	"vpnflow/pkg/model"
)

// Filter 典型流过滤参数。MVP 只保留数据传输明显的大流，丢弃小流/纯 ACK/短流。
type Filter struct {
	MinPackets      int     // 最小总包数
	MinDurationSec  float64 // 最小持续时间（秒）
	MinPayloadBytes int     // 最小 payload 总字节数
	MinPayloadPkts  int     // 最小含 payload 的包数
	RequireBidi     bool    // 是否要求双向都有包
}

// Default 返回 MVP 默认阈值（对应计划文档 §8.1）。
func Default() Filter {
	return Filter{
		MinPackets:      30,
		MinDurationSec:  5.0,
		MinPayloadBytes: 2000,
		MinPayloadPkts:  5,
		RequireBidi:     true,
	}
}

// Keep 返回该流是否通过典型流过滤。
func (f Filter) Keep(flow *model.Flow) bool {
	if flow.TotalPackets < f.MinPackets {
		return false
	}
	if flow.Duration() < f.MinDurationSec {
		return false
	}
	if flow.TotalPayloadBytes() < f.MinPayloadBytes {
		return false
	}
	payloadPkts := 0
	for _, p := range flow.Packets {
		if p.PayloadLen > 0 {
			payloadPkts++
		}
	}
	if payloadPkts < f.MinPayloadPkts {
		return false
	}
	if f.RequireBidi && !flow.IsBidirectional() {
		return false
	}
	return true
}

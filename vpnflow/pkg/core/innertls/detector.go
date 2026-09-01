package innertls

import (
	"time"

	"vpnflow/pkg/model"
)

// 检测窗口：内层 TLS ClientHello 被外层封装后的 AppData record 长度典型落在 200~600 字节。
const (
	innerHelloMinSize = 200
	innerHelloMaxSize = 600
)

// Detect 检测外层 TLS 内是否存在内层 TLS 握手（TLS over TLS，Trojan 特征）。
//
// 方法（方案3.md §3.6）：外层 TLS 加密了内层，DPI 无法看到内层握手的明文字节，
// 但内层握手的各消息（ClientHello ~250B / ServerHello ~120B / Certificate ~3KB）
// 被外层封装成特定长度的 AppData record，可通过长度分布 + 时序检测，无需解密。
//
// 返回：
//
//	innerHelloCount   - 外层握手结束后，长度 ∈ [200,600] 的 AppData record 数量
//	innerOffsetValue  - 外层握手结束到首个疑似内层 ClientHello AppData 的时间差（秒）；无则 -1
//	innerOffsetValid  - innerHelloCount > 0 时为 1，否则 0
func Detect(flow *model.Flow) (innerHelloCount int, innerOffsetValue float64, innerOffsetValid int) {
	records := flow.Records
	if len(records) == 0 {
		return 0, -1, 0
	}
	// 定位外层握手结束：最后一个 Handshake record 的 index
	hsEndIdx := -1
	for i := range records {
		if records[i].IsHandshake() {
			hsEndIdx = i
		}
	}
	if hsEndIdx < 0 {
		return 0, -1, 0
	}
	hsEndTime := records[hsEndIdx].Timestamp

	count := 0
	var firstADTs time.Time
	for i := hsEndIdx + 1; i < len(records); i++ {
		r := records[i]
		if r.IsAppData() && r.RecordLength >= innerHelloMinSize && r.RecordLength <= innerHelloMaxSize {
			count++
			if firstADTs.IsZero() {
				firstADTs = r.Timestamp
			}
		}
	}
	if count > 0 && !firstADTs.IsZero() {
		return count, firstADTs.Sub(hsEndTime).Seconds(), 1
	}
	return 0, -1, 0
}

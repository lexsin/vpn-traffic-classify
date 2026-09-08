package features

import "vpnflow/pkg/model"

// postTLSPayloadMinRecords 是 Trojan 后握手序列准入所需的最少 AppData Record 数。
const postTLSPayloadMinRecords = 3

// postTLSPayloadRecords 返回外层 TLS 握手完成后的 AppData Record。
//
// TLS 1.2 的握手 Record 是可见的，因此从 ServerHello 之后首条 AppData 开始。
// TLS 1.3 会把后续握手消息加密为 AppData：被动抓包无法精确区分 Finished 与
// 业务数据，所以保守跳过服务端受保护握手记录和首条客户端受保护记录，再开始
// 取序列。无法满足该边界的流不进入 Trojan 后载荷模型。
func postTLSPayloadRecords(flow *model.Flow) []model.TLSRecord {
	if flow.ClientHelloSize == 0 || flow.TLSVersion == 0 {
		return nil
	}
	serverHello := firstServerHelloIndex(flow.Records)
	if serverHello < 0 {
		return nil
	}
	if flow.TLSVersion != model.TLSVersion13 {
		return appDataRecordsFrom(flow.Records, serverHello+1)
	}

	serverProtected := -1
	for i := serverHello + 1; i < len(flow.Records); i++ {
		rec := flow.Records[i]
		if rec.Direction == model.DirectionDownlink && rec.IsAppData() {
			serverProtected = i
			break
		}
	}
	if serverProtected < 0 {
		return nil
	}

	clientFinished := -1
	for i := serverProtected + 1; i < len(flow.Records); i++ {
		rec := flow.Records[i]
		if rec.Direction == model.DirectionUplink && rec.IsAppData() {
			clientFinished = i
			break
		}
	}
	if clientFinished < 0 {
		return nil
	}
	return appDataRecordsFrom(flow.Records, clientFinished+1)
}

func firstServerHelloIndex(records []model.TLSRecord) int {
	for i, rec := range records {
		if rec.Direction == model.DirectionDownlink &&
			rec.IsHandshake() && rec.HandshakeType == model.TLSHandshakeServerHello {
			return i
		}
	}
	return -1
}

func appDataRecordsFrom(records []model.TLSRecord, start int) []model.TLSRecord {
	out := make([]model.TLSRecord, 0, 10)
	for i := start; i < len(records); i++ {
		if records[i].IsAppData() {
			out = append(out, records[i])
		}
	}
	return out
}

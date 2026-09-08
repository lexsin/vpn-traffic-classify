package model

import "time"

// TLS content_type 常量
const (
	TLSContentTypeChangeCipherSpec uint8 = 0x14
	TLSContentTypeAlert            uint8 = 0x15
	TLSContentTypeHandshake        uint8 = 0x16
	TLSContentTypeAppData          uint8 = 0x17
)

// TLS 握手消息类型常量
const (
	TLSHandshakeClientHello uint8 = 0x01
	TLSHandshakeServerHello uint8 = 0x02
	TLSHandshakeCertificate uint8 = 0x0B
)

// TLS 版本常量
const (
	TLSVersion12 uint16 = 0x0303
	TLSVersion13 uint16 = 0x0304
)

// 方向常量
const (
	DirectionUplink   = 0 // 客户端 → 服务端
	DirectionDownlink = 1 // 服务端 → 客户端
)

// TLSRecord 表示一条完整的 TLS Record 层记录（5 字节明文头解析结果）。
type TLSRecord struct {
	Timestamp    time.Time // 触发该 Record 完成的包的时间戳
	Direction    int       // 0=uplink, 1=downlink
	ContentType  uint8     // TLS Record Header 第 1 字节
	Version      uint16    // TLS Record Header 第 2-3 字节（legacy_version）
	RecordLength uint16    // TLS Record Header 第 4-5 字节（不含 5 字节头）
	// HandshakeType 仅在未加密 Handshake Record 的首个消息可见时填写；
	// 用于定位外层握手阶段，不作为模型特征。
	HandshakeType uint8
}

// IsAppData 判断是否为 ApplicationData Record。
func (r TLSRecord) IsAppData() bool {
	return r.ContentType == TLSContentTypeAppData
}

// IsHandshake 判断是否为 Handshake Record。
func (r TLSRecord) IsHandshake() bool {
	return r.ContentType == TLSContentTypeHandshake
}

package tlsparse

import (
	"time"

	"vpnflow/pkg/model"
)

// IsValidContentType 判断字节是否为合法 TLS content_type。
// 合法范围：0x14（ChangeCipherSpec）、0x15（Alert）、0x16（Handshake）、0x17（AppData）。
func IsValidContentType(b byte) bool {
	return b >= 0x14 && b <= 0x17
}

// ExtractRecordsWithPayload 从缓冲区起始位置连续提取完整 TLS Record。
// 对 content_type=0x16（Handshake）的 Record，额外在 handshakePayloads 中保存其
// payload 切片（共享 buf 底层内存，不拷贝）；其他类型对应位置为 nil。
// 返回：
//
//	records           - 本次提取出的完整 Record 列表
//	handshakePayloads - 与 records 等长，Handshake Record 对应其 payload，其余为 nil
//	consumed          - 缓冲区已消费字节数，调用方执行 buf = buf[consumed:]
func ExtractRecordsWithPayload(buf []byte, ts time.Time, dir int) (
	records []model.TLSRecord,
	handshakePayloads [][]byte,
	consumed int,
) {
	offset := 0
	for {
		if len(buf)-offset < 5 {
			break
		}
		contentType := buf[offset]
		version := uint16(buf[offset+1])<<8 | uint16(buf[offset+2])
		recordLen := uint16(buf[offset+3])<<8 | uint16(buf[offset+4])
		totalLen := 5 + int(recordLen)
		if len(buf)-offset < totalLen {
			break
		}

		rec := model.TLSRecord{
			Timestamp:    ts,
			Direction:    dir,
			ContentType:  contentType,
			Version:      version,
			RecordLength: recordLen,
		}
		records = append(records, rec)

		if contentType == model.TLSContentTypeHandshake {
			handshakePayloads = append(handshakePayloads, buf[offset+5:offset+totalLen])
		} else {
			handshakePayloads = append(handshakePayloads, nil)
		}

		offset += totalLen
	}
	consumed = offset
	return
}

// ParseClientHelloSNIWithValue 从 ClientHello 握手消息 payload 中提取 SNI 原始字符串和长度。
// 返回 (hostname, length) 或 ("", -1) 表示解析失败或无 SNI。
func ParseClientHelloSNIWithValue(payload []byte) (string, int) {
	if len(payload) < 4 || payload[0] != model.TLSHandshakeClientHello {
		return "", -1
	}
	pos := 4
	if pos+2 > len(payload) {
		return "", -1
	}
	pos += 2 // legacy_version
	if pos+32 > len(payload) {
		return "", -1
	}
	pos += 32 // random
	if pos+1 > len(payload) {
		return "", -1
	}
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen
	if pos > len(payload) {
		return "", -1
	}
	if pos+2 > len(payload) {
		return "", -1
	}
	cipherSuitesLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2 + cipherSuitesLen
	if pos > len(payload) {
		return "", -1
	}
	if pos+1 > len(payload) {
		return "", -1
	}
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen
	if pos > len(payload) {
		return "", -1
	}
	if pos+2 > len(payload) {
		return "", -1
	}
	extTotalLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(payload) {
		return "", -1
	}
	for pos+4 <= extEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4
		if extType == 0x0000 { // server_name
			if pos+2 > extEnd {
				return "", -1
			}
			listLen := int(payload[pos])<<8 | int(payload[pos+1])
			pos += 2
			listEnd := pos + listLen
			for pos+3 <= listEnd {
				nameType := payload[pos]
				nameLen := int(payload[pos+1])<<8 | int(payload[pos+2])
				pos += 3
				if nameType == 0x00 { // host_name
					if pos+nameLen > len(payload) {
						return "", -1
					}
					return string(payload[pos : pos+nameLen]), nameLen
				}
				pos += nameLen
			}
			return "", -1
		}
		pos += extLen
	}
	return "", -1
}

// ParseServerHelloVersion 从 ServerHello payload 中提取协商的 TLS 版本。
// 优先读取 supported_versions 扩展（0x002b）中的 selected_version；
// 扩展不存在时回退读取 ServerHello 头部的 legacy_version。
// 解析失败返回 0。
func ParseServerHelloVersion(payload []byte) uint16 {
	if len(payload) < 4 || payload[0] != model.TLSHandshakeServerHello {
		return 0
	}
	pos := 4
	if pos+2 > len(payload) {
		return 0
	}
	legacyVersion := uint16(payload[pos])<<8 | uint16(payload[pos+1])
	pos += 2
	if pos+32 > len(payload) {
		return legacyVersion
	}
	pos += 32
	if pos+1 > len(payload) {
		return legacyVersion
	}
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen
	if pos > len(payload) {
		return legacyVersion
	}
	if pos+2 > len(payload) {
		return legacyVersion
	}
	pos += 2 // cipher_suite
	if pos+1 > len(payload) {
		return legacyVersion
	}
	pos += 1 // compression_method
	if pos+2 > len(payload) {
		return legacyVersion
	}
	extTotalLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(payload) {
		return legacyVersion
	}
	for pos+4 <= extEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4
		if extType == 0x002b { // supported_versions
			if extLen < 2 || pos+2 > extEnd {
				return legacyVersion
			}
			return uint16(payload[pos])<<8 | uint16(payload[pos+1])
		}
		pos += extLen
	}
	return legacyVersion
}

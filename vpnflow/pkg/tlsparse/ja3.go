package tlsparse

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"vpnflow/pkg/model"
)

// ClientHelloFingerprint 是从 ClientHello 解析出的 TLS 指纹信息，用于 JA3 等特征。
type ClientHelloFingerprint struct {
	Present            bool
	LegacyVersion      uint16   // ClientHello 的 legacy_version
	CipherSuites       []uint16 // 含 GREASE，按出现顺序
	Extensions         []uint16 // 含 GREASE，按出现顺序
	SupportedGroups    []uint16 // 扩展 0x000a（supported_groups）
	ECPointFormats     []uint8  // 扩展 0x000b（ec_point_formats）
	HasGREASE          bool     // cipher/extension 中是否出现 GREASE 值
	JA3                string   // 标准 JA3 MD5 hex（排除 GREASE）
	ExtensionOrderHash string   // 扩展顺序（含 GREASE）的 MD5 hex
}

// isGREASE 判断是否为 GREASE 值（0x0a0a, 0x1a1a, ..., 0xfafa）。
func isGREASE(v uint16) bool {
	lo := v & 0xff
	hi := v >> 8
	if lo != hi {
		return false
	}
	return lo == 0x0a || lo == 0x1a || lo == 0x2a || lo == 0x3a || lo == 0x4a ||
		lo == 0x5a || lo == 0x6a || lo == 0x7a || lo == 0x8a || lo == 0x9a ||
		lo == 0xaa || lo == 0xba || lo == 0xca || lo == 0xda || lo == 0xea || lo == 0xfa
}

// ParseClientHelloFingerprint 从 ClientHello payload 解析指纹信息。
// payload 为 TLS Record 的完整 payload（不含 5 字节 Record Header），起始为 Handshake Header。
func ParseClientHelloFingerprint(payload []byte) ClientHelloFingerprint {
	var fp ClientHelloFingerprint
	if len(payload) < 4 || payload[0] != model.TLSHandshakeClientHello {
		return fp
	}
	fp.Present = true
	pos := 4
	if pos+2 > len(payload) {
		return fp
	}
	fp.LegacyVersion = uint16(payload[pos])<<8 | uint16(payload[pos+1])
	pos += 2
	if pos+32 > len(payload) {
		return fp
	}
	pos += 32 // random
	if pos+1 > len(payload) {
		return fp
	}
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen
	if pos > len(payload) {
		return fp
	}
	if pos+2 > len(payload) {
		return fp
	}
	cipherSuitesLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	cipherEnd := pos + cipherSuitesLen
	if cipherEnd > len(payload) {
		return fp
	}
	for pos+2 <= cipherEnd {
		c := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		fp.CipherSuites = append(fp.CipherSuites, c)
		if isGREASE(c) {
			fp.HasGREASE = true
		}
		pos += 2
	}
	if pos+1 > len(payload) {
		return fp
	}
	compressionLen := int(payload[pos])
	pos += 1 + compressionLen
	if pos > len(payload) {
		return fp
	}
	if pos+2 > len(payload) {
		return fp
	}
	extTotalLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	extEnd := pos + extTotalLen
	if extEnd > len(payload) {
		return fp
	}
	for pos+4 <= extEnd {
		extType := uint16(payload[pos])<<8 | uint16(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4
		fp.Extensions = append(fp.Extensions, extType)
		if isGREASE(extType) {
			fp.HasGREASE = true
		}
		extDataEnd := pos + extLen
		if extDataEnd > extEnd {
			break
		}
		switch extType {
		case 0x000a: // supported_groups
			if extLen >= 2 && pos+2 <= extDataEnd {
				listLen := int(payload[pos])<<8 | int(payload[pos+1])
				gEnd := pos + 2 + listLen
				if gEnd > extDataEnd {
					gEnd = extDataEnd
				}
				for p := pos + 2; p+2 <= gEnd; p += 2 {
					fp.SupportedGroups = append(fp.SupportedGroups, uint16(payload[p])<<8|uint16(payload[p+1]))
				}
			}
		case 0x000b: // ec_point_formats
			if extLen >= 1 && pos < extDataEnd {
				fmtLen := int(payload[pos])
				for p := pos + 1; p < pos+1+fmtLen && p < extDataEnd; p++ {
					fp.ECPointFormats = append(fp.ECPointFormats, payload[p])
				}
			}
		}
		pos = extDataEnd
	}
	fp.JA3 = computeJA3(fp)
	fp.ExtensionOrderHash = computeExtOrderHash(fp.Extensions)
	return fp
}

// computeJA3 计算标准 JA3：MD5(legacy_version,ciphers,extensions,groups,ecpf)，排除 GREASE。
func computeJA3(fp ClientHelloFingerprint) string {
	ciphers := filterGREASE16(fp.CipherSuites)
	exts := filterGREASE16(fp.Extensions)
	groups := filterGREASE16(fp.SupportedGroups)
	ecpf := make([]string, 0, len(fp.ECPointFormats))
	for _, v := range fp.ECPointFormats {
		ecpf = append(ecpf, strconv.Itoa(int(v)))
	}
	s := fmt.Sprintf("%d,%s,%s,%s,%s",
		fp.LegacyVersion,
		join16(ciphers), join16(exts), join16(groups),
		strings.Join(ecpf, "-"))
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func computeExtOrderHash(exts []uint16) string {
	sum := md5.Sum([]byte(join16(exts)))
	return hex.EncodeToString(sum[:])
}

func filterGREASE16(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func join16(vs []uint16) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, strconv.Itoa(int(v)))
	}
	return strings.Join(parts, "-")
}

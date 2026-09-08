package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpnflow/pkg/core/features"
	"vpnflow/pkg/core/protosig"
	"vpnflow/pkg/core/reassembly"
	"vpnflow/pkg/core/typicalflow"
	pcapreader "vpnflow/pkg/input/pcap"
	"vpnflow/pkg/model"
	"vpnflow/pkg/output"
)

// inferLabel 按文件名推断标签（对应计划 §2.3 命名规范），推断不出则按父目录名推断。
// path 为 pcap 完整路径。返回 "" 表示无法推断，需 --label 覆盖。
func inferLabel(path string) string {
	filename := filepath.Base(path)
	stem := strings.ToLower(strings.TrimSuffix(filename, filepath.Ext(filename)))
	switch {
	case strings.HasPrefix(stem, "pos_trojan_") || strings.HasPrefix(stem, "clash_tun_"):
		return "trojan"
	case strings.HasPrefix(stem, "pos_vmess_"):
		return "vmess_vless"
	case strings.HasPrefix(stem, "pos_vless_"):
		return "vmess_vless"
	case strings.HasPrefix(stem, "pos_shadowsocks_") || strings.HasPrefix(stem, "pos_ss_"):
		return "shadowsocks"
	case strings.HasPrefix(stem, "pos_openvpn"):
		return "openvpn"
	case strings.HasPrefix(stem, "pos_pptp"):
		return "pptp"
	case strings.HasPrefix(stem, "pos_l2tp"):
		return "l2tp"
	case strings.HasPrefix(stem, "pos_wireguard"):
		return "wireguard"
	case strings.HasPrefix(stem, "pos_hy2"):
		return "hysteria2"
	case strings.HasPrefix(stem, "neg_") || strings.HasPrefix(stem, "web_tls_") || strings.HasPrefix(stem, "clean_"):
		return "clean"
	}
	// 按父目录名推断
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch dir {
	case "clean", "neg", "https", "direct":
		return "clean"
	case "pos", "trojan":
		return "trojan"
	case "vmess", "vless":
		return "vmess_vless"
	case "shadowsocks", "ss":
		return "shadowsocks"
	case "openvpn":
		return "openvpn"
	case "pptp":
		return "pptp"
	case "l2tp":
		return "l2tp"
	case "wireguard":
		return "wireguard"
	case "hysteria2", "hy2":
		return "hysteria2"
	}
	return ""
}

func main() {
	pcapPath := flag.String("pcap", "", "PCAP 文件或目录（必填）")
	outPath := flag.String("output", "", "输出 CSV 路径（必填）")
	label := flag.String("label", "", "标签覆盖；默认按文件名推断")
	minPackets := flag.Int("min-packets", 30, "典型流最小包数")
	minDuration := flag.Float64("min-duration", 5.0, "典型流最小持续时间（秒）")
	minPayloadBytes := flag.Int("min-payload-bytes", 2000, "典型流最小 payload 字节数")
	minPayloadPkts := flag.Int("min-payload-pkts", 5, "典型流最小含 payload 包数")
	requireClientHello := flag.Bool("require-client-hello", false, "只输出能够解析到 TLS ClientHello 的完整 TLS 流")
	requirePostTLSPayload := flag.Bool("require-post-tls-payload", false, "只输出已定位到至少 3 条外层 TLS 后载荷 AppData Record 的流")
	requireTCPHandshake := flag.Bool("require-tcp-handshake", false, "只输出抓到并校验完整 TCP 三次握手的流")
	protocolOut := flag.String("protocol-output", "", "标准协议会话 JSONL 输出路径；为空时不写文件")
	protocolIdleTimeout := flag.Duration("protocol-idle-timeout", 120*time.Second, "标准协议 Flow/Session 空闲超时")
	protocolOnly := flag.Bool("protocol-only", false, "只运行标准协议规则分支，不做 TCP 重组和 ML 特征提取")
	flag.Parse()

	if *pcapPath == "" || (!*protocolOnly && *outPath == "") ||
		(*protocolOnly && *protocolOut == "") {
		fmt.Fprintln(os.Stderr, "错误：--pcap 必填；普通模式需要 --output，--protocol-only 模式需要 --protocol-output")
		flag.Usage()
		os.Exit(1)
	}

	// 收集 pcap 文件（递归扫描子目录）
	var pcapFiles []string
	info, err := os.Stat(*pcapPath)
	if err != nil {
		log.Fatalf("无法访问 %s: %v", *pcapPath, err)
	}
	if info.IsDir() {
		filepath.Walk(*pcapPath, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".pcap" || ext == ".pcapng" {
				pcapFiles = append(pcapFiles, p)
			}
			return nil
		})
	} else {
		pcapFiles = []string{*pcapPath}
	}
	if len(pcapFiles) == 0 {
		log.Fatalf("未找到任何 .pcap 文件: %s", *pcapPath)
	}

	flt := typicalflow.Filter{
		MinPackets:      *minPackets,
		MinDurationSec:  *minDuration,
		MinPayloadBytes: *minPayloadBytes,
		MinPayloadPkts:  *minPayloadPkts,
		RequireBidi:     true,
	}

	var allRows []model.FeatureRow
	var allProtocolResults []model.ProtocolResult
	totalFlows, keptFlows := 0, 0

	for _, pcapFile := range pcapFiles {
		filename := filepath.Base(pcapFile)
		fl := *label
		if fl == "" {
			fl = inferLabel(pcapFile)
		}
		if fl == "" && !*protocolOnly {
			log.Printf("[警告] %s 无法推断 label：仍执行标准协议识别，但不生成该文件的 ML 特征", filename)
		}
		mlEnabled := !*protocolOnly && fl != ""

		t0 := time.Now()
		packets, err := pcapreader.ReadPackets(pcapFile)
		if err != nil {
			log.Printf("[警告] 读取 %s 失败: %v", filename, err)
			continue
		}
		tcpPackets, udpPackets, grePackets := 0, 0, 0
		for _, pkt := range packets {
			switch {
			case pkt.IsTCP():
				tcpPackets++
			case pkt.IsUDP():
				udpPackets++
			case pkt.IsGRE():
				grePackets++
			}
		}
		fmt.Printf("[文件] %s: %d 个包 (TCP=%d, UDP=%d, GRE=%d)\n",
			filename, len(packets), tcpPackets, udpPackets, grePackets)

		protocolEngine := protosig.New(protosig.Config{
			SourceFile:  filename,
			IdleTimeout: *protocolIdleTimeout,
		})
		var fileProtocolResults []model.ProtocolResult
		ra := reassembly.New()
		for _, pkt := range packets {
			expired := protocolEngine.Observe(pkt)
			fileProtocolResults = append(fileProtocolResults, expired...)
			if mlEnabled && pkt.IsTCP() {
				ra.Feed(pkt)
			}
		}
		fileProtocolResults = append(fileProtocolResults, protocolEngine.FlushAll()...)
		allProtocolResults = append(allProtocolResults, fileProtocolResults...)
		fmt.Printf("[协议] %s: %d 条候选会话\n", filename, len(fileProtocolResults))
		protocolByFlow := make(map[string]model.ProtocolResult)
		for _, result := range fileProtocolResults {
			for _, flowKey := range result.Flows {
				current, exists := protocolByFlow[flowKey]
				if !exists ||
					(current.Verdict != model.VerdictConfirmed &&
						result.Verdict == model.VerdictConfirmed) {
					protocolByFlow[flowKey] = result
				}
			}
		}

		if !mlEnabled {
			continue
		}
		flows := ra.FlushAll()
		totalFlows += len(flows)

		fileKept := 0
		fileTypical := 0
		fileHandshakeDropped := 0
		fileClientHelloDropped := 0
		filePostTLSPayloadDropped := 0
		for i := range flows {
			f := &flows[i]
			if !flt.Keep(f) {
				continue
			}
			fileTypical++
			if *requireTCPHandshake && !f.TCPHandshakeComplete {
				fileHandshakeDropped++
				continue
			}
			row := features.Extract(f, filename, fl)
			if protocolResult, ok := protocolByFlow[row.FlowKey]; ok {
				row.StandardProtocol = protocolResult.Protocol
				row.StandardProtocolVerdict = string(protocolResult.Verdict)
				row.ProtocolSessionID = protocolResult.SessionID
			}
			if *requireClientHello && row.OuterClientHelloPresent == 0 {
				fileClientHelloDropped++
				continue
			}
			if *requirePostTLSPayload && row.PostTLSPayloadReady == 0 {
				filePostTLSPayloadDropped++
				continue
			}
			allRows = append(allRows, row)
			fileKept++
			keptFlows++
		}
		fmt.Printf("[过滤] %s: %d 条流 → %d 条典型候选 → %d 条保留 (label=%s, tcp握手排除=%d, ClientHello排除=%d), 耗时 %v\n",
			filename, len(flows), fileTypical, fileKept, fl, fileHandshakeDropped, fileClientHelloDropped, time.Since(t0))
		if *requirePostTLSPayload {
			fmt.Printf("[过滤] %s: 后TLS载荷窗口排除=%d\n", filename, filePostTLSPayloadDropped)
		}
	}

	if !*protocolOnly {
		if err := output.WriteCSV(allRows, *outPath); err != nil {
			log.Fatalf("写出 CSV 失败: %v", err)
		}
		fmt.Printf("[输出] %d 行 → %s (总流 %d, 典型流 %d)\n", len(allRows), *outPath, totalFlows, keptFlows)
	}
	if *protocolOut != "" {
		if err := output.WriteProtocolJSONL(allProtocolResults, *protocolOut); err != nil {
			log.Fatalf("写出标准协议 JSONL 失败: %v", err)
		}
		fmt.Printf("[协议输出] %d 条会话 → %s\n", len(allProtocolResults), *protocolOut)
	}
}

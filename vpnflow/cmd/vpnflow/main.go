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
	case strings.HasPrefix(stem, "neg_") || strings.HasPrefix(stem, "web_tls_"):
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
	requireTCPHandshake := flag.Bool("require-tcp-handshake", false, "只输出抓到并校验完整 TCP 三次握手的流")
	flag.Parse()

	if *pcapPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "错误：--pcap、--output 为必填参数")
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
	totalFlows, keptFlows := 0, 0

	for _, pcapFile := range pcapFiles {
		filename := filepath.Base(pcapFile)
		fl := *label
		if fl == "" {
			fl = inferLabel(pcapFile)
		}
		if fl == "" {
			log.Printf("[警告] 跳过 %s：无法推断 label，请用 --label 指定", filename)
			continue
		}

		t0 := time.Now()
		packets, err := pcapreader.ReadPackets(pcapFile)
		if err != nil {
			log.Printf("[警告] 读取 %s 失败: %v", filename, err)
			continue
		}
		fmt.Printf("[文件] %s: %d 个包\n", filename, len(packets))

		ra := reassembly.New()
		for _, pkt := range packets {
			ra.Feed(pkt)
		}
		flows := ra.FlushAll()
		totalFlows += len(flows)

		fileKept := 0
		fileTypical := 0
		fileHandshakeDropped := 0
		fileClientHelloDropped := 0
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
			if *requireClientHello && row.OuterClientHelloPresent == 0 {
				fileClientHelloDropped++
				continue
			}
			allRows = append(allRows, row)
			fileKept++
			keptFlows++
		}
		fmt.Printf("[过滤] %s: %d 条流 → %d 条典型候选 → %d 条保留 (label=%s, tcp握手排除=%d, ClientHello排除=%d), 耗时 %v\n",
			filename, len(flows), fileTypical, fileKept, fl, fileHandshakeDropped, fileClientHelloDropped, time.Since(t0))
	}

	if err := output.WriteCSV(allRows, *outPath); err != nil {
		log.Fatalf("写出 CSV 失败: %v", err)
	}
	fmt.Printf("[输出] %d 行 → %s (总流 %d, 典型流 %d)\n", len(allRows), *outPath, totalFlows, keptFlows)
}

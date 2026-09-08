package main

import (
	"path/filepath"
	"testing"
)

func TestInferLabelByFilename(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{filepath.Join("样本", "pos_trojan_tun_tcp.pcap"), "trojan"},
		{filepath.Join("样本", "pos_vless_proxy_tcp.pcap"), "vmess_vless"},
		{filepath.Join("样本", "pos_ss_proxy_tcp.pcap"), "shadowsocks"},
		{filepath.Join("样本", "pos_openvpn1_tcp.pcap"), "openvpn"},
		{filepath.Join("样本", "pos_openvpn14.tcp.pcap"), "openvpn"},
		{filepath.Join("样本", "pos_pptp_tcp1.pcap"), "pptp"},
		{filepath.Join("样本", "pos_l2tp_tcp8.pcap"), "l2tp"},
		{filepath.Join("样本", "pos_wireguard_udp1.pcap"), "wireguard"},
		{filepath.Join("样本", "pos_hy2_tun_udp.pcap"), "hysteria2"},
		{filepath.Join("样本", "clean", "clean_scp.pcap"), "clean"},
		{filepath.Join("样本", "clean", "clean_sftp.pcap"), "clean"},
		{filepath.Join("样本", "neg_https_direct.pcap"), "clean"},
	}
	for _, tc := range cases {
		got := inferLabel(tc.path)
		if got != tc.want {
			t.Errorf("inferLabel(%q)=%q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestInferLabelByParentDir(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{filepath.Join("样本", "clean", "browse.pcap"), "clean"},
		{filepath.Join("样本", "openvpn", "session.pcap"), "openvpn"},
		{filepath.Join("样本", "pptp", "session.pcap"), "pptp"},
		{filepath.Join("样本", "l2tp", "session.pcap"), "l2tp"},
		{filepath.Join("样本", "wireguard", "session.pcap"), "wireguard"},
		{filepath.Join("样本", "hy2", "session.pcap"), "hysteria2"},
	}
	for _, tc := range cases {
		got := inferLabel(tc.path)
		if got != tc.want {
			t.Errorf("inferLabel(%q)=%q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestResolveExtractionLabelInference(t *testing.T) {
	label, enabled := resolveExtractionLabel(filepath.Join("captures", "unknown.pcap"), "", true)
	if !enabled {
		t.Fatal("inference mode must enable ML feature extraction")
	}
	if label != "" {
		t.Fatalf("inference label=%q, want empty", label)
	}
}

func TestResolveExtractionLabelTrainingUnknown(t *testing.T) {
	label, enabled := resolveExtractionLabel(filepath.Join("captures", "unknown.pcap"), "", false)
	if enabled || label != "" {
		t.Fatalf("training unknown got label=%q enabled=%v, want empty/false", label, enabled)
	}
}

func TestResolveExtractionLabelOverride(t *testing.T) {
	label, enabled := resolveExtractionLabel("unknown.pcap", "trojan", true)
	if !enabled || label != "trojan" {
		t.Fatalf("override got label=%q enabled=%v", label, enabled)
	}
}

package model

import "testing"

func TestFeatureCSVIncludesTCPHandshakeComplete(t *testing.T) {
	row := FeatureRow{TCPHandshakeComplete: 1}
	header := CSVHeader()
	record := row.ToCSVRecord()
	if len(header) != len(record) {
		t.Fatalf("header has %d columns, record has %d", len(header), len(record))
	}
	for i, name := range header {
		if name == "tcp_handshake_complete" {
			if record[i] != "1" {
				t.Fatalf("tcp_handshake_complete=%q, want 1", record[i])
			}
			return
		}
	}
	t.Fatal("tcp_handshake_complete column not found")
}

func TestFeatureCSVIncludesTrojanApplicable(t *testing.T) {
	row := FeatureRow{TrojanApplicable: 1}
	header := CSVHeader()
	record := row.ToCSVRecord()
	for i, name := range header {
		if name == "trojan_applicable" {
			if record[i] != "1" {
				t.Fatalf("trojan_applicable=%q, want 1", record[i])
			}
			return
		}
	}
	t.Fatal("trojan_applicable column not found")
}

func TestFeatureCSVIncludesStandardProtocolRouting(t *testing.T) {
	row := FeatureRow{
		StandardProtocol:        "openvpn",
		StandardProtocolVerdict: "confirmed",
		ProtocolSessionID:       "openvpn:1",
	}
	header := CSVHeader()
	record := row.ToCSVRecord()
	want := map[string]string{
		"standard_protocol":         "openvpn",
		"standard_protocol_verdict": "confirmed",
		"protocol_session_id":       "openvpn:1",
	}
	for i, name := range header {
		if expected, ok := want[name]; ok {
			if record[i] != expected {
				t.Fatalf("%s=%q, want %q", name, record[i], expected)
			}
			delete(want, name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing routing columns: %v", want)
	}
}

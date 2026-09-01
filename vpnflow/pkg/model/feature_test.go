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

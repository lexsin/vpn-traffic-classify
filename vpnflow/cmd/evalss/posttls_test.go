package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeepTrainingRowRequiresPostTLSPayload(t *testing.T) {
	opts := readOptions{requirePostTLSPayload: true}
	row := map[string]string{"post_tls_payload_ready": "0"}
	if keepTrainingRow(row, opts) {
		t.Fatal("flow without post TLS payload was kept")
	}
	row["post_tls_payload_ready"] = "1"
	if !keepTrainingRow(row, opts) {
		t.Fatal("flow with post TLS payload was dropped")
	}
}

func TestReadDatasetRequiresPostTLSPayloadColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.csv")
	if err := os.WriteFile(path, []byte("label,total_packets\nclean,1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := readDataset(path, readOptions{requirePostTLSPayload: true})
	if err == nil || !strings.Contains(err.Error(), "post_tls_payload_ready") {
		t.Fatalf("expected missing post TLS payload column error, got %v", err)
	}
}

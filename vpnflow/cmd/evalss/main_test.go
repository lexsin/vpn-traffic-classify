package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeepTrainingRowRequiresTCPHandshake(t *testing.T) {
	opts := readOptions{requireTCPHandshake: true}
	row := map[string]string{"tcp_handshake_complete": "0"}
	if keepTrainingRow(row, opts) {
		t.Fatal("incomplete TCP flow was kept")
	}
	row["tcp_handshake_complete"] = "1"
	if !keepTrainingRow(row, opts) {
		t.Fatal("complete TCP flow was dropped")
	}
}

func TestKeepTrainingRowCombinesCompletenessRequirements(t *testing.T) {
	opts := readOptions{requireClientHello: true, requireTCPHandshake: true}
	row := map[string]string{
		"outer_client_hello_present": "0",
		"tcp_handshake_complete":     "1",
	}
	if keepTrainingRow(row, opts) {
		t.Fatal("row missing ClientHello was kept when both requirements were enabled")
	}
	row["outer_client_hello_present"] = "1"
	if !keepTrainingRow(row, opts) {
		t.Fatal("row satisfying both completeness requirements was dropped")
	}
}

func TestReadDatasetRequiresHandshakeColumnOnlyWhenEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.csv")
	if err := os.WriteFile(path, []byte("label,total_packets\nclean,1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDataset(path, readOptions{}); err != nil {
		t.Fatalf("old CSV should remain readable when handshake filter is disabled: %v", err)
	}
	_, err := readDataset(path, readOptions{requireTCPHandshake: true})
	if err == nil || !strings.Contains(err.Error(), "tcp_handshake_complete") {
		t.Fatalf("expected missing handshake column error, got %v", err)
	}
}

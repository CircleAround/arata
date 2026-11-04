package notify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 巨大な report.json をメモリに読まない。「読めない」として緊急用に知らせる経路に乗せる。
func TestReadInputRejectsOversizedReport(t *testing.T) {
	defer func(n int64) { maxReportBytes = n }(maxReportBytes)
	maxReportBytes = 16
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ReportJSON), []byte(`{"generated_at":"2026-10-21T09:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadInput(dir, now, 26*time.Hour)
	var ie *InputError
	if !errors.As(err, &ie) || ie.Code != CodeInputInvalid {
		t.Fatalf("%v", err)
	}
}

// 大きすぎる report.md は使わず、report.json から作り直す。
func TestReadInputIgnoresOversizedMarkdown(t *testing.T) {
	defer func(n int64) { maxReportBytes = n }(maxReportBytes)
	dir := inputDir(t, golden(t, "report.json"), "x")
	maxReportBytes = int64(len(golden(t, "report.json")))
	big := make([]byte, maxReportBytes+1)
	if err := os.WriteFile(filepath.Join(dir, ReportMD), big, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := ReadInput(dir, now, 26*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Markdown) == len(big) || in.Markdown == "" {
		t.Fatalf("report.md を使った: %d", len(in.Markdown))
	}
}

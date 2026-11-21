package config

import (
	"strings"
	"testing"
)

// プロファイルの重大度の下限 (ADR 0082 の 1 節)。書かなければ下限なし (暗黙の既定を持たない)。
func TestProfileMinSeverity(t *testing.T) {
	with := func(v string) string {
		return strings.Replace(minimal, "    checks: [default-daily, root_usage]\n", "    checks: [default-daily, root_usage]\n    min_severity: "+v+"\n", 1)
	}
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Profiles["daily"].MinSeverity; got != "" {
		t.Fatalf("既定は空: %q", got)
	}
	for _, v := range []string{"critical", "high", "medium", "low"} {
		cfg, err := Load(write(t, with(v)))
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if got := cfg.Profiles["daily"].MinSeverity; got != v {
			t.Fatalf("%s: %q", v, got)
		}
	}
	// info は下限にできない (下限より下は info だけになり、意味が無い)。大文字・知らない値・空白は誤記
	for _, v := range []string{"info", "High", "urgent", "' high'"} {
		_, err := Load(write(t, with(v)))
		if err == nil || !strings.Contains(err.Error(), "min_severity") {
			t.Errorf("%s: %v", v, err)
		}
	}
}

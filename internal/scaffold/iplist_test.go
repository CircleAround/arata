package scaffold

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
)

// 怪しい IP の一覧 (ADR 0069): 雛形は ip_list: を既定値で書き出す (理由は 3 つとも)。retention.ip_list も書く。
func TestGenerateIPList(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, Generate(checks.NewRegistry(), config.AuditAccountNone), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.IPList
	if l == nil || l.ActiveRaw != config.DefaultIPListActive || cfg.Retention.IPListRaw != config.DefaultRetention.IPListRaw {
		t.Fatalf("ip_list = %+v, retention %q", l, cfg.Retention.IPListRaw)
	}
	r := l.Reasons
	if r.WAFBlock == nil || *r.WAFBlock != config.DefaultIPListWAFBlock || r.Probe == nil || *r.Probe != config.DefaultIPListProbe ||
		r.SignInFailure == nil || !reflect.DeepEqual(*r.SignInFailure, config.DefaultIPListSignIn) {
		t.Fatalf("reasons = %+v %+v %+v", r.WAFBlock, r.Probe, r.SignInFailure)
	}
}

// --diff: ip_list: が無い設定には missing_key、書いた値が既定値と違えば param_changed。
func TestDiffIPList(t *testing.T) {
	reg := checks.NewRegistry()
	b := string(Generate(reg, config.AuditAccountNone))
	i := strings.Index(b, "\nip_list:")
	j := strings.Index(b, "\n# 保持期間")
	if i < 0 || j < i {
		t.Fatal("template has no ip_list block before retention")
	}
	without := b[:i] + "\n" + b[j:]
	items, err := Diff([]byte(without), reg)
	if err != nil || len(items) != 1 || items[0].Kind != DiffMissingKey || items[0].Path != "ip_list" || !strings.Contains(items[0].Detail, "ADR 0069") {
		t.Fatalf("%v %+v", err, items)
	}
	changed := strings.Replace(b, "min_count_window: 50", "min_count_window: 80", 1)
	items, err = Diff([]byte(changed), reg)
	if err != nil || len(items) != 1 || items[0].Kind != DiffParamChanged || items[0].Path != "ip_list.reasons.sign_in_failure.min_count_window" ||
		items[0].Current != "80" || items[0].Template != "50" {
		t.Fatalf("%v %+v", err, items)
	}
	if items, err := Diff([]byte(b), reg); err != nil || len(items) != 0 {
		t.Fatalf("template itself: %v %+v", err, items)
	}
}

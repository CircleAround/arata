package engine

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/store"
)

// approve --shared (ADR 0094 の 1 節)。値はすべて架空。実 AWS には接続しない。

func sharedFinding(t *testing.T, e *Engine, id, check, ip string, data map[string]any) {
	t.Helper()
	if data == nil {
		data = map[string]any{}
	}
	data["ip"] = ip
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	f := store.Finding{ID: id, Check: check, Key: ip, Severity: "low", Summary: "s", FirstSeen: at, LastSeen: at, LastChanged: at, Status: store.FindingOpen, Fingerprint: "low|", Data: data}
	if err := e.st.UpsertFinding(t.Context(), f); err != nil {
		t.Fatal(err)
	}
}

func TestApproveShared(t *testing.T) {
	h := newHarness(t)
	e := h.open(t)
	sharedFinding(t, e, "f00000000001", "rate_limited_ip", "198.51.100.7", map[string]any{"reasons": []string{"suggest_shared"}})
	sharedFinding(t, e, "f00000000002", "login_bruteforce", "2001:db8:10::5", nil)
	sharedFinding(t, e, "f00000000003", "rate_limited_ip", "198.51.100.8", map[string]any{"shared": true})
	sharedFinding(t, e, "f00000000004", "probe_paths", "198.51.100.9", nil)
	sharedFinding(t, e, "f00000000005", "rate_limited_ip", "x", nil)
	sharedFinding(t, e, "f00000000006", "rate_limited_ip", "::ffff:192.0.2.7", nil)

	// review は既定で書く範囲を示す (IPv4 射影は IPv4 に読み直す)。既に shared の IP・ほかのチェック・読めない IP には示さない
	items, err := e.Review(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range items {
		got[it.ID] = it.ApproveShared
		if it.ID == "f00000000001" && strings.Join(it.Triage.Allowed, ",") != "approve,snooze,resolve" {
			t.Fatalf("triage: %+v", it.Triage)
		}
	}
	want := map[string]string{"f00000000001": "198.51.100.7/32", "f00000000002": "2001:db8:10::5/128", "f00000000003": "", "f00000000004": "", "f00000000005": "", "f00000000006": "192.0.2.7/32"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("approve_shared %s: got %q want %q", id, got[id], w)
		}
	}

	// 断るもの (何も書かない)
	before, _ := os.ReadFile(h.cfg.Allowlist)
	for name, tc := range map[string]struct {
		id   string
		o    ApproveOptions
		want string
	}{
		"note が無い":          {"f00000000001", ApproveOptions{Shared: true}, "--note"},
		"ほかのチェック":           {"f00000000004", ApproveOptions{Shared: true, Note: "n"}, "only for rate_limited_ip and login_bruteforce"},
		"既に shared":         {"f00000000003", ApproveOptions{Shared: true, Note: "n"}, "already in shared_sources"},
		"読めない IP":           {"f00000000005", ApproveOptions{Shared: true, Note: "n"}, "no valid IP"},
		"IP を含まない範囲":        {"f00000000001", ApproveOptions{SharedCIDR: "192.0.2.0/24", Note: "n"}, "does not contain"},
		"広すぎる範囲":            {"f00000000001", ApproveOptions{SharedCIDR: "198.51.100.0/23", Note: "n"}, "broader than /24"},
		"IPv6 の広すぎる範囲":      {"f00000000002", ApproveOptions{SharedCIDR: "2001:db8::/32", Note: "n"}, "broader than"},
		"ネットワークの形でない":       {"f00000000001", ApproveOptions{SharedCIDR: "198.51.100.7/24", Note: "n"}, "network address"},
		"過去の期限":             {"f00000000001", ApproveOptions{Shared: true, Note: "n", Expires: "2026-10-20"}, "already past"},
		"主体の承認の指定と一緒":       {"f00000000001", ApproveOptions{Shared: true, Note: "n", Account: true}, "cannot be combined"},
		"--destination と一緒": {"f00000000001", ApproveOptions{Shared: true, Destination: true, Note: "n"}, "cannot be combined"},
		"--shared なしは主体の承認": {"f00000000001", ApproveOptions{Note: "n"}, "not about a principal"},
	} {
		if _, err := e.Approve(t.Context(), tc.id, tc.o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v want %q", name, err, tc.want)
		}
	}
	if after, _ := os.ReadFile(h.cfg.Allowlist); string(after) != string(before) {
		t.Fatalf("断ったのに書いた:\n%s", after)
	}

	// 既定は IP そのもの。期限は今日 (2026-10-21) でもよい
	res, err := e.Approve(t.Context(), "f00000000001", ApproveOptions{Shared: true, Note: "試験の会場", Expires: "2026-10-21", By: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject() != "shared_source:198.51.100.7/32" || !strings.Contains(res.Added, "cidr: 198.51.100.7/32\n") || !strings.Contains(res.Added, "expires: 2026-10-21\n") || !strings.Contains(res.Added, "approved_by: alice\n") {
		t.Fatalf("res: %+v\n%s", res, res.Added)
	}
	// 範囲を書く
	if res, err = e.Approve(t.Context(), "f00000000002", ApproveOptions{SharedCIDR: "2001:db8:10::/48", Note: "学校"}); err != nil || res.Subject() != "shared_source:2001:db8:10::/48" {
		t.Fatalf("cidr: %+v %v", res, err)
	}
	if err := e.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	al, err := allowlist.Load(h.cfg.Allowlist)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := al.SharedSource("198.51.100.7", time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)); !ok || e.Note != "試験の会場" || len(al.Principals) != 1 {
		t.Fatalf("allowlist: %+v", al)
	}
	for _, id := range []string{"f00000000001", "f00000000002"} {
		f, err := e.st.Finding(t.Context(), id)
		if err != nil || f.Status != store.FindingResolved {
			t.Fatalf("%s: %+v %v", id, f, err)
		}
	}
	// 同じ範囲は 2 度書かない
	sharedFinding(t, e, "f00000000007", "login_bruteforce", "198.51.100.7", nil)
	if _, err := e.Approve(t.Context(), "f00000000007", ApproveOptions{Shared: true, Note: "n"}); !errors.Is(err, allowlist.ErrAlreadyListed) {
		t.Fatalf("duplicate: %v", err)
	}
}

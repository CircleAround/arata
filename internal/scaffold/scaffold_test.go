package scaffold

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/allowlist"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

// TestGenerateGolden は雛形の YAML を固定する。チェックや既定値を変えたら差分を確かめて -update する。
func TestGenerateGolden(t *testing.T) {
	got := Generate(checks.NewRegistry(), "111122223333")
	p := filepath.Join("testdata", "config.yaml")
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("template differs from golden (review, then `go test ./internal/scaffold -update`):\n%s", got)
	}
}

// TestGenerateLoads は雛形をそのまま読み込んで Validate が通り、全チェックがどれかのプロファイルに入っていることを確かめる。
func TestGenerateLoads(t *testing.T) {
	reg := checks.NewRegistry()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, Generate(reg, config.AuditAccountNone), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, prof := range cfg.Profiles {
		for _, c := range prof.Checks {
			if strings.HasPrefix(c, "default-") {
				t.Fatalf("template must not use %s", c)
			}
			used[c] = true
		}
	}
	for _, n := range reg.Names() {
		if !used[n] {
			t.Errorf("check %s is in no profile", n)
		}
	}
	// CloudTrail (ふだん使わないリージョンを含む) と週次用のアカウント単位のソースを有効にし、cost-anomaly (有料) と cloudwatch-logs はコメントの例だけ
	var kinds []string
	for _, s := range cfg.Sources {
		kinds = append(kinds, s.Kind)
	}
	if strings.Join(kinds, ",") != "cloudtrail-lookup,cloudtrail-unused-regions,iam-credential-report,guardduty,access-analyzer,posture" {
		t.Fatalf("sources: %v", kinds)
	}
}

// TestGenerateMatchesDefaults は雛形の checks: が config.DefaultChecks() と一致し、全パラメータが明示されていることを確かめる (ドリフト防止)。
func TestGenerateMatchesDefaults(t *testing.T) {
	var doc struct {
		Checks    map[string]map[string]any `yaml:"checks"`
		Retention map[string]string         `yaml:"retention"`
	}
	b := Generate(checks.NewRegistry(), config.AuditAccountNone)
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range config.DefaultChecks().Params() {
		if _, ok := doc.Checks[p.Check][p.Key]; !ok {
			t.Errorf("template lacks checks.%s.%s", p.Check, p.Key)
		}
	}
	var got config.Checks
	if err := yaml.Unmarshal(b, &struct {
		Checks *config.Checks `yaml:"checks"`
	}{&got}); err != nil {
		t.Fatal(err)
	}
	want := config.DefaultChecks()
	if !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatalf("template checks differ from DefaultChecks:\n got %+v\nwant %+v", got, want)
	}
	r := config.DefaultRetention
	if doc.Retention["raw_jsonl"] != r.RawJSONLRaw || doc.Retention["runs"] != r.RunsRaw || len(doc.Retention) != 5 {
		t.Fatalf("retention: %v", doc.Retention)
	}
}

// normalize は nil と空のスライスを同一視する (exclude_paths の既定は nil、雛形では [])。
func normalize(c config.Checks) []config.Param {
	ps := c.Params()
	for i := range ps {
		if v := reflect.ValueOf(ps[i].Value); v.Kind() == reflect.Slice && v.Len() == 0 {
			ps[i].Value = nil
		}
	}
	return ps
}

func TestDescriptions(t *testing.T) {
	for _, n := range checks.NewRegistry().Names() {
		if Descriptions[n] == "" {
			t.Errorf("Descriptions lacks %s", n)
		}
	}
	for _, p := range config.DefaultChecks().Params() {
		if paramComments[p.Check+"."+p.Key] == "" {
			t.Errorf("paramComments lacks %s.%s", p.Check, p.Key)
		}
	}
}

func TestDiff(t *testing.T) {
	reg := checks.NewRegistry()
	if items, err := Diff(Generate(reg, config.AuditAccountNone), reg); err != nil || len(items) != 0 {
		t.Fatalf("template vs itself: %v %+v", err, items)
	}
	cur := `
name: acme
store: dir:///tmp/x
sources:
  - id: trail
    kind: cloudtrail-lookup
profiles:
  daily:
    window: 24h
    checks: [default-daily, secret_access_unknown]
    overide: {}
    overrides:
      login_bruteforce: { min_count: 99 }
checks:
  login_bruteforce:
    min_count: 30
    factor: 3
    methods: [POST]
  probe_paths:
    exclude_paths: []
    bogus: 1
`
	items, err := Diff([]byte(cur), reg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Kind+" "+it.Path+" "+it.Current+"|"+it.Template)
	}
	want := []string{
		"unknown_check profiles.daily.checks secret_access_unknown|",
		"unused_check root_usage |hourly, daily",
		"unused_check unknown_assume_role |hourly, daily",
		"unused_check oidc_assume_role |hourly, daily",
		"unused_check credential_hygiene |weekly",
		"unused_check guardduty_findings |weekly",
		"unused_check posture |weekly",
		"unused_check access_analyzer |weekly",
		"unused_check waf_review |weekly",
		"unused_check log_hygiene |weekly",
		"missing_profile profiles.hourly |root_usage, unknown_assume_role, oidc_assume_role",
		"missing_profile profiles.weekly |credential_hygiene, guardduty_findings, posture, access_analyzer, waf_review, log_hygiene",
		"param_changed checks.login_bruteforce.min_count 30|20",
		"missing_key audit_account |\"<12 桁のアカウント ID>\" か none",
		"unknown_key profiles.daily.overide |",
		"unknown_key checks.probe_paths.bogus |",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s", strings.Join(got, "\n"))
	}
	var b strings.Builder
	if err := WriteDiff(&b, items); err != nil || !strings.Contains(b.String(), "[param_changed] checks.login_bruteforce.min_count: 設定 30 / 雛形 20") {
		t.Fatalf("%v\n%s", err, b.String())
	}
}

// TestGenerateAuditAccount は雛形に「監査する側のアカウント」の選択が残ることを確かめる (ADR 0045)。
func TestGenerateAuditAccount(t *testing.T) {
	reg := checks.NewRegistry()
	for _, tc := range []struct{ in, line string }{
		{"111122223333", `audit_account: "111122223333"`},
		{config.AuditAccountNone, "audit_account: none"},
	} {
		b := Generate(reg, tc.in)
		if n := strings.Count(string(b), "\n"+tc.line+" "); n != 1 {
			t.Fatalf("%s: want 1 line %q, got %d", tc.in, tc.line, n)
		}
		p := filepath.Join(t.TempDir(), "arata.yaml")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(p)
		if err != nil || cfg.AuditAccount != tc.in {
			t.Fatalf("%s: loaded %q, %v", tc.in, cfg.AuditAccount, err)
		}
		if items, err := Diff(b, reg); err != nil || len(items) != 0 {
			t.Fatalf("%s: template vs itself: %v %+v", tc.in, err, items)
		}
	}
}

// TestDiffAuditAccount は audit_account の無い設定 (この項目より前の版) が差分に出て、直し方が読めることを確かめる。
func TestDiffAuditAccount(t *testing.T) {
	reg := checks.NewRegistry()
	b := Generate(reg, config.AuditAccountNone)
	old := strings.Replace(string(b), "\naudit_account: none", "\n# audit_account: none", 1)
	if old == string(b) {
		t.Fatal("template has no audit_account line")
	}
	items, err := Diff([]byte(old), reg)
	if err != nil || len(items) != 1 || items[0].Kind != DiffMissingKey || items[0].Path != "audit_account" {
		t.Fatalf("%v %+v", err, items)
	}
	for _, w := range []string{"audit_account: none", "allowlist", "account:"} {
		if !strings.Contains(items[0].Detail, w) {
			t.Errorf("detail lacks %q: %s", w, items[0].Detail)
		}
	}
	// 値が誤っていても「無い」とは言わない (誤りは config check / Load が止める)
	if items, err := Diff([]byte(strings.Replace(string(b), "audit_account: none", "audit_account: self", 1)), reg); err != nil || len(items) != 0 {
		t.Fatalf("%v %+v", err, items)
	}
}

// TestAuditAllowlist は init が既知リストに書く「監査する側のアカウント」の項目を固定する。
func TestAuditAllowlist(t *testing.T) {
	day := time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC)
	out, added, err := AuditAllowlist(nil, "111122223333", "", day)
	if err != nil {
		t.Fatal(err)
	}
	wantEntry := `  - account: "111122223333"
    note: 監査する側のアカウント。このアカウントの実行用ロールが、監査対象の読み取り専用ロールを引き受けて arata を動かす (arata config init --audit-account が記入)
    approved_at: 2026-11-13
`
	if added != wantEntry {
		t.Fatalf("added:\n%s", added)
	}
	if !strings.HasPrefix(string(out), "# 既知リスト") || !strings.HasSuffix(string(out), "principals:\n"+wantEntry) {
		t.Fatalf("new file:\n%s", out)
	}
	l, err := allowlist.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if st := l.Account("111122223333", day); st != allowlist.StatusApproved {
		t.Fatalf("status %s", st)
	}
	// dynamic_source は書かない: 外部アカウントそのものは principal_new_source の対象 (IAM ユーザーとロール) でない
	if l.Principals[0].DynamicSource || l.Principals[0].ApprovedBy != "" || len(l.Principals[0].Tags) != 0 {
		t.Fatalf("%+v", l.Principals[0])
	}
	// --by を付けたときだけ approved_by を書く
	if _, added, err := AuditAllowlist(nil, "111122223333", "alice", day); err != nil || !strings.Contains(added, "    approved_by: alice\n    approved_at: 2026-11-13\n") {
		t.Fatalf("%v\n%s", err, added)
	}
	// 既にある既知リストには末尾に足し、ほかの行は変えない
	src := "# 手で書いた既知リスト\nprincipals:\n  - arn: arn:aws:iam::123456789012:role/Deploy   # デプロイ\n    tags: [deploy]\nsource_ips:\n  - cidr: 203.0.113.0/24\n"
	out, _, err = AuditAllowlist([]byte(src), "111122223333", "", day)
	want := "# 手で書いた既知リスト\nprincipals:\n  - arn: arn:aws:iam::123456789012:role/Deploy   # デプロイ\n    tags: [deploy]\n" + wantEntry + "source_ips:\n  - cidr: 203.0.113.0/24\n"
	if err != nil || string(out) != want {
		t.Fatalf("%v\n%s", err, out)
	}
	// 同じアカウントが既に書いてあれば足さない
	if _, _, err := AuditAllowlist(out, "111122223333", "", day); !errors.Is(err, allowlist.ErrAlreadyListed) {
		t.Fatalf("err = %v", err)
	}
	// 壊れた既知リストは書き換えない
	if _, _, err := AuditAllowlist([]byte("principals:\n  - note: x\n"), "111122223333", "", day); err == nil || errors.Is(err, allowlist.ErrAlreadyListed) {
		t.Fatalf("err = %v", err)
	}
}

// config init --diff --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
// 最上位は配列のまま、版 1 として固定する (schema / schema_version の項目は持てない)。
func TestDiffSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: DiffSchema, Version: DiffSchemaVersion, Type: []DiffItem{},
		Description: "arata config init --diff --format json の出力。設定とこの版の雛形の差分の配列 (最上位が配列。schema の項目は無い)"}, *update)
}

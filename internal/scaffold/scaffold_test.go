package scaffold

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
)

var update = flag.Bool("update", false, "ゴールデンファイルを更新する")

// TestGenerateGolden は雛形の YAML を固定する。チェックや既定値を変えたら差分を確かめて -update する。
func TestGenerateGolden(t *testing.T) {
	got := Generate(checks.NewRegistry())
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
	if err := os.WriteFile(p, Generate(reg), 0o600); err != nil {
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
	// CloudTrail と週次用のアカウント単位のソースを有効にし、cloudwatch-logs はコメントの例だけ
	var kinds []string
	for _, s := range cfg.Sources {
		kinds = append(kinds, s.Kind)
	}
	if strings.Join(kinds, ",") != "cloudtrail-lookup,iam-credential-report,guardduty,access-analyzer,posture" {
		t.Fatalf("sources: %v", kinds)
	}
}

// TestGenerateMatchesDefaults は雛形の checks: が config.DefaultChecks() と一致し、全パラメータが明示されていることを確かめる (ドリフト防止)。
func TestGenerateMatchesDefaults(t *testing.T) {
	var doc struct {
		Checks    map[string]map[string]any `yaml:"checks"`
		Retention map[string]string         `yaml:"retention"`
	}
	b := Generate(checks.NewRegistry())
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
	if items, err := Diff(Generate(reg), reg); err != nil || len(items) != 0 {
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
		"unused_check credential_hygiene |weekly",
		"unused_check guardduty_findings |weekly",
		"unused_check posture |weekly",
		"unused_check access_analyzer |weekly",
		"unused_check waf_review |weekly",
		"missing_profile profiles.hourly |root_usage, unknown_assume_role",
		"missing_profile profiles.weekly |credential_hygiene, guardduty_findings, posture, access_analyzer, waf_review",
		"param_changed checks.login_bruteforce.min_count 30|20",
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

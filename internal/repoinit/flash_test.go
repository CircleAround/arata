package repoinit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// noFlashGolden は、--flash (ADR 0082) を足す前の版が書き出した生成物 (見本の引数から --flash を外したもの、と --collect-every も外したもの)。
// --flash を付けない一式が、この版でも 1 バイトも変わらないことを固定する。生成物を意図して変えたときだけ -update で作り直す。
const noFlashGolden = "testdata/no-flash"

func TestNoFlashOutputIsUnchanged(t *testing.T) {
	withCollect := exampleParams()
	withCollect.Flash = false
	noCollect := withCollect
	noCollect.CollectEvery = ""
	for name, p := range map[string]Params{"collect-1h": withCollect, "no-collect": noCollect} {
		dir := filepath.Join(noFlashGolden, name)
		for _, f := range mustFiles(t, p) {
			if f.Kind != Generated {
				continue // aws/<アカウント>/ は config init の雛形 (scaffold) の版で変わる
			}
			path := filepath.Join(dir, filepath.FromSlash(f.Path))
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, f.Body, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !bytes.Equal(b, f.Body) {
				t.Errorf("%s: %s differs without --flash (the output must not change. ADR 0082)", name, f.Path)
			}
		}
		if strings.Contains(name, "no-collect") {
			if _, err := os.Stat(filepath.Join(dir, ".github/workflows/arata-collect.yml")); err == nil {
				t.Errorf("%s: arata-collect.yml must not be written", name)
			}
		}
	}
}

// --flash は --collect-every と一緒にだけ使える (ADR 0082 の 5 節)。README のコマンドと PR の検査の引数に載る。
func TestFlashArgs(t *testing.T) {
	p := exampleParams()
	p.Flash, p.CollectEvery = true, ""
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "--flash") {
		t.Fatalf("%v", err)
	}
	p = exampleParams()
	p.Flash = true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Command(), " --collect-every 1h --flash --out .") || !strings.Contains(p.CheckCommand(), " --flash ") {
		t.Fatalf("%s / %s", p.Command(), p.CheckCommand())
	}
}

type flashStep struct {
	ID      string            `yaml:"id"`
	If      string            `yaml:"if"`
	Env     map[string]string `yaml:"env"`
	Run     string            `yaml:"run"`
	Timeout int               `yaml:"timeout-minutes"`
}

func collectSteps(t *testing.T, p Params) (jobEnv map[string]string, steps []flashStep) {
	t.Helper()
	var w struct {
		Env  map[string]string `yaml:"env"`
		Jobs map[string]struct {
			Env   map[string]string `yaml:"env"`
			Steps []flashStep       `yaml:"steps"`
		} `yaml:"jobs"`
	}
	f := byPath(t, mustFiles(t, p), ".github/workflows/arata-collect.yml")
	if err := yaml.Unmarshal(f.Body, &w); err != nil {
		t.Fatal(err)
	}
	job := w.Jobs["collect"]
	env := map[string]string{}
	for k, v := range w.Env {
		env[k] = v
	}
	for k, v := range job.Env {
		env[k] = v
	}
	return env, job.Steps
}

// --flash の取得のワークフロー: 判定 → 通知 → 取得 → 知らせ の順。Slack のトークンは通知と知らせの step だけに渡る (ADR 0082 の 4 節)。
func TestFlashWorkflowShape(t *testing.T) {
	p := exampleParams()
	p.Flash = true
	env, steps := collectSteps(t, p)
	var ids []string
	byID := map[string]flashStep{}
	for _, s := range steps {
		ids = append(ids, s.ID)
		byID[s.ID] = s
	}
	if got := strings.Join(ids, ","); got != "checkout,install,secrets,aws,aws-config,hourly,notify,collect,alert" {
		t.Fatalf("steps: %s", got)
	}
	for k, v := range env {
		if strings.Contains(v, "secrets.") {
			t.Errorf("job env %s must not take a secret: %s", k, v)
		}
	}
	for _, s := range steps {
		for k, v := range s.Env {
			if strings.Contains(v, "secrets."+botTokenSecret) && s.ID != "notify" && s.ID != "alert" {
				t.Errorf("step %s must not take the Slack token (%s)", s.ID, k)
			}
		}
	}
	if !strings.Contains(byID["notify"].Env[botTokenSecret], "secrets."+botTokenSecret) {
		t.Errorf("notify must take the token: %v", byID["notify"].Env)
	}
	if !strings.Contains(byID["hourly"].Run, "--profile hourly") || byID["hourly"].Timeout != 15 {
		t.Errorf("hourly: %+v", byID["hourly"])
	}
	if !strings.Contains(byID["notify"].If, "steps.hourly.outputs.reported == 'true'") || byID["notify"].Timeout != 5 {
		t.Errorf("notify must run only after a report: %+v", byID["notify"])
	}
	// 判定・通知が失敗しても取得は動く。取得の時間切れは残り (判定 15 分・通知 5 分の後)
	if !strings.HasPrefix(byID["collect"].If, "always()") || byID["collect"].Timeout != 35 {
		t.Errorf("collect: %+v", byID["collect"])
	}
	// 知らせは、通知が失敗したときだけ (判定・取得の失敗では送らない)
	if a := byID["alert"].If; !strings.Contains(a, "steps.notify.outcome == 'failure'") || !strings.Contains(a, "github.event_name == 'schedule'") {
		t.Errorf("alert: %s", a)
	}

	// 知らせのチャンネルを使わない一式では、知らせの step を持たない
	p.AlertChannel = NoAlert
	_, steps = collectSteps(t, p)
	for _, s := range steps {
		if s.ID == "alert" {
			t.Fatal("no alert step without an alert channel")
		}
	}
}

// repo check --flash は、各アカウントの arata.yaml の profiles.hourly に min_severity があることを確かめる (ADR 0082 の 5 節)。
// 無ければ ng にして、足す行をそのまま出す (黙って medium を毎時に記録・送らないように、PR で止める)。
func TestCheckFlashProfile(t *testing.T) {
	p := exampleParams()
	p.Flash = true
	dir := t.TempDir()
	if _, err := Apply(dir, mustFiles(t, p), false); err != nil {
		t.Fatal(err)
	}
	run := func() *CheckOutput {
		t.Helper()
		o := NewCheck()
		if err := CheckFiles(o, dir, p, mustFiles(t, p)); err != nil {
			t.Fatal(err)
		}
		return o
	}
	o := run()
	if !o.OK || len(rowsOf(o, ItemFlash, CheckOK)) != 2 {
		t.Fatalf("the fresh set passes: %+v", o.Rows)
	}
	prod := filepath.Join(dir, "aws", "prod", "arata.yaml")
	edit(t, prod, "\n    min_severity: high ", "\n    # min_severity: high ")
	o = run()
	ng := rowsOf(o, ItemFlash, CheckNG)
	if o.OK || len(ng) != 1 || ng[0].Target != "prod" || ng[0].Code != "REPO_FLASH_PROFILE" {
		t.Fatalf("%+v", o.Rows)
	}
	if strings.Join(ng[0].Fix, "\n") != "profiles:\n  hourly:\n    min_severity: high" {
		t.Fatalf("fix: %q", ng[0].Fix)
	}
	// hourly のプロファイルが無い
	mustWrite(t, prod, "name: prod\nprofiles:\n  daily: {window: 24h, checks: [root_usage]}\n")
	if ng := rowsOf(run(), ItemFlash, CheckNG); len(ng) != 1 || !strings.Contains(ng[0].Detail, "profiles.hourly") {
		t.Fatalf("%+v", ng)
	}
	// 読めない YAML は中身を出さずに ng
	mustWrite(t, prod, "profiles: [\n")
	if ng := rowsOf(run(), ItemFlash, CheckNG); len(ng) != 1 {
		t.Fatalf("%+v", ng)
	}
	// critical も利用者の判断として通す
	mustWrite(t, prod, "profiles:\n  hourly: {window: 1h, min_severity: critical, checks: [root_usage]}\n")
	if ok := rowsOf(run(), ItemFlash, CheckOK); len(ok) != 2 {
		t.Fatalf("%+v", ok)
	}
	// --flash でなければ見ない
	p.Flash = false
	if rows := rowsOf(run(), ItemFlash, CheckNG); len(rows) != 0 {
		t.Fatalf("%+v", rows)
	}
}

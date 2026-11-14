package repoinit

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/jsonschema/schematest"
)

// 例の値はすべて架空 (CLAUDE.md「顧客の情報を書かない」)。
func exampleParams() Params {
	return Params{
		Owner: "example-org", Repo: "security-audit", Accounts: []string{"prod", "staging"},
		AuditAccount: "111122223333", StoreBucket: "example-arata-store", Region: "ap-northeast-1",
		Schedule: true, Version: "v0.15.0",
	}
}

var exampleDay = time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC)

func mustFiles(t testing.TB, p Params) []File {
	t.Helper()
	files, err := Files(p, checks.NewRegistry(), exampleDay)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func byPath(t testing.TB, files []File, path string) File {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no file %s", path)
	return File{}
}

// TestValidateRejectsValuesOutsideTheShapes は、引数の形を固定する (ADR 0059: 値は YAML・HCL・シェルの中に入るので、形で絞る)。
func TestValidateRejectsValuesOutsideTheShapes(t *testing.T) {
	if err := exampleParams().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Params){
		"owner empty":            func(p *Params) { p.Owner = "" },
		"owner slash":            func(p *Params) { p.Owner = "example-org/x" },
		"owner leading hyphen":   func(p *Params) { p.Owner = "-example" },
		"owner quote":            func(p *Params) { p.Owner = `a"b` },
		"owner too long":         func(p *Params) { p.Owner = strings.Repeat("a", 40) },
		"repo empty":             func(p *Params) { p.Repo = "" },
		"repo dot":               func(p *Params) { p.Repo = ".." },
		"repo space":             func(p *Params) { p.Repo = "a b" },
		"repo expression":        func(p *Params) { p.Repo = "${{x}}" },
		"repo newline":           func(p *Params) { p.Repo = "a\nb" },
		"no accounts":            func(p *Params) { p.Accounts = nil },
		"account upper":          func(p *Params) { p.Accounts = []string{"Prod"} },
		"account digit first":    func(p *Params) { p.Accounts = []string{"1e3"} },
		"account yaml word":      func(p *Params) { p.Accounts = []string{"null"} },
		"account yaml bool":      func(p *Params) { p.Accounts = []string{"prod", "on"} },
		"account empty":          func(p *Params) { p.Accounts = []string{"prod", ""} },
		"account dup":            func(p *Params) { p.Accounts = []string{"prod", "prod"} },
		"account slash":          func(p *Params) { p.Accounts = []string{"a/b"} },
		"account comma":          func(p *Params) { p.Accounts = []string{"a,b"} },
		"account too long":       func(p *Params) { p.Accounts = []string{"a" + strings.Repeat("b", 40)} },
		"too many accounts":      func(p *Params) { p.Accounts = make([]string, 101) },
		"audit account missing":  func(p *Params) { p.AuditAccount = "" },
		"audit account short":    func(p *Params) { p.AuditAccount = "1234" },
		"bucket upper":           func(p *Params) { p.StoreBucket = "Example" },
		"bucket url":             func(p *Params) { p.StoreBucket = "s3://example-arata-store" },
		"bucket dots":            func(p *Params) { p.StoreBucket = "a..b" },
		"bucket short":           func(p *Params) { p.StoreBucket = "ab" },
		"bucket slash":           func(p *Params) { p.StoreBucket = "example/prefix" },
		"region empty":           func(p *Params) { p.Region = "" },
		"region upper":           func(p *Params) { p.Region = "AP-NORTHEAST-1" },
		"region junk":            func(p *Params) { p.Region = "ap-northeast-1; rm" },
		"version dev":            func(p *Params) { p.Version = "dev" },
		"version without v":      func(p *Params) { p.Version = "0.15.0" },
		"version pre-release":    func(p *Params) { p.Version = "v0.15.0-rc1" },
		"version with expansion": func(p *Params) { p.Version = "v0.15.$(id)" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := exampleParams()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("Validate accepted %+v", p)
			}
			if files, err := Files(p, checks.NewRegistry(), exampleDay); err == nil || files != nil {
				t.Fatalf("Files must return nothing for invalid params")
			}
		})
	}
	for _, ok := range []func(*Params){
		func(p *Params) { p.AuditAccount = config.AuditAccountNone },
		func(p *Params) { p.Region = "us-gov-west-1" },
		func(p *Params) { p.Repo = ".github" },
		func(p *Params) { p.Accounts = []string{"a"} },
	} {
		p := exampleParams()
		ok(&p)
		if err := p.Validate(); err != nil {
			t.Errorf("Validate rejected %+v: %v", p, err)
		}
	}
}

type workflowDoc struct {
	On struct {
		Schedule         []struct{ Cron string } `yaml:"schedule"`
		WorkflowDispatch struct {
			Inputs map[string]struct {
				Options []string `yaml:"options"`
			} `yaml:"inputs"`
		} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Env  map[string]string `yaml:"env"`
	Jobs map[string]struct {
		Environment string `yaml:"environment"`
		Strategy    struct {
			Matrix struct {
				Account []string `yaml:"account"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Env map[string]string `yaml:"env"`
	} `yaml:"jobs"`
}

func parseWorkflow(t testing.TB, f File) workflowDoc {
	t.Helper()
	var w workflowDoc
	if err := yaml.Unmarshal(f.Body, &w); err != nil {
		t.Fatalf("%s: %v", f.Path, err)
	}
	return w
}

var workflowPaths = []string{
	".github/workflows/arata-audit.yml", ".github/workflows/arata-triage.yml",
	".github/workflows/arata-notify-test.yml", ".github/workflows/arata-check.yml",
}

// TestFilesFillInTheArguments は、引数の値が決まった場所に入ることと、印 (@@…@@) が残らないことを確かめる。
func TestFilesFillInTheArguments(t *testing.T) {
	p := exampleParams()
	files := mustFiles(t, p)
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
		if bytes.Contains(f.Body, []byte("@@")) {
			t.Errorf("%s: a marker is left", f.Path)
		}
		if len(f.Body) == 0 || f.Body[len(f.Body)-1] != '\n' {
			t.Errorf("%s: must end with a newline", f.Path)
		}
	}
	want := []string{
		".github/scripts/arata-secret-check.sh", ".github/scripts/arata-slack-method.sh",
		".github/workflows/arata-audit.yml", ".github/workflows/arata-check.yml", ".github/workflows/arata-notify-test.yml", ".github/workflows/arata-triage.yml",
		".gitignore", "README.md",
		"aws/prod/allowlist.yaml", "aws/prod/arata.yaml", "aws/prod/aratam.yaml",
		"aws/staging/allowlist.yaml", "aws/staging/arata.yaml", "aws/staging/aratam.yaml",
		"github/.terraform.lock.hcl", "github/main.tf", "github/secrets/.terraform.lock.hcl", "github/secrets/main.tf",
	}
	sort.Strings(paths)
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("files:\n%s", strings.Join(paths, "\n"))
	}
	for _, path := range workflowPaths {
		w := parseWorkflow(t, byPath(t, files, path))
		if w.Env["ARATA_VERSION"] != p.Version {
			t.Errorf("%s: ARATA_VERSION = %q", path, w.Env["ARATA_VERSION"])
		}
	}
	audit := parseWorkflow(t, byPath(t, files, workflowPaths[0]))
	job := audit.Jobs["audit"]
	if strings.Join(job.Strategy.Matrix.Account, ",") != "prod,staging" || job.Environment != "audit" {
		t.Errorf("audit job: %+v", job)
	}
	if job.Env["ARATA_STORE_URL"] != "s3://example-arata-store/${{ matrix.account }}" || audit.Env["AWS_REGION"] != "ap-northeast-1" {
		t.Errorf("store url %q region %q", job.Env["ARATA_STORE_URL"], audit.Env["AWS_REGION"])
	}
	for _, path := range workflowPaths[1:3] {
		if got := parseWorkflow(t, byPath(t, files, path)).On.WorkflowDispatch.Inputs["account"].Options; strings.Join(got, ",") != "prod,staging" {
			t.Errorf("%s: account options %v", path, got)
		}
	}
	for _, f := range files {
		if f.Mode != 0o755 && f.Mode != 0o644 {
			t.Errorf("%s: mode %o", f.Path, f.Mode)
		}
		if exec := strings.HasSuffix(f.Path, ".sh"); exec != (f.Mode == 0o755) {
			t.Errorf("%s: mode %o", f.Path, f.Mode)
		}
		if seed := strings.HasPrefix(f.Path, "aws/"); seed != (f.Kind == Seed) {
			t.Errorf("%s: kind %v", f.Path, f.Kind)
		}
	}
	tf := string(byPath(t, files, "github/main.tf").Body)
	for _, s := range []string{`owner       = "example-org"`, `repository  = "security-audit"`, `version = "= ` + ProviderVersion + `"`} {
		if !strings.Contains(tf, s) {
			t.Errorf("github/main.tf lacks %q", s)
		}
	}
	readme := string(byPath(t, files, "README.md").Body)
	if !strings.Contains(readme, "arata repo init --owner example-org --repo security-audit --accounts prod,staging --audit-account 111122223333 --store-bucket example-arata-store --region ap-northeast-1 --schedule --out .\n") {
		t.Errorf("README must show the command that reproduces this set:\n%s", readme[:600])
	}
}

// TestScheduleIsOptIn は、--schedule を付けないと定時が入らないことを確かめる (導入の流れが済んでから PR で入れる)。
func TestScheduleIsOptIn(t *testing.T) {
	p := exampleParams()
	on := parseWorkflow(t, byPath(t, mustFiles(t, p), workflowPaths[0]))
	if len(on.On.Schedule) != 2 {
		t.Fatalf("with --schedule: %+v", on.On.Schedule)
	}
	p.Schedule = false
	files := mustFiles(t, p)
	off := parseWorkflow(t, byPath(t, files, workflowPaths[0]))
	if len(off.On.Schedule) != 0 || len(off.On.WorkflowDispatch.Inputs) == 0 {
		t.Fatalf("without --schedule the audit must only run by hand: %+v", off.On)
	}
	if readme := string(byPath(t, files, "README.md").Body); strings.Contains(readme, "--schedule --out") {
		t.Error("README must show the command without --schedule")
	}
	// 変わるのは監査のワークフローと README だけ
	a, b := mustFiles(t, exampleParams()), files
	for i := range a {
		same := bytes.Equal(a[i].Body, b[i].Body)
		if changes := a[i].Path == workflowPaths[0] || a[i].Path == "README.md"; same == changes {
			t.Errorf("%s: same=%v", a[i].Path, same)
		}
	}
}

// TestSeedsLoad は、アカウントごとの設定の雛形が、そのまま読み込めて引数の値を持つことを確かめる。
func TestSeedsLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := Apply(dir, mustFiles(t, exampleParams()), false); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"prod", "staging"} {
		cfg, err := config.Load(filepath.Join(dir, "aws", account, "arata.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Name != account || cfg.Store.Bucket != "example-arata-store" || cfg.Store.Prefix != account || cfg.AWS.Profile != "arata-audit" || cfg.AWS.Region != "ap-northeast-1" {
			t.Errorf("%s: %+v %+v %+v", account, cfg.Name, cfg.Store, cfg.AWS)
		}
		al, err := os.ReadFile(filepath.Join(dir, "aws", account, "allowlist.yaml"))
		if err != nil || !strings.Contains(string(al), `account: "111122223333"`) || !strings.Contains(string(al), "approved_at: 2026-11-14") {
			t.Errorf("%s allowlist: %v\n%s", account, err, al)
		}
		am, err := os.ReadFile(filepath.Join(dir, "aws", account, "aratam.yaml"))
		if err != nil || !strings.Contains(string(am), "\nname: "+account+" ") {
			t.Errorf("%s aratam.yaml: %v", account, err)
		}
	}
	// 外から監査しない (none) なら、既知リストは書かない (config init と同じ)
	p := exampleParams()
	p.AuditAccount = config.AuditAccountNone
	for _, f := range mustFiles(t, p) {
		if strings.HasSuffix(f.Path, "allowlist.yaml") {
			t.Errorf("none must not write %s", f.Path)
		}
	}
}

var secretRef = regexp.MustCompile(`secrets\.([A-Z][A-Z0-9_]*)`)

// TestSecretBoxesMatchTheWorkflows は、秘密の箱の名前が、ワークフローが使う秘密の名前と同じであることを固定する。
func TestSecretBoxesMatchTheWorkflows(t *testing.T) {
	files := mustFiles(t, exampleParams())
	used := map[string]bool{}
	for _, path := range workflowPaths {
		body := byPath(t, files, path).Body
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range secretRef.FindAllStringSubmatch(line, -1) {
				used[m[1]] = true
			}
		}
	}
	var names []string
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join(SecretNames, ",") {
		t.Fatalf("workflows use %v, boxes are %v", names, SecretNames)
	}
	tf := string(byPath(t, files, "github/secrets/main.tf").Body)
	for _, n := range SecretNames {
		if !strings.Contains(tf, `    "`+n+`",`+"\n") {
			t.Errorf("github/secrets/main.tf lacks %s", n)
		}
	}
	// 仮の値は 1 か所で決め、Terraform と検査のスクリプトに同じ文字列が入る
	script := string(byPath(t, files, ".github/scripts/arata-secret-check.sh").Body)
	if !strings.Contains(tf, `placeholder = "`+Placeholder+`"`) || !strings.Contains(script, "PLACEHOLDER='"+Placeholder+"'") {
		t.Error("the placeholder must be the same string in the Terraform and in the script")
	}
	// 仮の値は、どの秘密の形にも合わない
	for _, bad := range []string{"arn:", "{", "http", "xox", " ", "'", `"`, "$"} {
		if strings.Contains(Placeholder, bad) {
			t.Errorf("placeholder %q must not look like a real value (%q)", Placeholder, bad)
		}
	}
}

// TestLockFilePinsTheProviderVersion は、lock と宣言の provider の版が同じで、4 つの環境のハッシュを持つことを固定する。
func TestLockFilePinsTheProviderVersion(t *testing.T) {
	files := mustFiles(t, exampleParams())
	lock := byPath(t, files, "github/.terraform.lock.hcl")
	if !bytes.Equal(lock.Body, byPath(t, files, "github/secrets/.terraform.lock.hcl").Body) {
		t.Error("the two roots must share the same lock")
	}
	s := string(lock.Body)
	if !strings.Contains(s, `version     = "`+ProviderVersion+`"`) || !strings.Contains(s, `constraints = "`+ProviderVersion+`"`) {
		t.Errorf("lock does not pin %s", ProviderVersion)
	}
	if n := strings.Count(s, `"h1:`); n != 4 {
		t.Errorf("lock must have the hashes of 4 platforms (linux/darwin x amd64/arm64), got %d", n)
	}
}

func TestApplyNeverOverwritesByDefault(t *testing.T) {
	dir := t.TempDir()
	files := mustFiles(t, exampleParams())
	res, err := Apply(dir, files, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Action != Created {
			t.Errorf("%s: %s", r.Path, r.Action)
		}
	}
	if st, err := os.Stat(filepath.Join(dir, ".github/scripts/arata-slack-method.sh")); err != nil || st.Mode().Perm()&0o111 == 0 {
		t.Errorf("the script must be executable: %v", err)
	}
	// 2 回目は何も変えない
	res, err = Apply(dir, files, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if want := map[Kind]Action{Generated: Unchanged, Seed: Kept}[r.Kind]; r.Action != want {
			t.Errorf("%s: %s", r.Path, r.Action)
		}
	}
	// 生成物を手で直す・設定を育てる
	wf := filepath.Join(dir, workflowPaths[0])
	seed := filepath.Join(dir, "aws/prod/arata.yaml")
	for _, p := range []string{wf, seed} {
		if err := os.WriteFile(p, []byte("edited\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err = Apply(dir, files, false)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Action{}
	for _, r := range res {
		got[r.Path] = r.Action
	}
	if got[workflowPaths[0]] != Differs || got["aws/prod/arata.yaml"] != Kept {
		t.Fatalf("%v", got)
	}
	for _, p := range []string{wf, seed} {
		if b, _ := os.ReadFile(p); string(b) != "edited\n" {
			t.Errorf("%s was overwritten without --force", p)
		}
	}
	// --force は生成物だけを書き直す。aws/ は書き直さない
	res, err = Apply(dir, files, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		got[r.Path] = r.Action
	}
	if got[workflowPaths[0]] != Overwritten || got["aws/prod/arata.yaml"] != Kept {
		t.Fatalf("%v", got)
	}
	if b, _ := os.ReadFile(wf); !bytes.Equal(b, byPath(t, files, workflowPaths[0]).Body) {
		t.Error("--force must rewrite the workflow")
	}
	if b, _ := os.ReadFile(seed); string(b) != "edited\n" {
		t.Error("--force must not rewrite aws/")
	}
}

// TestApplyAddsAnAccount は、アカウントを足したときに、新しい aws/<名前>/ だけが作られることを確かめる。
func TestApplyAddsAnAccount(t *testing.T) {
	dir := t.TempDir()
	if _, err := Apply(dir, mustFiles(t, exampleParams()), false); err != nil {
		t.Fatal(err)
	}
	p := exampleParams()
	p.Accounts = append(p.Accounts, "dev")
	res, err := Apply(dir, mustFiles(t, p), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		switch {
		case strings.HasPrefix(r.Path, "aws/dev/"):
			if r.Action != Created {
				t.Errorf("%s: %s", r.Path, r.Action)
			}
		case r.Action == Created || r.Action == Overwritten:
			t.Errorf("%s: %s", r.Path, r.Action)
		}
	}
}

// TestApplyRefusesLinksAndOddFiles は、書く先がふつうのファイルでないときに、何も書かずに止まることを確かめる
// (シンボリックリンクをたどって、書き出す先のディレクトリの外に書かない)。
func TestApplyRefusesLinksAndOddFiles(t *testing.T) {
	files := mustFiles(t, exampleParams())
	t.Run("file link", func(t *testing.T) {
		dir, outside := t.TempDir(), filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("keep\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "README.md")); err != nil {
			t.Skip(err)
		}
		if _, err := Apply(dir, files, true); err == nil {
			t.Fatal("Apply followed a symlink")
		}
		if b, _ := os.ReadFile(outside); string(b) != "keep\n" {
			t.Fatal("the file outside was overwritten")
		}
		if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err == nil {
			t.Fatal("nothing may be written when a target is refused")
		}
	})
	t.Run("directory link", func(t *testing.T) {
		dir, outside := t.TempDir(), t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "github")); err != nil {
			t.Skip(err)
		}
		if _, err := Apply(dir, files, true); err == nil {
			t.Fatal("Apply followed a directory symlink")
		}
		if ents, _ := os.ReadDir(outside); len(ents) != 0 {
			t.Fatal("files were written outside")
		}
	})
	t.Run("directory in place of a file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "README.md"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Apply(dir, files, true); err == nil {
			t.Fatal("Apply accepted a directory in place of a file")
		}
	})
}

func TestDiffReportsEachGeneratedFile(t *testing.T) {
	dir := t.TempDir()
	files := mustFiles(t, exampleParams())
	out, err := Diff(dir, files)
	if err != nil {
		t.Fatal(err)
	}
	if out.OK || out.Schema != DiffSchema || out.SchemaVersion != DiffSchemaVersion {
		t.Fatalf("%+v", out)
	}
	for _, f := range out.Files {
		if f.Status != StatusMissing {
			t.Errorf("%s: %s", f.Path, f.Status)
		}
	}
	if _, err := Apply(dir, files, false); err != nil {
		t.Fatal(err)
	}
	if out, err = Diff(dir, files); err != nil || !out.OK {
		t.Fatalf("a fresh set must have no diff: %v %+v", err, out)
	}
	// 育てた設定は差にしない。生成物の直し・消えたファイル・この版に無い arata- のファイルは差にする
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "aws/prod/arata.yaml"), []byte("name: grown\n"), 0o644))
	if out, err = Diff(dir, files); err != nil || !out.OK {
		t.Fatalf("editing aws/ must not be a diff: %v", err)
	}
	wf := filepath.Join(dir, workflowPaths[0])
	b, _ := os.ReadFile(wf)
	must(os.WriteFile(wf, bytes.Replace(b, []byte("ARATA_VERSION: v0.15.0"), []byte("ARATA_VERSION: v0.14.0"), 1), 0o644))
	must(os.Remove(filepath.Join(dir, ".gitignore")))
	must(os.Remove(filepath.Join(dir, "aws/staging/aratam.yaml")))
	must(os.WriteFile(filepath.Join(dir, ".github/workflows/arata-old.yml"), []byte("name: old\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, ".github/workflows/ci.yml"), []byte("name: ci\n"), 0o644))
	out, err = Diff(dir, files)
	must(err)
	got := map[string]string{}
	for _, f := range out.Files {
		if f.Status != StatusSame && f.Status != StatusPresent {
			got[f.Path] = f.Status
		}
	}
	want := map[string]string{
		workflowPaths[0]: StatusDiffers, ".gitignore": StatusMissing, "aws/staging/aratam.yaml": StatusMissing,
		".github/workflows/arata-old.yml": StatusExtra,
	}
	if len(got) != len(want) || out.OK {
		t.Fatalf("got %v", got)
	}
	for p, s := range want {
		if got[p] != s {
			t.Errorf("%s: %q, want %q", p, got[p], s)
		}
	}
	var text bytes.Buffer
	must(WriteDiff(&text, out))
	for _, s := range []string{"-  ARATA_VERSION: v0.14.0", "+  ARATA_VERSION: v0.15.0", ".github/workflows/arata-old.yml"} {
		if !strings.Contains(text.String(), s) {
			t.Errorf("text diff lacks %q:\n%s", s, text.String())
		}
	}
}

var update = flag.Bool("update", false, "ゴールデン (schemas/ と examples/audit-repo) を作り直す")

// repo init --diff --format json の型から作ったスキーマを、schemas/ のファイルで固定する (ADR 0054)。
func TestDiffSchemaIsFixed(t *testing.T) {
	schematest.Golden(t, schematest.Spec{Name: DiffSchema, Version: DiffSchemaVersion, Type: DiffOutput{}, Versioned: true,
		Description: "arata repo init --diff --format json の出力。今ある一式と、この版の arata が書き出す一式を、ファイルごとに比べた結果"}, *update)
}

// exampleDir は見本。決まった架空の引数 (exampleParams) での出力そのもの (ADR 0059: 見本と雛形を二重に持たない)。
const exampleDir = "../../examples/audit-repo"

// TestExampleIsTheOutput は、見本 (examples/audit-repo) が、雛形から作った一式と 1 バイトも違わないことを固定する。
// 雛形 (templates/) が正で、見本を手で直すとここで落ちる。雛形を直したら -update で見本を作り直し、PR に理由を書く。
// 見本のワークフローの中身 (秘密の渡し方、run のスクリプトなど) は examples/github-actions のテストが確かめる。
func TestExampleIsTheOutput(t *testing.T) {
	files := mustFiles(t, exampleParams())
	if *update {
		if err := os.RemoveAll(exampleDir); err != nil {
			t.Fatal(err)
		}
		if _, err := Apply(exampleDir, files, true); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]File{}
	for _, f := range files {
		want[f.Path] = f
	}
	err := filepath.WalkDir(exampleDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(exampleDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, ok := want[rel]
		if !ok {
			t.Errorf("examples/audit-repo/%s is not part of the set (the example must be exactly the output)", rel)
			return nil
		}
		delete(want, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !bytes.Equal(b, f.Body) {
			t.Errorf("examples/audit-repo/%s differs from the output of the templates (edit internal/repoinit/templates, then run this test with -update)", rel)
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		if exec := st.Mode().Perm()&0o100 != 0; exec != (f.Mode&0o100 != 0) {
			t.Errorf("examples/audit-repo/%s: executable=%v", rel, exec)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for p := range want {
		t.Errorf("examples/audit-repo/%s is missing (run this test with -update)", p)
	}
}

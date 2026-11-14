package repoinit

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/config"
)

// FuzzFiles は、引数 (利用者が打つ値。YAML・HCL・シェル・Markdown の中に入る) の形の規則を確かめる (ADR 0041・0059)。
//
//   - 形を通らない引数では、ファイルを 1 つも返さない
//   - 形を通った引数なら、ワークフローは YAML として読め、matrix と選択肢のアカウントは引数と同じ並びで、
//     版・リージョン・ストアの URL は決まった場所に入る
//   - 引数の値は、引用符・改行・式 (${{、$( ) を生成物に持ち込まない
//   - アカウントごとの設定の雛形は、name が引数の名前のままで読める
func FuzzFiles(f *testing.F) {
	f.Add("example-org", "security-audit", "prod,staging", "111122223333", "example-arata-store", "ap-northeast-1", "v0.15.0", true)
	f.Add("a", "b", "x", "none", "abc", "us-gov-west-1", "v1.0.0", false)
	f.Add("example-org", "x\"\n${{ secrets.X }}", "prod", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false)
	f.Add("example-org", "repo", "true,null", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false)
	f.Add("example-org", "repo", "prod", "none", "example-arata-store/$(id)", "ap-northeast-1\n  evil: 1", "v0.15.0`id`", false)
	f.Add("-a", "..", "1e3,0x10", "123", "a..b", "AP", "dev", true)
	reg := checks.NewRegistry()
	f.Fuzz(func(t *testing.T, owner, repo, accounts, auditAccount, bucket, region, version string, schedule bool) {
		p := Params{Owner: owner, Repo: repo, AuditAccount: auditAccount, StoreBucket: bucket, Region: region, Version: version, Schedule: schedule}
		if accounts != "" {
			p.Accounts = strings.Split(accounts, ",")
		}
		files, err := Files(p, reg, exampleDay)
		if p.Validate() != nil {
			if err == nil || files != nil {
				t.Fatalf("Files returned a set for invalid params %+v", p)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid params %+v: %v", p, err)
		}
		// 形を通った値は、解釈される文字を持たない
		for _, v := range append([]string{owner, repo, bucket, region, version, auditAccount}, p.Accounts...) {
			if v == "" || strings.ContainsAny(v, "\"'`$ \t\r\n{}()[]<>;&|\\#:,*?!~%@=+/") || !utf8.ValidString(v) {
				t.Fatalf("Validate accepted %q", v)
			}
		}
		for _, file := range files {
			if bytes.Contains(file.Body, []byte("@@")) {
				t.Fatalf("%s: a marker is left", file.Path)
			}
		}
		for _, path := range workflowPaths {
			w := parseWorkflow(t, byPath(t, files, path))
			if w.Env["ARATA_VERSION"] != version {
				t.Fatalf("%s: ARATA_VERSION %q", path, w.Env["ARATA_VERSION"])
			}
		}
		audit := parseWorkflow(t, byPath(t, files, workflowPaths[0]))
		job := audit.Jobs["audit"]
		if strings.Join(job.Strategy.Matrix.Account, ",") != accounts || job.Environment != Environment ||
			job.Env["ARATA_STORE_URL"] != "s3://"+bucket+"/${{ matrix.account }}" || audit.Env["AWS_REGION"] != region || (len(audit.On.Schedule) > 0) != schedule {
			t.Fatalf("audit workflow does not carry the arguments: %+v %+v", job, audit.Env)
		}
		for _, path := range workflowPaths[1:3] {
			if got := parseWorkflow(t, byPath(t, files, path)).On.WorkflowDispatch.Inputs["account"].Options; strings.Join(got, ",") != accounts {
				t.Fatalf("%s: options %v", path, got)
			}
		}
		for _, a := range p.Accounts {
			var cfg struct {
				Name  string `yaml:"name"`
				Store string `yaml:"store"`
				AWS   struct {
					Region  string `yaml:"region"`
					Profile string `yaml:"profile"`
				} `yaml:"aws"`
				AuditAccount string `yaml:"audit_account"`
			}
			if err := yaml.Unmarshal(byPath(t, files, "aws/"+a+"/arata.yaml").Body, &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Name != a || cfg.Store != "s3://"+bucket+"/"+a || cfg.AWS.Region != region || cfg.AWS.Profile != AuditProfile || cfg.AuditAccount != auditAccount {
				t.Fatalf("aws/%s/arata.yaml: %+v", a, cfg)
			}
			var am struct {
				Name string `yaml:"name"`
			}
			if err := yaml.Unmarshal(byPath(t, files, "aws/"+a+"/aratam.yaml").Body, &am); err != nil || am.Name != a {
				t.Fatalf("aws/%s/aratam.yaml: %q %v", a, am.Name, err)
			}
		}
		if auditAccount != config.AuditAccountNone {
			var al struct {
				Principals []struct {
					Account string `yaml:"account"`
				} `yaml:"principals"`
			}
			if err := yaml.Unmarshal(byPath(t, files, "aws/"+p.Accounts[0]+"/allowlist.yaml").Body, &al); err != nil || len(al.Principals) != 1 || al.Principals[0].Account != auditAccount {
				t.Fatalf("allowlist: %+v %v", al, err)
			}
		}
	})
}

// FuzzLineDiff は、今あるファイル (利用者のもの。中身は信用できない) との行の差分の規則を確かめる。
//
//   - 出す行に制御文字 (端末の制御列) と不正な UTF-8 が残らない
//   - 同じ中身なら何も出さない
//   - 「-」と「+」の行の数は、それぞれ元の行数・新しい行数を超えない
func FuzzLineDiff(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nx\nc\n")
	f.Add("", "new\n")
	f.Add("old\x1b[2J\n", "new\n")
	f.Add("\xff\xfe\n", "ok\n")
	f.Add("same\n", "same\n")
	f.Fuzz(func(t *testing.T, oldText, newText string) {
		if len(oldText) > 1<<12 || len(newText) > 1<<12 {
			return
		}
		lines := lineDiff(oldText, newText)
		if oldText == newText && len(lines) != 0 {
			t.Fatalf("same text gave %q", lines)
		}
		minus, plus := 0, 0
		for _, l := range lines {
			if !utf8.ValidString(l) || strings.IndexFunc(l, isControl) >= 0 || strings.Contains(l, "\n") {
				t.Fatalf("unsafe line %q", l)
			}
			switch {
			case strings.HasPrefix(l, "-"):
				minus++
			case strings.HasPrefix(l, "+"):
				plus++
			}
		}
		if minus > len(splitLines(oldText)) || plus > len(splitLines(newText)) {
			t.Fatalf("-%d +%d for %d and %d lines", minus, plus, len(splitLines(oldText)), len(splitLines(newText)))
		}
		if p := printable(oldText); !utf8.ValidString(p) || strings.IndexFunc(p, isControl) >= 0 {
			t.Fatalf("printable left %q", p)
		}
	})
}

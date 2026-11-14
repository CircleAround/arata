package repoinit

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
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
	f.Add("example-org", "security-audit", "prod,staging", "111122223333", "example-arata-store", "ap-northeast-1", "v0.15.0", true, "C0123456782", "prod=C0123456789,staging=C0123456781", "prod=C0123456780,staging=same")
	f.Add("a", "b", "x", "none", "abc", "us-gov-west-1", "v1.0.0", false, "none", "", "")
	f.Add("example-org", "x\"\n${{ secrets.X }}", "prod", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false, "none", "", "")
	f.Add("example-org", "repo", "true,null", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false, "none", "", "")
	f.Add("example-org", "repo", "prod", "none", "example-arata-store/$(id)", "ap-northeast-1\n  evil: 1", "v0.15.0`id`", false, "none", "", "")
	f.Add("-a", "..", "1e3,0x10", "123", "a..b", "AP", "dev", true, "", "", "")
	f.Add("example-org", "repo", "prod", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false, "C0123456782\n          EVIL: ${{ secrets.X }}", "prod=C0123456789\"", "prod=same,prod=same")
	f.Add("example-org", "repo", "prod", "none", "example-arata-store", "ap-northeast-1", "v0.15.0", false, "#alerts", "prod=xoxb-not-a-channel", "dev=same")
	reg := checks.NewRegistry()
	f.Fuzz(func(t *testing.T, owner, repo, accounts, auditAccount, bucket, region, version string, schedule bool, alert, channels, urgent string) {
		p := Params{Owner: owner, Repo: repo, AuditAccount: auditAccount, StoreBucket: bucket, Region: region, Version: version, Schedule: schedule, AlertChannel: alert}
		if accounts != "" {
			p.Accounts = strings.Split(accounts, ",")
		}
		var err1, err2 error
		p.Channels, err1 = ParseAssignments("--channel", channels)
		p.UrgentChannels, err2 = ParseAssignments("--urgent-channel", urgent)
		if err1 != nil || err2 != nil {
			// 組の形でない引数は、コマンドがここで止める。エラーに値を写さない
			for _, err := range []error{err1, err2} {
				if err != nil && (strings.ContainsAny(err.Error(), "\n\x1b") || len(err.Error()) > 300) {
					t.Fatalf("unsafe error %q", err)
				}
			}
			return
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
		values := append([]string{owner, repo, bucket, region, version, auditAccount, alert}, p.Accounts...)
		for _, m := range []map[string]string{p.Channels, p.UrgentChannels} {
			for _, v := range m {
				values = append(values, v)
			}
		}
		for _, v := range values {
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
		// どの引数でも、ワークフローが参照する秘密は同じ 3 つで、名前を式で作る参照は無い (ADR 0060)。
		// 知らせのチャンネルは、none なら どの生成物にも入らず、ID ならワークフローの決まった場所にだけ入る
		used := map[string]bool{}
		for _, path := range workflowPaths {
			names, dynamic, err := WorkflowSecrets(byPath(t, files, path).Body)
			if err != nil || dynamic {
				t.Fatalf("%s: dynamic=%v err=%v", path, dynamic, err)
			}
			for _, n := range names {
				used[n] = true
			}
		}
		if len(used) != len(SecretNames) {
			t.Fatalf("workflows use %v", used)
		}
		for _, n := range SecretNames {
			if !used[n] {
				t.Fatalf("workflows do not use %s", n)
			}
		}
		for _, file := range files {
			if file.Kind == Generated && (alert == NoAlert) == bytes.Contains(file.Body, []byte("chat.postMessage")) && strings.HasSuffix(file.Path, "arata-audit.yml") {
				t.Fatalf("%s: the alert step does not follow --alert-channel %s", file.Path, alert)
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
				Name  string      `yaml:"name"`
				Slack aratamSlack `yaml:"slack"`
			}
			seed := byPath(t, files, "aws/"+a+"/aratam.yaml")
			if err := yaml.Unmarshal(seed.Body, &am); err != nil || am.Name != a {
				t.Fatalf("aws/%s/aratam.yaml: %q %v", a, am.Name, err)
			}
			// bot トークンの方式で、チャンネルは引数の値のまま。足りなければ、足りない引数が Missing に入る (空のまま書き出さない)
			wantUrgent := p.UrgentChannels[a]
			if wantUrgent == SameChannel {
				wantUrgent = ""
			}
			if am.Slack.BotTokenEnv != botTokenSecret || am.Slack.WebhookEnv != "" || am.Slack.UrgentWebhookEnv != "" || am.Slack.Channel != p.Channels[a] || am.Slack.UrgentChannel != wantUrgent {
				t.Fatalf("aws/%s/aratam.yaml: %+v", a, am.Slack)
			}
			if complete := p.Channels[a] != "" && p.UrgentChannels[a] != ""; complete != (len(seed.Missing) == 0) {
				t.Fatalf("aws/%s/aratam.yaml: missing %v", a, seed.Missing)
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

// FuzzWorkflowSecrets は、ワークフローの YAML (利用者のリポジトリのファイル) から秘密の名前を拾う規則を確かめる (ADR 0041・0060)。
//
//   - パニックしない。読めない・大きすぎる入力は、エラーにする
//   - 返す名前は、秘密の名前の形 (英大文字・数字・_) だけで、重複が無く、名前の順
//   - 拾った名前は、入力の中に (大文字と小文字を区別せずに) 現れる
func FuzzWorkflowSecrets(f *testing.F) {
	f.Add("a: ${{ secrets.FOO }}\nb: ${{ secrets[matrix.x] }}\n")
	f.Add("env:\n  A: ${{ steps.x.outputs.y == 'z' && secrets.ARATAM_SLACK_BOT_TOKEN || '' }}\n# ${{ secrets.COMMENT }}\n")
	f.Add("a: &x ${{ toJSON(secrets) }}\nb: [*x, *x]\n")
	f.Add("jobs:\n  x:\n    secrets: inherit\n")
	f.Add("a: ${{ secrets.\n  FOO }}")
	f.Add("a: [")
	f.Add("\xff\xfe: ${{ secrets.X }}")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1<<14 {
			return
		}
		names, _, err := WorkflowSecrets([]byte(body))
		if err != nil {
			if names != nil {
				t.Fatalf("names with an error: %v", names)
			}
			return
		}
		upper := strings.ToUpper(body)
		for i, n := range names {
			if !githubSecretRE.MatchString(n) || n != strings.ToUpper(n) || (i > 0 && names[i-1] >= n) {
				t.Fatalf("names %q", names)
			}
			if !strings.Contains(upper, n) {
				t.Fatalf("%q is not in the input", n)
			}
		}
	})
}

// FuzzAratamSlack は、aratam.yaml (利用者が育てるファイル) の slack の節を読む規則を確かめる (ADR 0041・0060)。
//
//   - パニックしない。エラーには、ファイルの中身を写さない
//   - 送り方は bot か webhook のどちらか。bot の項目が 1 つでも書いてあれば bot (aratam と同じ)
func FuzzAratamSlack(f *testing.F) {
	f.Add("slack:\n  bot_token_env: ARATAM_SLACK_BOT_TOKEN\n  channel: C0123456789\n")
	f.Add("slack:\n  webhook_env: ARATAM_SLACK_WEBHOOK\n")
	f.Add("slack: [1, 2]\n")
	f.Add("slack:\n  channel: {a: b}\n")
	f.Add("name: x\n")
	f.Add("\x00")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 1<<14 {
			return
		}
		s, err := readAratamSlack([]byte(body))
		if err != nil {
			if len(err.Error()) > 100 || (len(body) > 8 && strings.Contains(err.Error(), body)) {
				t.Fatalf("the error carries the input: %q", err)
			}
			return
		}
		m := s.method()
		if m != methodBot && m != methodWebhook {
			t.Fatalf("method %q", m)
		}
		if (s.BotTokenEnv != "" || s.Channel != "" || s.UrgentChannel != "") != (m == methodBot) {
			t.Fatalf("%+v is %s", s, m)
		}
	})
}

// FuzzGitHubSecretList は、GitHub の API の応答 (秘密の名前の一覧) を読む規則を確かめる (ADR 0041・0060)。
//
//   - パニックしない。JSON でない・大きすぎる応答は、API の失敗にする (足りない秘密としては出さない)
//   - 出力 (行・コマンド) に運ぶ名前は、秘密の名前の形だけ。応答の本文・鍵は、出力に現れない
//   - 出すコマンドは、gh secret set / gh secret delete に、形を確かめた名前を付けたものだけ
func FuzzGitHubSecretList(f *testing.F) {
	f.Add(`{"total_count":1,"secrets":[{"name":"ARATA_RUNNER_ROLE_ARN","updated_at":"2026-01-02T00:00:00Z"}]}`)
	f.Add(`{"secrets":[{"name":"X; rm -rf /"},{"name":"$(id)"},{"name":"a\nb"},{"name":7},{"name":"lower_ok"}]}`)
	f.Add(`{"secrets":"no"}`)
	f.Add(`[]`)
	f.Add(`<html>`)
	f.Add(``)
	cmdRE := regexp.MustCompile(`^gh secret (set|delete) [A-Z_][A-Z0-9_]{0,254}( --env audit)? -R example-org/security-audit$`)
	f.Fuzz(func(t *testing.T, list string) {
		if len(list) > 1<<14 {
			return
		}
		fake := newFakeGitHub()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/secrets") {
				_, _ = io.WriteString(w, list)
				return
			}
			fake.ServeHTTP(w, r)
		}))
		defer srv.Close()
		o := NewCheck()
		CheckGitHub(context.Background(), o, GitHub{Client: srv.Client(), BaseURL: srv.URL, Token: fakeToken}, exampleParams())
		failed := false
		for _, r := range o.Rows {
			if r.Item == ItemSecret && r.Code == "GITHUB_API_FAILED" {
				failed = true
			}
			switch r.Item {
			case ItemSecret, ItemSecretUnused, ItemRepositorySecret:
				if r.Target != "" && (!githubSecretRE.MatchString(r.Target) || r.Target != strings.ToUpper(r.Target)) {
					t.Fatalf("unsafe target %q", r.Target)
				}
				for _, l := range r.Fix {
					if !cmdRE.MatchString(l) {
						t.Fatalf("unsafe command %q", l)
					}
				}
			}
			if strings.Contains(r.Detail, fakeToken) || (len(list) > 20 && strings.Contains(r.Detail, list)) {
				t.Fatalf("the row carries the token or the response: %q", r.Detail)
			}
		}
		if failed && len(o.MissingSecrets) != 0 {
			t.Fatalf("an unreadable list must not be reported as missing secrets: %+v", o.MissingSecrets)
		}
		for _, m := range o.MissingSecrets {
			if !cmdRE.MatchString(m.Command) {
				t.Fatalf("unsafe command %q", m.Command)
			}
		}
	})
}

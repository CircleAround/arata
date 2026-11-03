package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/llm"
	"github.com/CircleAround/arata/internal/notify"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// cli はコマンドレベルの e2e の土台。実 Slack には接続せず、httptest の Webhook に送る。
type cli struct {
	t              *testing.T
	dir            string
	cfg            string
	env            map[string]string
	stdout, stderr *bytes.Buffer
	hook           *hook
	// rec は偽の claude が引数・標準入力・環境変数を記録するディレクトリ。claudeOut は偽の claude が返す出力 (--output-format json の形)。
	rec       string
	claudeOut string
	// claudeProposalsOut は提案の書き起こしの呼び出し (標準入力が JSON の配列) に返す出力。空なら claudeOut を返す。
	claudeProposalsOut string
	fakeMode           string // "" = claudeOut を返す / "fail" = 終了コード 1 / "sleep" = 時間切れ
	bedrock            *httptest.Server
}

// hook は Incoming Webhook の偽物。パスごとに受け取った text を記録する。
type hook struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    map[string][]string
	status int
}

func newHook(t *testing.T) *hook {
	h := &hook{got: map[string][]string{}, status: http.StatusOK}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		h.mu.Lock()
		h.got[r.URL.Path] = append(h.got[r.URL.Path], m["text"])
		status := h.status
		h.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

const (
	normalPath = "/services/T000/B000/normal-secret"
	urgentPath = "/services/T000/B000/urgent-secret"
)

func newCLI(t *testing.T) *cli {
	t.Helper()
	dir := t.TempDir()
	c := &cli{t: t, dir: dir, cfg: filepath.Join(dir, "aratam.yaml"), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, hook: newHook(t), rec: filepath.Join(dir, "rec")}
	// 実際の claude を起動しないよう、PATH には偽の claude だけを置く
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{bin, c.rec} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(fakeClaude), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	c.env = map[string]string{
		"ARATAM_SLACK_WEBHOOK":        c.hook.srv.URL + normalPath,
		"ARATAM_SLACK_URGENT_WEBHOOK": c.hook.srv.URL + urgentPath,
	}
	body := strings.Replace(string(notify.Scaffold()), "name: example", "name: acme", 1)
	if err := os.WriteFile(c.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// run は aratam を実行する。Webhook の URL (秘密) が標準出力・標準エラーに出ていないことを毎回確かめる。
func (c *cli) run(args ...string) int {
	c.t.Helper()
	c.stdout.Reset()
	c.stderr.Reset()
	code := Execute(args, Deps{
		Stdout: c.stdout, Stderr: c.stderr,
		Getenv:     func(k string) string { return c.env[k] },
		Now:        func() time.Time { return time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC) },
		HTTPClient: c.hook.srv.Client(),
		Environ: func() []string {
			// aratam のプロセスの環境変数のつもり。Webhook の URL は子プロセスに渡らないことを確かめる
			out, _ := os.Create(filepath.Join(c.rec, "response"))
			_, _ = io.WriteString(out, c.claudeOut)
			out.Close()
			if c.claudeProposalsOut != "" {
				_ = os.WriteFile(filepath.Join(c.rec, "response_proposals"), []byte(c.claudeProposalsOut), 0o600)
			}
			return []string{"PATH=/usr/bin:/bin", "REC=" + c.rec, "FAKE_MODE=" + c.fakeMode,
				"ARATAM_SLACK_WEBHOOK=" + c.env["ARATAM_SLACK_WEBHOOK"], "ARATAM_SLACK_URGENT_WEBHOOK=" + c.env["ARATAM_SLACK_URGENT_WEBHOOK"]}
		},
		NewBedrock: func(_ context.Context, region, _, model string) (notify.Summarizer, error) {
			if c.bedrock == nil {
				c.t.Fatal("bedrock is not faked")
			}
			return &llm.Bedrock{Model: model, Client: bedrockruntime.New(bedrockruntime.Options{
				Region: region, BaseEndpoint: aws.String(c.bedrock.URL), HTTPClient: c.bedrock.Client(), RetryMaxAttempts: 1,
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "example"}, nil
				}),
			})}, nil
		},
	})
	for _, out := range []string{c.stdout.String(), c.stderr.String()} {
		if strings.Contains(out, "secret") || strings.Contains(out, c.hook.srv.URL) {
			c.t.Fatalf("webhook URL leaked:\n%s", out)
		}
	}
	return code
}

// codes は標準エラーの JSON ログの code。
func (c *cli) codes() []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(c.stderr.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			if s, ok := m["code"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (c *cli) setConfig(from, to string) {
	c.t.Helper()
	b, _ := os.ReadFile(c.cfg)
	if err := os.WriteFile(c.cfg, []byte(strings.Replace(string(b), from, to, 1)), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

// goldenReport は arata の report.json のゴールデン (テストが Chdir しても読めるよう絶対パスにしておく)。
var goldenReport, _ = filepath.Abs("../../internal/report/testdata/report.json")

// inputDir は arata のゴールデンの report.json を置いた出力ディレクトリ。
func (c *cli) inputDir() string {
	c.t.Helper()
	b, err := os.ReadFile(goldenReport)
	if err != nil {
		c.t.Fatal(err)
	}
	dir := filepath.Join(c.t.TempDir(), "out")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		c.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), b, 0o600); err != nil {
		c.t.Fatal(err)
	}
	return dir
}

func TestNotifySendsToUrgentWebhookOnce(t *testing.T) {
	c := newCLI(t)
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.hook.got[urgentPath]; len(got) != 1 || !strings.HasPrefix(got[0], "*arata daily (acme)*") || len(c.hook.got[normalPath]) != 0 {
		t.Fatalf("got %v", c.hook.got)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in); code != 0 || len(c.hook.got[urgentPath]) != 1 || strings.Join(c.codes(), ",") != notify.CodeAlreadyNotified {
		t.Fatalf("second notify must not send: exit %d %v %s", code, c.hook.got, c.stderr)
	}
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--force"); code != 0 || len(c.hook.got[urgentPath]) != 2 {
		t.Fatalf("--force: exit %d %v", code, c.hook.got)
	}
}

// 緊急用の Webhook が無ければ通常用に送り、冒頭にメンションを付ける。
func TestNotifyUrgentFallsBackToNormalWithMention(t *testing.T) {
	c := newCLI(t)
	c.setConfig("urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK", `urgent_webhook_env: ""`)
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.hook.got[normalPath]; len(got) != 1 || !strings.HasPrefix(got[0], "<!channel>\n*arata daily") {
		t.Fatalf("got %v", c.hook.got)
	}

	// 名前は書いたが環境変数が空 → 警告して通常用に送る
	c = newCLI(t)
	delete(c.env, "ARATAM_SLACK_URGENT_WEBHOOK")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 0 || strings.Join(c.codes(), ",") != "URGENT_WEBHOOK_UNSET" {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if got := c.hook.got[normalPath]; len(got) != 1 || !strings.HasPrefix(got[0], "<!channel>\n") {
		t.Fatalf("got %v", c.hook.got)
	}
}

// --dry-run は送らず、.aratam-notified も書かない。Webhook の環境変数も要らない。
func TestNotifyDryRun(t *testing.T) {
	c := newCLI(t)
	c.env = map[string]string{}
	in := c.inputDir()
	if code := c.run("notify", "-c", c.cfg, "--in", in, "--dry-run"); code != 0 {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if !strings.HasPrefix(c.stdout.String(), "--- route: urgent → normal webhook (no urgent webhook) ---\n<!channel>\n*arata daily") || len(c.hook.got) != 0 {
		t.Fatalf("stdout:\n%s", c.stdout)
	}
	if _, err := os.Stat(filepath.Join(in, ".aratam-notified")); err == nil {
		t.Fatal("dry-run must not mark")
	}
}

func TestNotifyExitCodes(t *testing.T) {
	c := newCLI(t)
	// 入力が無い → 緊急用に送って 4
	if code := c.run("notify", "-c", c.cfg, "--in", filepath.Join(c.dir, "missing")); code != 4 || len(c.hook.got[urgentPath]) != 1 ||
		!strings.Contains(c.hook.got[urgentPath][0], "INPUT_MISSING") {
		t.Fatalf("missing input: exit %d %v", code, c.hook.got)
	}
	// 送信に失敗 → 5 (URL はログに出さない。run が確かめる)
	c.hook.status = http.StatusInternalServerError
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 5 || strings.Join(c.codes(), ",") != notify.CodeSendFailed {
		t.Fatalf("send failure: exit %d %s", code, c.stderr)
	}
	c.hook.status = http.StatusOK
	// Webhook の環境変数が無い → 2
	delete(c.env, "ARATAM_SLACK_WEBHOOK")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir()); code != 2 || !strings.Contains(c.stderr.String(), "ARATAM_SLACK_WEBHOOK (slack.webhook_env) is not set") {
		t.Fatalf("missing webhook env: exit %d %s", code, c.stderr)
	}
	// --in は必須 (既定を持たない)
	if code := c.run("notify", "-c", c.cfg); code != 2 || !strings.Contains(c.stderr.String(), `required flag(s) \"in\" not set`) {
		t.Fatalf("--in: exit %d %s", code, c.stderr)
	}
}

// --llm none は設定のプロバイダを上書きし、LLM を呼ばない。
func TestNotifyLLMOverride(t *testing.T) {
	c := newCLI(t)
	c.setConfig("provider: none", "provider: claude-cli")
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run", "--llm", "none"); code != 0 {
		t.Fatalf("--llm none: exit %d %s", code, c.stderr)
	}
	if _, err := os.Stat(filepath.Join(c.rec, "stdin")); err == nil {
		t.Fatal("--llm none must not call claude")
	}
	if code := c.run("notify", "-c", c.cfg, "--in", c.inputDir(), "--dry-run", "--llm", "gpt"); code != 2 || !strings.Contains(c.stderr.String(), "--llm: llm.provider must be one of") {
		t.Fatalf("--llm gpt: exit %d %s", code, c.stderr)
	}
}

func TestConfigInit(t *testing.T) {
	c := newCLI(t)
	t.Chdir(t.TempDir())
	if code := c.run("config", "init"); code != 0 || !strings.Contains(c.stdout.String(), "aratam.yaml を書き出しました") {
		t.Fatalf("exit %d %s %s", code, c.stdout, c.stderr)
	}
	b, _ := os.ReadFile("aratam.yaml")
	if string(b) != string(notify.Scaffold()) {
		t.Fatal("config init must write the scaffold")
	}
	if code := c.run("config", "init"); code != 2 || !strings.Contains(c.stderr.String(), "already exists; use --force") {
		t.Fatalf("exit %d %s", code, c.stderr)
	}
	if code := c.run("config", "init", "--force"); code != 0 {
		t.Fatalf("--force: exit %d %s", code, c.stderr)
	}
	if code := c.run("config", "init", "--out", "-"); code != 0 || c.stdout.String() != string(notify.Scaffold()) {
		t.Fatalf("--out -: exit %d", code)
	}
	if code := c.run("config", "init", "--out", "sub/x.yaml"); code != 0 || !strings.Contains(c.stdout.String(), "aratam notify -c sub/x.yaml --in") {
		t.Fatalf("--out file: exit %d %s", code, c.stdout)
	}
}

// 設定ファイルの解決順: -c > 環境変数 ARATAM_CONFIG > カレントディレクトリの ./aratam.yaml。
func TestConfigPathResolution(t *testing.T) {
	c := newCLI(t)
	base, _ := os.ReadFile(c.cfg)
	write := func(p, name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(base), "name: acme", "name: "+name, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cwd := filepath.Join(c.dir, "cwd")
	write(filepath.Join(cwd, "aratam.yaml"), "from-cwd")
	envCfg := filepath.Join(c.dir, "env", "env.yaml")
	write(envCfg, "from-env")
	flagCfg := filepath.Join(c.dir, "flag", "flag.yaml")
	write(flagCfg, "from-flag")
	t.Chdir(cwd)
	in := c.inputDir()

	// どの設定を使ったかは name の不一致の警告で分かる
	used := func(args ...string) string {
		t.Helper()
		if code := c.run(append([]string{"notify", "--in", in, "--dry-run"}, args...)...); code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, c.stderr)
		}
		return c.stdout.String()
	}
	if got := used(); !strings.Contains(got, "設定の name (from-cwd)") {
		t.Fatalf("./aratam.yaml must be used: %s", got)
	}
	c.env["ARATAM_CONFIG"] = envCfg
	if got := used(); !strings.Contains(got, "設定の name (from-env)") {
		t.Fatalf("ARATAM_CONFIG must win over ./aratam.yaml: %s", got)
	}
	if got := used("-c", flagCfg); !strings.Contains(got, "設定の name (from-flag)") {
		t.Fatalf("-c must win over ARATAM_CONFIG: %s", got)
	}
	// 指したファイルが無ければ ./aratam.yaml に落ちずに設定エラー
	c.env["ARATAM_CONFIG"] = filepath.Join(c.dir, "nope.yaml")
	if code := c.run("notify", "--in", in); code != 2 || strings.Join(c.codes(), ",") != notify.CodeConfigInvalid || !strings.Contains(c.stderr.String(), "nope.yaml") {
		t.Fatalf("missing ARATAM_CONFIG file: exit %d %s", code, c.stderr)
	}
	delete(c.env, "ARATAM_CONFIG")
	t.Chdir(c.dir)
	if err := os.Remove(c.cfg); err != nil {
		t.Fatal(err)
	}
	if code := c.run("notify", "--in", in); code != 2 || !strings.Contains(c.stderr.String(), "config file not found: tried -c/--config (not given), $ARATAM_CONFIG (not set), ./aratam.yaml (not found)") {
		t.Fatalf("no config: exit %d %s", code, c.stderr)
	}
}

func TestRootHelpAndVersion(t *testing.T) {
	c := newCLI(t)
	if code := c.run(); code != 0 || !strings.Contains(c.stdout.String(), "aratam config init") || !strings.Contains(c.stdout.String(), "Available Commands:\n  config") {
		t.Fatalf("exit %d\n%s", code, c.stdout)
	}
	if code := c.run("--version"); code != 0 || c.stdout.String() != "aratam version dev\n" {
		t.Fatalf("exit %d %q", code, c.stdout)
	}
	if code := c.run("bogus"); code != 2 {
		t.Fatalf("unknown command: exit %d", code)
	}
}

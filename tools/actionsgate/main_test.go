package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	shaA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
	shaB = "b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
	shaT = "86bbafdfd62173cc5312b8bc1c3e87dcd6b1c2bb" // annotated tag の object
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// fakeGitHub は path ごとに固定の JSON を返す。無いものは 404。テストは本物の GitHub に接続しない。
func fakeGitHub(t *testing.T, routes map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func tagRoutes(repo, tag, sha string, published time.Time) map[string]any {
	return map[string]any{
		"/repos/" + repo + "/git/ref/tags/" + tag:  map[string]any{"object": map[string]string{"type": "commit", "sha": sha}},
		"/repos/" + repo + "/releases/tags/" + tag: map[string]any{"published_at": published},
	}
}

func writeWorkflow(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ci.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runGate(t *testing.T, srv *httptest.Server, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	url := "http://127.0.0.1:1" // -offline のテストが通信すれば失敗する
	if srv != nil {
		url = srv.URL
	}
	code := run(append([]string{"-api", url}, args...), &out, &errOut, now, http.DefaultClient, "")
	return code, out.String() + errOut.String()
}

func TestParseUses(t *testing.T) {
	text := "steps:\n" +
		"  - uses: actions/checkout@" + shaA + " # v7.0.1\n" +
		"  - name: x\n" +
		"    uses: 'github/codeql-action/upload-sarif@" + shaB + "' # v4.39.1\n" +
		"  # - uses: commented/out@v1\n" +
		"  - uses: ./local\n" +
		"  - uses: $/.github/actions/same-repo\n"
	got := parseUses("ci.yml", text)
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Repo != "actions/checkout" || got[0].Ref != shaA || got[0].Tag != "v7.0.1" {
		t.Errorf("got %+v", got[0])
	}
	if got[1].Repo != "github/codeql-action" || got[1].Ref != shaB || got[1].Tag != "v4.39.1" {
		t.Errorf("subpath action: %+v", got[1])
	}
}

func TestOfflineRejectsUnpinned(t *testing.T) {
	cases := map[string]string{
		"tag":            "      - uses: actions/checkout@v7.0.1\n",
		"branch":         "      - uses: actions/checkout@main\n",
		"short sha":      "      - uses: actions/checkout@3d3c42e\n",
		"no comment":     "      - uses: actions/checkout@" + shaA + "\n",
		"no version":     "      - uses: actions/checkout@" + shaA + " # latest\n",
		"reusable":       "    uses: example-org/shared/.github/workflows/x.yml@main\n",
		"image with tag": "      - uses: docker://alpine:3.20\n",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			code, msg := runGate(t, nil, "-offline", writeWorkflow(t, line))
			if code != 1 {
				t.Fatalf("code=%d msg=%s", code, msg)
			}
			if !strings.Contains(msg, "ci.yml") {
				t.Errorf("must name the file: %s", msg)
			}
		})
	}
}

func TestOfflineAcceptsPinned(t *testing.T) {
	body := "      - uses: actions/checkout@" + shaA + " # v7.0.1\n" +
		"      - uses: docker://alpine@sha256:" + strings.Repeat("a", 64) + "\n" +
		"      - uses: ./local\n"
	if code, msg := runGate(t, nil, "-offline", writeWorkflow(t, body)); code != 0 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

// 走査の結果が 0 件なら、ディレクトリの指定の誤りかもしれないので通さない。
func TestNoWorkflowsIsAnError(t *testing.T) {
	if code, msg := runGate(t, nil, "-offline", t.TempDir()); code != 2 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

func TestOldEnoughPasses(t *testing.T) {
	srv := fakeGitHub(t, tagRoutes("actions/checkout", "v7.0.1", shaA, now.AddDate(0, 0, -8)))
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	if code, msg := runGate(t, srv, "-days", "7", dir); code != 0 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

func TestTooNewFails(t *testing.T) {
	srv := fakeGitHub(t, tagRoutes("actions/checkout", "v7.0.1", shaA, now.AddDate(0, 0, -6)))
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	code, msg := runGate(t, srv, "-days", "7", dir)
	if code != 1 || !strings.Contains(msg, "actions/checkout@v7.0.1") {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

// コメントの版と SHA が食い違えば、読む人が見ている版と動く版が違う。
func TestCommentMustMatchSHA(t *testing.T) {
	srv := fakeGitHub(t, tagRoutes("actions/checkout", "v7.0.1", shaB, now.AddDate(0, 0, -30)))
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	code, msg := runGate(t, srv, dir)
	if code != 1 || !strings.Contains(msg, shaB) {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

func TestAnnotatedTagIsPeeled(t *testing.T) {
	routes := tagRoutes("actions/checkout", "v7.0.1", shaA, now.AddDate(0, 0, -30))
	routes["/repos/actions/checkout/git/ref/tags/v7.0.1"] = map[string]any{"object": map[string]string{"type": "tag", "sha": shaT}}
	routes["/repos/actions/checkout/git/tags/"+shaT] = map[string]any{"object": map[string]string{"type": "commit", "sha": shaA}}
	srv := fakeGitHub(t, routes)
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	if code, msg := runGate(t, srv, dir); code != 0 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

// リリースの無いタグはコミットの時刻で判定する。
func TestFallsBackToCommitDate(t *testing.T) {
	routes := tagRoutes("actions/checkout", "v7.0.1", shaA, now)
	delete(routes, "/repos/actions/checkout/releases/tags/v7.0.1")
	routes["/repos/actions/checkout/git/commits/"+shaA] = map[string]any{"committer": map[string]any{"date": now.AddDate(0, 0, -2)}}
	srv := fakeGitHub(t, routes)
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	if code, msg := runGate(t, srv, dir); code != 1 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

// 判定できないものは通さない (fail closed)。
func TestUnknownIsFailClosed(t *testing.T) {
	srv := fakeGitHub(t, nil)
	dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
	if code, msg := runGate(t, srv, dir); code != 2 {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

const lockText = `version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - 'actions/attest-build-provenance@v4.2.2'
dependencies:
    'actions/attest-build-provenance@v4.2.2':
        ref: 'v4.2.2'
        commit: 'sha1-` + shaA + `'
        owner_id: 1
        repo_id: 2
        uses:
            - 'actions/attest@` + shaB + `'
    'actions/attest@` + shaB + `':
        ref: 'v4.1.0'
        commit: 'sha1-` + shaB + `'
        owner_id: 1
        repo_id: 3
`

func TestLockfileDependencies(t *testing.T) {
	got, err := parseLock([]byte(lockText))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[1].Repo != "actions/attest" || got[1].Ref != shaB || got[1].Tag != "v4.1.0" {
		t.Errorf("got %+v", got[1])
	}
}

// 推移的な依存 (composite の中の action) も 7 日待つ。
func TestLockedTransitiveDependencyIsChecked(t *testing.T) {
	routes := tagRoutes("actions/attest-build-provenance", "v4.2.2", shaA, now.AddDate(0, 0, -30))
	for k, v := range tagRoutes("actions/attest", "v4.1.0", shaB, now.AddDate(0, 0, -1)) {
		routes[k] = v
	}
	srv := fakeGitHub(t, routes)
	dir := writeWorkflow(t, "      - uses: actions/attest-build-provenance@"+shaA+" # v4.2.2\n")
	lock := filepath.Join(dir, "actions.lock")
	if err := os.WriteFile(lock, []byte(lockText), 0o644); err != nil {
		t.Fatal(err)
	}
	code, msg := runGate(t, srv, "-lock", lock, dir)
	if code != 1 || !strings.Contains(msg, "actions/attest@v4.1.0") {
		t.Fatalf("code=%d msg=%s", code, msg)
	}
}

// ロックファイルの ref は動く参照 (v1、main) でもよい。動いた先の中身は lock が固定しているので、記録の commit の時刻で判定する。
func TestLockedFloatingRefUsesCommitDate(t *testing.T) {
	lock := "dependencies:\n  'example-org/tool@v1':\n    ref: 'v1'\n    commit: 'sha1-" + shaB + "'\n"
	for name, tc := range map[string]struct {
		age  int
		want int
	}{"old": {30, 0}, "new": {2, 1}} {
		t.Run(name, func(t *testing.T) {
			routes := tagRoutes("actions/checkout", "v7.0.1", shaA, now.AddDate(0, 0, -30))
			for k, v := range tagRoutes("example-org/tool", "v1", shaA, now.AddDate(0, 0, -100)) { // タグは別の commit へ動いた
				routes[k] = v
			}
			routes["/repos/example-org/tool/git/commits/"+shaB] = map[string]any{"committer": map[string]any{"date": now.AddDate(0, 0, -tc.age)}}
			srv := fakeGitHub(t, routes)
			dir := writeWorkflow(t, "      - uses: actions/checkout@"+shaA+" # v7.0.1\n")
			path := filepath.Join(dir, "actions.lock")
			if err := os.WriteFile(path, []byte(lock), 0o644); err != nil {
				t.Fatal(err)
			}
			if code, msg := runGate(t, srv, "-lock", path, dir); code != tc.want {
				t.Fatalf("code=%d want=%d msg=%s", code, tc.want, msg)
			}
		})
	}
}

// このリポジトリのワークフローと見本は常に固定されている (CI を待たず go test で分かる)。
func TestRepositoryWorkflowsArePinned(t *testing.T) {
	code, msg := runGate(t, nil, "-offline", "../../.github/workflows", "../../examples/github-actions")
	if code != 0 {
		t.Fatalf("code=%d\n%s", code, msg)
	}
}

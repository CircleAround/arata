package repoinit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Terraform を実際に動かすテスト。provider の取得にネットワーク (Terraform のレジストリ) が要るので、ふだんの go test ./... では動かさない。
// 環境変数 ARATA_TEST_TERRAFORM=1 で有効にする (CI の terraform のジョブと make test-terraform)。
// GitHub には接続しない: provider を、手元の偽の GitHub API (httptest) に向ける (ADR 0059)。
func terraformBin(t *testing.T) string {
	t.Helper()
	if os.Getenv("ARATA_TEST_TERRAFORM") != "1" {
		t.Skip("set ARATA_TEST_TERRAFORM=1 to run the Terraform tests (needs terraform on PATH and network access to the Terraform registry)")
	}
	bin, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("ARATA_TEST_TERRAFORM=1 but terraform is not on PATH: %v", err)
	}
	return bin
}

// fakeGitHub は、秘密の箱の Terraform が呼ぶ GitHub の API だけを持つ偽のサーバー (GitHub Enterprise Server の形のパス /api/v3/…)。
// 秘密への書き込み (PUT) と削除 (DELETE) を記録する。
type fakeGitHub struct {
	mu          sync.Mutex
	secrets     map[string]time.Time // 名前 → 最後に更新した時刻
	environment bool                 // environment がある
	writes      []string             // "PUT 名前" / "DELETE 名前"
	clock       time.Time
}

func newFakeGitHub(existing ...string) *fakeGitHub {
	f := &fakeGitHub{secrets: map[string]time.Time{}, environment: true, clock: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	for _, n := range existing {
		f.secrets[n] = f.clock
	}
	return f
}

// touch は、人が画面で値を入れた (更新の時刻が進んだ) ことにする。
func (f *fakeGitHub) touch(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(time.Hour)
	f.secrets[name] = f.clock
}

func (f *fakeGitHub) takeWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.writes
	f.writes = nil
	return w
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	notFound := func() { reply(http.StatusNotFound, map[string]string{"message": "Not Found"}) }
	secret := func(name string) map[string]string {
		at := f.secrets[name].Format(time.RFC3339)
		return map[string]string{"name": name, "created_at": at, "updated_at": at}
	}
	const prefix = "/api/v3/repositories/42/environments/" + Environment + "/secrets"
	p := r.URL.Path
	switch {
	case p == "/api/v3/repos/example-org/security-audit":
		reply(200, map[string]any{"id": 42, "name": "security-audit", "full_name": "example-org/security-audit", "owner": map[string]string{"login": "example-org"}})
	case p == "/api/v3/orgs/example-org":
		reply(200, map[string]any{"login": "example-org", "id": 7})
	case !strings.HasPrefix(p, prefix):
		notFound()
	case !f.environment:
		notFound()
	case p == prefix && r.Method == http.MethodGet:
		names := make([]string, 0, len(f.secrets))
		for n := range f.secrets {
			names = append(names, n)
		}
		sort.Strings(names)
		list := []map[string]string{}
		for _, n := range names {
			list = append(list, secret(n))
		}
		reply(200, map[string]any{"total_count": len(list), "secrets": list})
	case p == prefix+"/public-key":
		reply(200, map[string]string{"key_id": "1", "key": base64.StdEncoding.EncodeToString(make([]byte, 32))})
	default:
		name := strings.TrimPrefix(p, prefix+"/")
		switch r.Method {
		case http.MethodPut:
			f.writes = append(f.writes, "PUT "+name)
			f.clock = f.clock.Add(time.Hour)
			f.secrets[name] = f.clock
			reply(http.StatusCreated, map[string]string{})
		case http.MethodDelete:
			f.writes = append(f.writes, "DELETE "+name)
			delete(f.secrets, name)
			reply(http.StatusNoContent, nil)
		case http.MethodGet:
			if _, ok := f.secrets[name]; !ok {
				notFound()
				return
			}
			reply(200, secret(name))
		default:
			notFound()
		}
	}
}

type tfRoot struct {
	t   *testing.T
	bin string
	dir string
	env []string
}

func (r tfRoot) run(args ...string) (string, error) {
	r.t.Helper()
	cmd := exec.Command(r.bin, args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), r.env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (r tfRoot) must(args ...string) string {
	r.t.Helper()
	out, err := r.run(args...)
	if err != nil {
		r.t.Fatalf("terraform %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// writeSet は見本の引数の一式を一時ディレクトリに書く。
func writeSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := Apply(dir, mustFiles(t, exampleParams()), false); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestTerraformFormatAndValidate は、書き出した Terraform が terraform fmt の形で、固定した provider の版で validate を通ることを確かめる。
// init は lock を書き換えさせない (-lockfile=readonly): 書き出した lock のハッシュで、取得した provider が確かめられる。
func TestTerraformFormatAndValidate(t *testing.T) {
	bin := terraformBin(t)
	dir := writeSet(t)
	cache := t.TempDir()
	if out, err := (tfRoot{t, bin, dir, nil}).run("fmt", "-check", "-recursive", "-diff", "."); err != nil {
		t.Fatalf("terraform fmt: %v\n%s", err, out)
	}
	for _, root := range []string{"github", "github/secrets"} {
		r := tfRoot{t, bin, filepath.Join(dir, root), []string{"TF_IN_AUTOMATION=1", "TF_PLUGIN_CACHE_DIR=" + cache, "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE=0"}}
		before, _ := os.ReadFile(filepath.Join(r.dir, ".terraform.lock.hcl"))
		r.must("init", "-input=false", "-no-color", "-lockfile=readonly")
		if out := r.must("validate", "-no-color"); !strings.Contains(out, "Success") {
			t.Errorf("%s: %s", root, out)
		}
		if after, _ := os.ReadFile(filepath.Join(r.dir, ".terraform.lock.hcl")); string(before) != string(after) {
			t.Errorf("%s: init changed the lock file", root)
		}
	}
}

// TestSecretBoxesNeverOverwriteExistingSecrets は、秘密の箱の Terraform を偽の GitHub API に当てて、
// 既にある秘密に 1 度も書き込まないことを確かめる (この一式でいちばん壊してはいけない性質。ADR 0059)。
func TestSecretBoxesNeverOverwriteExistingSecrets(t *testing.T) {
	bin := terraformBin(t)
	dir := writeSet(t)
	// 既に本物の値が入っている秘密が 2 つある
	existing := []string{"ARATAM_SLACK_WEBHOOK", "ARATA_RUNNER_ROLE_ARN"}
	gh := newFakeGitHub(existing...)
	srv := httptest.NewServer(gh)
	defer srv.Close()
	r := tfRoot{t, bin, filepath.Join(dir, "github", "secrets"), []string{
		"TF_IN_AUTOMATION=1", "GITHUB_BASE_URL=" + srv.URL + "/", "GITHUB_TOKEN=dummy-token-for-the-fake-api", "GITHUB_OWNER=",
	}}
	r.must("init", "-input=false", "-no-color", "-lockfile=readonly")
	apply := func() string { return r.must("apply", "-auto-approve", "-input=false", "-no-color") }
	puts := func(names ...string) string {
		var w []string
		for _, n := range names {
			w = append(w, "PUT "+n)
		}
		sort.Strings(w)
		return strings.Join(w, ",")
	}
	sorted := func(w []string) string { sort.Strings(w); return strings.Join(w, ",") }

	// 1 回目: 既にある 2 つは取り込むだけ。無い 4 つだけを作る
	out := apply()
	var missing []string
	for _, n := range SecretNames {
		if n != existing[0] && n != existing[1] {
			missing = append(missing, n)
		}
	}
	if got := sorted(gh.takeWrites()); got != puts(missing...) {
		t.Fatalf("the first apply must create only the missing boxes.\nwrites: %s\n%s", got, out)
	}
	if !strings.Contains(out, "2 imported, 4 added, 0 changed, 0 destroyed") {
		t.Errorf("first apply:\n%s", out)
	}

	// 2 回目: 何も変わらない (箱を消す計画にならない)
	out = apply()
	if got := gh.takeWrites(); len(got) != 0 || !strings.Contains(out, "0 added, 0 changed, 0 destroyed") {
		t.Fatalf("the second apply must change nothing: %v\n%s", got, out)
	}

	// 人が値を入れた後: 箱だった秘密にも、取り込んだ秘密にも書かない
	gh.touch(missing[0])
	gh.touch(existing[0])
	out = apply()
	if got := gh.takeWrites(); len(got) != 0 || !strings.Contains(out, "0 added, 0 changed, 0 destroyed") {
		t.Fatalf("after a human set the values nothing may be written: %v\n%s", got, out)
	}

	// destroy は止まる (本物の値を消さない)
	if out, err := r.run("destroy", "-auto-approve", "-input=false", "-no-color"); err == nil || !strings.Contains(out, "prevent_destroy") {
		t.Fatalf("destroy must be refused:\n%s", out)
	}
	if got := gh.takeWrites(); len(got) != 0 {
		t.Fatalf("destroy wrote: %v", got)
	}

	// state を失っても安全側: 全部が「既にある」になり、取り込むだけ
	for _, f := range []string{"terraform.tfstate", "terraform.tfstate.backup"} {
		_ = os.Remove(filepath.Join(r.dir, f))
	}
	out = apply()
	if got := gh.takeWrites(); len(got) != 0 || !strings.Contains(out, fmt.Sprintf("%d imported, 0 added, 0 changed, 0 destroyed", len(SecretNames))) {
		t.Fatalf("after losing the state everything must be imported, not written: %v\n%s", got, out)
	}

	// 人が秘密を 1 つ消したら、その箱だけを作り直す
	gh.mu.Lock()
	delete(gh.secrets, missing[1])
	gh.mu.Unlock()
	apply()
	if got := sorted(gh.takeWrites()); got != puts(missing[1]) {
		t.Fatalf("only the deleted box is recreated: %s", got)
	}

	// environment が無ければ、書かずに止まる (github/ を先に当てる)
	gh.mu.Lock()
	gh.environment = false
	gh.mu.Unlock()
	if out, err := r.run("plan", "-input=false", "-no-color"); err == nil {
		t.Fatalf("plan must fail without the environment:\n%s", out)
	}
	if got := gh.takeWrites(); len(got) != 0 {
		t.Fatalf("writes without the environment: %v", got)
	}
}

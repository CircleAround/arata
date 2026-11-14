package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const lockBody = `# This file is maintained automatically by "terraform init".

provider "registry.terraform.io/integrations/github" {
  version     = "6.13.0"
  constraints = "6.13.0"
  hashes = [
    "h1:example=",
  ]
}
`

// registry は Terraform のレジストリの代わり (実際のレジストリには接続しない)。
func registry(t *testing.T, published map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at, ok := published[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"version":"x","published_at":%q}`, at)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func gate(t *testing.T, srv *httptest.Server, locks ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args := []string{"-days", "7"}
	if srv != nil {
		args = append(args, "-registry", srv.URL)
	}
	code := run(append(args, locks...), &out, &errOut, time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), http.DefaultClient)
	return code, out.String() + errOut.String()
}

func writeLock(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".terraform.lock.hcl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGate(t *testing.T) {
	const path = "/v1/providers/integrations/github/6.13.0"
	lock := writeLock(t, lockBody)
	t.Run("old enough", func(t *testing.T) {
		code, out := gate(t, registry(t, map[string]string{path: "2026-07-08T18:13:13Z"}), lock)
		if code != 0 || !strings.Contains(out, "integrations/github 6.13.0") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("exactly 7 days", func(t *testing.T) {
		if code, out := gate(t, registry(t, map[string]string{path: "2026-11-07T00:00:00Z"}), lock); code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("too new", func(t *testing.T) {
		code, out := gate(t, registry(t, map[string]string{path: "2026-11-07T00:00:01Z"}), lock)
		if code != 1 || !strings.Contains(out, "6.13.0") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	// 判定できないものは通さない
	t.Run("unknown version", func(t *testing.T) {
		if code, _ := gate(t, registry(t, nil), lock); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("bad date", func(t *testing.T) {
		if code, _ := gate(t, registry(t, map[string]string{path: "yesterday"}), lock); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("no lock given", func(t *testing.T) {
		if code, _ := gate(t, nil); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		if code, _ := gate(t, registry(t, nil), filepath.Join(t.TempDir(), "none")); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("lock without a provider", func(t *testing.T) {
		if code, _ := gate(t, registry(t, nil), writeLock(t, "# empty\n")); code != 2 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("other registry host", func(t *testing.T) {
		other := strings.Replace(lockBody, "registry.terraform.io", "registry.example.com", 1)
		if code, _ := gate(t, registry(t, map[string]string{path: "2026-07-08T18:13:13Z"}), writeLock(t, other)); code != 2 {
			t.Fatalf("a provider from another registry cannot be judged: exit %d", code)
		}
	})
	t.Run("same provider in two locks is asked once", func(t *testing.T) {
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n++
			fmt.Fprint(w, `{"published_at":"2026-07-08T18:13:13Z"}`)
		}))
		defer srv.Close()
		if code, out := gate(t, srv, lock, writeLock(t, lockBody)); code != 0 || n != 1 {
			t.Fatalf("exit %d, %d requests\n%s", code, n, out)
		}
	})
}

// TestParseLock は、信用できない入力 (lock のファイル) から、決まった形の provider と版だけを取り出すことを確かめる。
func TestParseLock(t *testing.T) {
	got, err := parseLock([]byte(lockBody))
	if err != nil || len(got) != 1 || got[0] != (provider{"registry.terraform.io", "integrations", "github", "6.13.0"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{
		`provider "registry.terraform.io/integrations/github" {` + "\n}\n",                       // 版が無い
		`provider "registry.terraform.io/../github" {` + "\n" + `  version = "6.13.0"` + "\n}\n", // 名前の形
		`provider "registry.terraform.io/a/b" {` + "\n" + `  version = "6.13.0/../x"` + "\n}\n",  // 版の形
	} {
		if got, err := parseLock([]byte(bad)); err == nil {
			t.Errorf("accepted %q: %v", bad, got)
		}
	}
}

func FuzzParseLock(f *testing.F) {
	f.Add(lockBody)
	f.Add(`provider "registry.terraform.io/a/b" {` + "\n" + `version = "1.0.0"` + "\n}")
	f.Add("provider \"x\" {\n")
	f.Fuzz(func(t *testing.T, s string) {
		ps, err := parseLock([]byte(s))
		if err != nil {
			return
		}
		// 取り出した値は URL のパスに入る。決まった文字だけで、パスの区切りや .. を含まない
		for _, p := range ps {
			for _, v := range []string{p.host, p.namespace, p.name, p.version} {
				if v == "" || strings.ContainsAny(v, "/\\?#% \n") || strings.Contains(v, "..") {
					t.Fatalf("unsafe value %q from %q", v, s)
				}
			}
		}
	})
}

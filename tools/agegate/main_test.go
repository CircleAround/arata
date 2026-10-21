package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// listJSON は `go list -m -json all` と同じく、JSON オブジェクトを連ねた出力を作る。
func listJSON(t *testing.T, mods ...Module) string {
	t.Helper()
	var b strings.Builder
	for _, m := range mods {
		j, err := json.MarshalIndent(m, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		b.Write(j)
		b.WriteString("\n")
	}
	return b.String()
}

// proxy は <escaped path>/@v/<escaped version>.info に Time を返すテスト用の GOPROXY。
// infos に無いパスは 404 を返す。叩かれたパスは hits に残す。
func proxy(t *testing.T, infos map[string]time.Time) (*httptest.Server, *[]string) {
	t.Helper()
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		at, ok := infos[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": "x", "Time": at})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func runAgegate(t *testing.T, srv *httptest.Server, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args = append([]string{"-proxy", srv.URL}, args...)
	code := run(args, strings.NewReader(stdin), &out, &errOut, now, srv.Client())
	return code, out.String(), errOut.String()
}

func TestEscapePath(t *testing.T) {
	cases := map[string]string{
		"github.com/aws/aws-sdk-go-v2":   "github.com/aws/aws-sdk-go-v2",
		"github.com/BurntSushi/toml":     "github.com/!burnt!sushi/toml",
		"github.com/Azure/azure-sdk-ABC": "github.com/!azure/azure-sdk-!a!b!c",
		"v1.0.0-RC1":                     "v1.0.0-!r!c1",
	}
	for in, want := range cases {
		if got := escapePath(in); got != want {
			t.Errorf("escapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPseudoTime(t *testing.T) {
	want := time.Date(2023, 1, 29, 9, 28, 42, 0, time.UTC)
	for _, v := range []string{
		"v0.0.0-20230129092842-24d4a6f8daec",
		"v1.2.4-0.20230129092842-24d4a6f8daec",
		"v1.2.3-pre.0.20230129092842-24d4a6f8daec",
		"v2.0.0-20230129092842-24d4a6f8daec+incompatible",
	} {
		got, ok := pseudoTime(v)
		if !ok || !got.Equal(want) {
			t.Errorf("pseudoTime(%q) = %v, %v; want %v", v, got, ok, want)
		}
	}
	for _, v := range []string{"v1.2.3", "v1.2.3-rc.1", "v1.0.0-20230129092842"} {
		if _, ok := pseudoTime(v); ok {
			t.Errorf("pseudoTime(%q) は疑似バージョンではない", v)
		}
	}
}

func TestOldModulesPass(t *testing.T) {
	srv, hits := proxy(t, map[string]time.Time{
		"/github.com/example/old/@v/v1.2.3.info":       now.AddDate(0, 0, -30),
		"/github.com/!example/indirect/@v/v0.4.0.info": now.AddDate(0, 0, -7).Add(-time.Minute),
	})
	in := listJSON(t,
		Module{Path: "github.com/CircleAround/arata", Main: true},
		Module{Path: "github.com/example/old", Version: "v1.2.3"},
		Module{Path: "github.com/Example/indirect", Version: "v0.4.0", Indirect: true},
		Module{Path: "github.com/example/pseudo", Version: "v0.0.0-20230129092842-24d4a6f8daec", Indirect: true},
	)
	code, out, errOut := runAgegate(t, srv, in)
	if code != 0 {
		t.Fatalf("code = %d, stdout=%q stderr=%q", code, out, errOut)
	}
	if len(*hits) != 2 {
		t.Errorf("疑似バージョンと main は proxy を引かない: hits=%v", *hits)
	}
	if !strings.Contains(out, "3 modules") {
		t.Errorf("検査した数を出す: %q", out)
	}
}

func TestYoungModuleFails(t *testing.T) {
	srv, _ := proxy(t, map[string]time.Time{
		"/github.com/example/old/@v/v1.2.3.info":   now.AddDate(0, 0, -30),
		"/github.com/example/young/@v/v1.0.1.info": now.AddDate(0, 0, -3),
	})
	in := listJSON(t,
		Module{Path: "github.com/example/old", Version: "v1.2.3"},
		Module{Path: "github.com/example/young", Version: "v1.0.1", Indirect: true},
		Module{Path: "github.com/example/fresh", Version: "v0.0.0-20261020000000-abcdefabcdef"},
	)
	code, out, errOut := runAgegate(t, srv, in)
	if code != 1 {
		t.Fatalf("code = %d, want 1; stdout=%q stderr=%q", code, out, errOut)
	}
	for _, want := range []string{"github.com/example/young@v1.0.1", "github.com/example/fresh@v0.0.0-20261020000000-abcdefabcdef"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr に %s が無い: %q", want, errOut)
		}
	}
	if strings.Contains(errOut, "example/old") {
		t.Errorf("古いものは出さない: %q", errOut)
	}
}

func TestDaysFlag(t *testing.T) {
	srv, _ := proxy(t, map[string]time.Time{
		"/github.com/example/young/@v/v1.0.1.info": now.AddDate(0, 0, -3),
	})
	in := listJSON(t, Module{Path: "github.com/example/young", Version: "v1.0.1"})
	if code, _, errOut := runAgegate(t, srv, in, "-days", "2"); code != 0 {
		t.Errorf("-days 2 なら 3 日前は通る: code=%d %s", code, errOut)
	}
	if code, _, _ := runAgegate(t, srv, in, "-days", "4"); code != 1 {
		t.Errorf("-days 4 なら 3 日前は落ちる: code=%d", code)
	}
}

func TestReplace(t *testing.T) {
	srv, hits := proxy(t, map[string]time.Time{
		"/github.com/fork/lib/@v/v1.1.0.info": now.AddDate(0, 0, -1),
	})
	in := listJSON(t,
		Module{Path: "github.com/example/lib", Version: "v1.0.0", Replace: &Module{Path: "github.com/fork/lib", Version: "v1.1.0"}},
		Module{Path: "github.com/example/local", Version: "v1.0.0", Replace: &Module{Path: "../local"}},
	)
	code, _, errOut := runAgegate(t, srv, in)
	if code != 1 || !strings.Contains(errOut, "github.com/fork/lib@v1.1.0") {
		t.Errorf("置き換え先の版で判定する: code=%d %q", code, errOut)
	}
	if len(*hits) != 1 {
		t.Errorf("ローカルへの置き換えは対象外: hits=%v", *hits)
	}
}

func TestProxyErrorFailsClosed(t *testing.T) {
	srv, _ := proxy(t, map[string]time.Time{})
	in := listJSON(t, Module{Path: "github.com/example/missing", Version: "v1.0.0"})
	code, _, errOut := runAgegate(t, srv, in)
	if code != 2 || !strings.Contains(errOut, "github.com/example/missing@v1.0.0") {
		t.Errorf("公開時刻が取れなければ失敗にする: code=%d %q", code, errOut)
	}
}

func TestBadInput(t *testing.T) {
	srv, _ := proxy(t, map[string]time.Time{})
	if code, _, _ := runAgegate(t, srv, "{not json"); code != 2 {
		t.Errorf("壊れた入力は code 2: %d", code)
	}
	if code, _, _ := runAgegate(t, srv, "", "-days", "-1"); code != 2 {
		t.Errorf("負の日数は code 2: %d", code)
	}
}

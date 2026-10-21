// agegate は依存モジュールの公開からの日数を確かめ、新しすぎる版があれば失敗する CI 用の小さなツール。
//
//	go list -m -json all | go run ./tools/agegate -days 7
//
// 公開時刻は GOPROXY の <module>/@v/<version>.info の Time を使う。疑似バージョンは版文字列の時刻で判定し、proxy を引かない。
// 終了コード: 0 = すべて -days 以上前、1 = 新しすぎる版がある、2 = 入力・通信のエラー (判定できないものは通さない)。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Module は `go list -m -json` の出力のうち使う項目。
type Module struct {
	Path     string  `json:",omitempty"`
	Version  string  `json:",omitempty"`
	Main     bool    `json:",omitempty"`
	Indirect bool    `json:",omitempty"`
	Replace  *Module `json:",omitempty"`
}

func main() {
	client := &http.Client{Timeout: 30 * time.Second}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, time.Now(), client))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, now time.Time, client *http.Client) int {
	fs := flag.NewFlagSet("agegate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	days := fs.Int("days", 7, "公開から最低これだけの日数が経った版だけを通す")
	proxyURL := fs.String("proxy", "https://proxy.golang.org", "公開時刻を引く GOPROXY")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *days < 0 {
		fmt.Fprintln(stderr, "agegate: -days は 0 以上")
		return 2
	}
	mods, err := parseModules(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "agegate: 入力を読めない: %v\n", err)
		return 2
	}
	minAge := time.Duration(*days) * 24 * time.Hour
	p := proxyClient{base: strings.TrimRight(*proxyURL, "/"), client: client}

	code := 0
	targets := targets(mods)
	for _, m := range targets {
		at, err := p.published(context.Background(), m)
		if err != nil {
			fmt.Fprintf(stderr, "agegate: %s@%s: 公開時刻を取れない: %v\n", m.Path, m.Version, err)
			code = 2
			continue
		}
		if age := now.Sub(at); age < minAge {
			fmt.Fprintf(stderr, "agegate: %s@%s は %s 公開 (%.1f 日前)。%d 日経つまで使わない\n",
				m.Path, m.Version, at.UTC().Format(time.RFC3339), age.Hours()/24, *days)
			if code == 0 {
				code = 1
			}
		}
	}
	if code == 0 {
		fmt.Fprintf(stdout, "agegate: %d modules ok (公開から %d 日以上)\n", len(targets), *days)
	}
	return code
}

// parseModules は JSON オブジェクトを連ねた `go list -m -json all` の出力を読む。
func parseModules(r io.Reader) ([]Module, error) {
	dec := json.NewDecoder(r)
	var mods []Module
	for {
		var m Module
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return mods, nil
		} else if err != nil {
			return nil, err
		}
		mods = append(mods, m)
	}
}

// targets は判定する版を返す。main モジュールとローカルへの置き換え (版を持たない) は除き、置き換えがあれば置き換え先を見る。
func targets(mods []Module) []Module {
	var out []Module
	for _, m := range mods {
		if m.Main {
			continue
		}
		if m.Replace != nil {
			m = *m.Replace
		}
		if m.Version == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

type proxyClient struct {
	base   string
	client *http.Client
}

func (p proxyClient) published(ctx context.Context, m Module) (time.Time, error) {
	if at, ok := pseudoTime(m.Version); ok {
		return at, nil
	}
	url := fmt.Sprintf("%s/%s/@v/%s.info", p.base, escapePath(m.Path), escapePath(m.Version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, err
	}
	res, err := p.client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("%s: %s", url, res.Status)
	}
	var info struct{ Time time.Time }
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", url, err)
	}
	if info.Time.IsZero() {
		return time.Time{}, fmt.Errorf("%s: Time が無い", url)
	}
	return info.Time, nil
}

// escapePath は module proxy のパス規則に従い、大文字を "!" + 小文字にする (版文字列にも同じ規則を使う)。
func escapePath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if 'A' <= r && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pseudoRe は 3 つの疑似バージョンの形 (vX.0.0-T-H / vX.Y.Z-pre.0.T-H / vX.Y.Z-0.T-H) の時刻 T を取る。
var pseudoRe = regexp.MustCompile(`^v\d+\.\d+\.\d+-(?:[0-9A-Za-z.-]*\.)?(\d{14})-[0-9a-f]{12}(?:\+incompatible)?$`)

// pseudoTime は疑似バージョンに埋め込まれたコミット時刻 (UTC) を返す。
func pseudoTime(v string) (time.Time, bool) {
	m := pseudoRe.FindStringSubmatch(v)
	if m == nil {
		return time.Time{}, false
	}
	at, err := time.Parse("20060102150405", m[1])
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

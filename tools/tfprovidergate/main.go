// tfprovidergate は、Terraform の lock (.terraform.lock.hcl) に固定した provider の版が、公開から決まった日数を過ぎていることを確かめる CI 用の小さなツール。
//
//	go run ./tools/tfprovidergate -days 7 examples/audit-repo/github/.terraform.lock.hcl
//
// arata repo init が書き出す GitHub の設定の Terraform は、provider を完全な版で固定する (ADR 0059)。Go のモジュールでも action でもないので、
// tools/agegate と tools/actionsgate の対象にならない。公開時刻は Terraform のレジストリの /v1/providers/<namespace>/<name>/<version> の published_at を使う。
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

func main() {
	client := &http.Client{Timeout: 30 * time.Second}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now(), client))
}

// officialHost は公開時刻を引けるレジストリ。lock の provider がほかのレジストリのものなら、判定できないので通さない。
const officialHost = "registry.terraform.io"

type provider struct{ host, namespace, name, version string }

var (
	providerLine = regexp.MustCompile(`^provider "([a-z0-9][a-z0-9.-]*)/([A-Za-z0-9][A-Za-z0-9_-]*)/([A-Za-z0-9][A-Za-z0-9_-]*)" \{$`)
	versionLine  = regexp.MustCompile(`^\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+)?)"$`)
)

// parseLock は lock から provider と版を取り出す。HCL 全体は解釈しない: terraform が書く決まった形の行だけを読み、
// provider のブロックに形の合う版の行が無ければエラーにする (読み飛ばして通さない)。
func parseLock(b []byte) ([]provider, error) {
	var out []provider
	var cur *provider
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "provider "):
			if cur != nil {
				return nil, fmt.Errorf("provider %s/%s has no version", cur.namespace, cur.name)
			}
			m := providerLine.FindStringSubmatch(line)
			if m == nil || strings.Contains(m[1], "..") {
				return nil, fmt.Errorf("unexpected provider line: %q", line)
			}
			cur = &provider{host: m[1], namespace: m[2], name: m[3]}
		case cur != nil && strings.HasPrefix(strings.TrimSpace(line), "version"):
			m := versionLine.FindStringSubmatch(line)
			if m == nil {
				return nil, fmt.Errorf("unexpected version line: %q", line)
			}
			cur.version = m[1]
			out = append(out, *cur)
			cur = nil
		case line == "}" && cur != nil:
			return nil, fmt.Errorf("provider %s/%s has no version", cur.namespace, cur.name)
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("provider %s/%s has no version", cur.namespace, cur.name)
	}
	if len(out) == 0 {
		return nil, errors.New("no provider in the lock file")
	}
	return out, nil
}

func run(args []string, stdout, stderr io.Writer, now time.Time, client *http.Client) int {
	fs := flag.NewFlagSet("tfprovidergate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	days := fs.Int("days", 7, "公開から最低これだけの日数が経った版だけを通す")
	registry := fs.String("registry", "https://"+officialHost, "公開時刻を引く Terraform のレジストリ")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *days < 0 || fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: tfprovidergate [-days N] <.terraform.lock.hcl>...")
		return 2
	}
	minAge := time.Duration(*days) * 24 * time.Hour
	seen := map[provider]bool{}
	code := 0
	for _, path := range fs.Args() {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "tfprovidergate: %v\n", err)
			return 2
		}
		ps, err := parseLock(b)
		if err != nil {
			fmt.Fprintf(stderr, "tfprovidergate: %s: %v\n", path, err)
			return 2
		}
		for _, p := range ps {
			if seen[p] {
				continue
			}
			seen[p] = true
			if p.host != officialHost {
				fmt.Fprintf(stderr, "tfprovidergate: %s: provider %s/%s/%s is not from %s (the publish date cannot be checked)\n", path, p.host, p.namespace, p.name, officialHost)
				return 2
			}
			at, err := published(context.Background(), client, strings.TrimRight(*registry, "/"), p)
			if err != nil {
				fmt.Fprintf(stderr, "tfprovidergate: %s/%s %s: %v\n", p.namespace, p.name, p.version, err)
				return 2
			}
			age := now.Sub(at)
			if age < minAge {
				fmt.Fprintf(stdout, "NG  %s/%s %s: 公開 %s (%.1f 日前)。%d 日以上たった版にする\n", p.namespace, p.name, p.version, at.Format(time.RFC3339), age.Hours()/24, *days)
				code = 1
				continue
			}
			fmt.Fprintf(stdout, "ok  %s/%s %s: 公開 %s\n", p.namespace, p.name, p.version, at.Format(time.RFC3339))
		}
	}
	return code
}

func published(ctx context.Context, client *http.Client, base string, p provider) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/providers/"+p.namespace+"/"+p.name+"/"+p.version, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("registry returned %s", resp.Status)
	}
	var v struct {
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v); err != nil {
		return time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339, v.PublishedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("published_at %q: %w", v.PublishedAt, err)
	}
	return at, nil
}

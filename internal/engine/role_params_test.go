package engine

import (
	"regexp"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/config"
)

// FuzzBuildRoleParams は、利用者の設定 (log_group の並び) から作る AllowedLogGroupNames が、ロールのパラメータの規則を必ず守ることを確かめる (ADR 0041・0062)。
//   - error でなければ、値はテンプレートの AllowedPattern に合い (空・`*` にならない)、4,096 バイト以内で、カンマで分けると LogGroups に戻る
//   - ロググループが 1 つも無ければ値は `none` (どのロググループも読ませない) で、LogGroups は空。`none` という名前は予約語と区別できないので error
//   - LogGroups は設定の log_group の重複を除いたもので、設定の順
//   - 受け付けない名前が 1 つでもあれば error で、値は出さない
func FuzzBuildRoleParams(f *testing.F) {
	for _, s := range []string{"prod-nginx-access", "prod-nginx-access\n/app/prod/api\nprod-nginx-access", "prod-*", "a,b", "", "*", "a b", "none", "none\nprod-api", strings.Repeat("a", 5000)} {
		f.Add(s)
	}
	pattern := regexp.MustCompile(`^\*$|^[A-Za-z0-9_./#-]+(,[A-Za-z0-9_./#-]+)*$`)
	f.Fuzz(func(t *testing.T, lines string) {
		cfg := &config.Config{}
		var names []string
		for _, n := range strings.Split(lines, "\n") {
			if n == "" {
				continue // 設定の検証は空の log_group を通さない
			}
			names = append(names, n)
			cfg.Sources = append(cfg.Sources, config.Source{ID: "s", Kind: config.KindCloudWatchLogs, LogGroup: n})
		}
		p, err := BuildRoleParams(cfg)
		if err != nil {
			if p.AllowedLogGroupNames != "" || len(p.LogGroups) != 0 {
				t.Fatalf("error なのに値を出した: %+v", p)
			}
			return
		}
		if len(names) == 0 {
			if p.AllowedLogGroupNames != "none" || len(p.LogGroups) != 0 {
				t.Fatalf("ロググループが無いのに: %+v", p)
			}
			return
		}
		for _, n := range names {
			if n == "none" {
				t.Fatalf("none という名前を通した: %+v", p)
			}
		}
		if p.AllowedLogGroupNames == "*" || !pattern.MatchString(p.AllowedLogGroupNames) || len(p.AllowedLogGroupNames) > roleParamValueMax {
			t.Fatalf("ロールが受け付けない値: %q", p.AllowedLogGroupNames)
		}
		if strings.Join(p.LogGroups, ",") != p.AllowedLogGroupNames {
			t.Fatalf("値と LogGroups が違う: %+v", p)
		}
		seen := map[string]bool{}
		var want []string
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				want = append(want, n)
			}
		}
		if strings.Join(want, "\n") != strings.Join(p.LogGroups, "\n") {
			t.Fatalf("LogGroups %q, 設定の順で重複を除くと %q", p.LogGroups, want)
		}
	})
}

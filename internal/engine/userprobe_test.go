package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/pathids"
)

// 利用者ごとのチェックのクエリ (U1・U2。ADR 0087) の長さの検査と、doctor の費用の本数。値はすべて架空。実 AWS には接続しない。

const userProbeUserID = `      user_id:
        from: app_line
        regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$'
`

var longSegments = []string{`[0-9]{1,20}`, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`}

// longTemplates は path_ids の文が上限 (pathids.MaxQueryLen) に近くなるだけの型 (どれも架空)。
func longTemplates(t *testing.T) []string {
	t.Helper()
	var ok []string
	for i := 0; i < pathids.MaxTemplates; i++ {
		try := append(append([]string{}, ok...), fmt.Sprintf("/section%02d/:id/detail/:any/x", i))
		if _, err := pathids.Compile(pathids.Rules{Segments: longSegments, Templates: try, MaxSegments: 12}); err != nil {
			break
		}
		ok = try
	}
	return ok
}

func userProbeSource(t *testing.T, long bool) string {
	src := requestLinesSource
	pi := "    path_ids:\n      segments: ['[0-9]{1,20}']\n      max_segments: 8\n"
	if long {
		pad := strings.Repeat(`(?:x)?`, 75)
		src += "        - name: ua\n          regex: 'UA " + pad + `(?P<ua>\S+)'` + "\n        - name: duration\n          regex: 'Duration " + pad + `(?P<duration>[0-9.]+)'` + "\n"
		pi = "    path_ids:\n      segments: ['" + strings.Join(longSegments, "', '") + "']\n      templates: ['" + strings.Join(longTemplates(t), "', '") + "']\n      max_segments: 12\n"
	}
	return src + userProbeUserID + pi
}

const userProbeChecks = `checks:
  user_denied:
    sources: [web]
  user_id_enumeration:
    sources: [web]
`

func TestLongQueries(t *testing.T) {
	h := newHarnessWith(t, userProbeSource(t, false), userProbeChecks)
	if l := LongQueries(h.cfg); len(l) != 0 {
		t.Fatalf("LongQueries = %v", l)
	}
	h = newHarnessWith(t, userProbeSource(t, true), userProbeChecks)
	l := LongQueries(h.cfg)
	if len(l) == 0 || !strings.Contains(l[0], "source web") || !strings.Contains(l[0], "user_ids") || !strings.Contains(l[0], "path_ids") {
		t.Fatalf("LongQueries = %v", l)
	}
	// sources に書かなければ流さないので、長くても誤りにしない
	h = newHarnessWith(t, userProbeSource(t, true), "")
	if l := LongQueries(h.cfg); len(l) != 0 {
		t.Fatalf("LongQueries without sources = %v", l)
	}
	// doctor はソースの config の行で ng にする
	h = newHarnessWith(t, userProbeSource(t, true), userProbeChecks)
	h.logs.LogGroups = []string{"prod-app"}
	h.logs.On("sort @timestamp desc", doctorSample(95, 5))
	res := Doctor(t.Context(), h.cfg, h.deps, 24*time.Hour)
	found := false
	for _, r := range res.Rows {
		found = found || r.Source == "web" && r.Item == "config" && r.Status == DoctorNG && strings.Contains(r.Detail, "user_ids")
	}
	if !found {
		t.Fatalf("doctor rows: %+v", res.Rows)
	}
}

// doctor の費用の本数 (ADR 0028) に U1・U2 が入る (ADR 0087 の 1 節)。
func TestDoctorQueryCountUserProbe(t *testing.T) {
	count := func(checks string) int {
		h := newHarnessWith(t, userProbeSource(t, false), checks)
		c, err := cwlogsCollector(h, "web")
		if err != nil {
			t.Fatal(err)
		}
		return c.QueryCount()
	}
	base, with := count(""), count(userProbeChecks)
	if with != base+2 {
		t.Fatalf("QueryCount: %d without the user checks, %d with (want +2)", base, with)
	}
}

func cwlogsCollector(h *harness, id string) (*cwlogs.Collector, error) {
	for _, s := range h.cfg.Sources {
		if s.ID == id {
			return cwlogs.New(s, h.cfg.Checks, h.logs)
		}
	}
	return nil, fmt.Errorf("no source %s", id)
}

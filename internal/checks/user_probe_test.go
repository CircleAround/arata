package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// ログインした利用者の総当たり (ADR 0071・0087)。値はすべて架空 (利用者は user:42、型は /orders/:id)。
// 窓は appWindow [10-20 09:00, 10-21 09:00)。評価する日は 10-20 と 10-21。平常帯は各日の前日から 14 日。

func probeConfig() config.Checks {
	c := config.DefaultChecks()
	c.UserDenied.Sources = []string{"app"}
	c.UserIDEnumeration.Sources = []string{"app"}
	c.UserPathBreadth.Sources = []string{"app"}
	c.UserIDEnumeration.ExcludeTemplates = []string{"/courses/*"}
	return c
}

// userCollected は 10-19 から遡って days 日に、ログインした要求の数 (user_requests) を入れる (アプリの記録のある日)。
func userCollected(m metricSeed, days int) {
	for i := 0; i < days; i++ {
		m.put(time.Date(2026, 10, 19-i, 0, 0, 0, 0, time.UTC).Format(record.DateLayout), "app", cwlogs.MetricUserRequests, "user", 1000)
	}
}

func probeRegistry(c config.Checks) *Registry {
	r := NewRegistryFor(c)
	r.SetPathIDSources([]string{"app"})
	return r
}

func evalProbe(t *testing.T, name string, c config.Checks, st *store.Dir) (map[string]Observation, []string) {
	t.Helper()
	ch, ok := probeRegistry(c).Get(name)
	if !ok {
		t.Fatalf("no check %s", name)
	}
	n, ok := ch.(Noter)
	if !ok {
		t.Fatalf("%s is not a Noter", name)
	}
	obs, notes, err := n.EvaluateWithNotes(context.Background(), st, appWindow, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Observation{}
	for _, o := range obs {
		if o.Check != name || o.Summary == "" || o.Fingerprint == "" || o.Severity == "" {
			t.Fatalf("observation incomplete: %+v", o)
		}
		out[o.Key] = o
	}
	return out, notes
}

func keysOf(m map[string]Observation) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestUserDenied(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	userCollected(m, 14)
	// ふだん: いちばん多い利用者 (user:40) が 1 日 10 件、user:41 が 5 件 → アプリの平常帯 10 × 2 = 20
	m.history("app", cwlogs.MetricUserDenied, "user:40", 10)
	m.history("app", cwlogs.MetricUserDenied, "user:41", 5)
	d := "2026-10-21"
	m.put(d, "app", cwlogs.MetricUserDenied, "user:42", 48) // 新しい利用者: 本人の帯は使わず、アプリの帯と下限で
	m.put(d, "app", cwlogs.MetricUserDenied, "user:41", 35) // 本人の帯 5 × 3 = 15 とアプリの帯 20 を超える
	m.put(d, "app", cwlogs.MetricUserDenied, "user:40", 25) // アプリの帯は超えるが min_count (30) 未満
	// ゆっくりした試し: user:44 が 10-17〜10-21 に 1 日 25 件 (1 日では min_count 未満、窓 7 日の和 125 ≥ 100)
	for day := 17; day <= 21; day++ {
		m.put(fmt.Sprintf("2026-10-%02d", day), "app", cwlogs.MetricUserDenied, "user:44", 25)
	}
	obs, notes := evalProbe(t, "user_denied", probeConfig(), st)
	if len(notes) != 0 {
		t.Fatalf("notes: %v", notes)
	}
	if keysOf(obs) != "user:41,user:42,user:44" {
		t.Fatalf("keys: %s", keysOf(obs))
	}
	o := obs["user:42"]
	if o.Severity != Medium || o.Data["day"] != d || o.Data["value"] != 48.0 || o.Data["app_band"] != 20.0 ||
		strings.Join(o.Data["reasons"].([]string), ",") != "above_app_band,new_user" {
		t.Fatalf("user:42: %+v", o)
	}
	if u := o.Data["user"].(map[string]string); u["kind"] != "user" || u["id"] != "42" {
		t.Fatalf("user: %v", u)
	}
	if r := strings.Join(obs["user:41"].Data["reasons"].([]string), ","); r != "above_app_band,above_user_band" || obs["user:41"].Data["user_band"] != 15.0 {
		t.Fatalf("user:41: %+v", obs["user:41"])
	}
	w := obs["user:44"]
	if r := strings.Join(w.Data["reasons"].([]string), ","); r != "new_user,window" || w.Data["day"] != d {
		t.Fatalf("user:44: %+v", w)
	}
	if win := w.Data["window"].(map[string]any); win["sum"] != 125.0 || win["days_with_value"] != 5 || win["days"] != 7 || win["app_band"] != 100.0 {
		t.Fatalf("window: %+v", win)
	}
}

// アプリの記録のある日が min_baseline_days に満たない間は判定せず、注記を出す (ADR 0071 の 10 節)。
func TestUserProbeBaselineWait(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	userCollected(m, 3)
	m.put("2026-10-21", "app", cwlogs.MetricUserDenied, "user:42", 500)
	m.put("2026-10-21", "app", cwlogs.MetricUserIDs, "user:42|/orders/:id", 500)
	m.put("2026-10-21", "app", cwlogs.MetricUserTemplates, "user:42", 500)
	for _, name := range []string{"user_denied", "user_id_enumeration", "user_path_breadth"} {
		obs, notes := evalProbe(t, name, probeConfig(), st)
		if len(obs) != 0 || len(notes) != 1 || !strings.Contains(notes[0], name) || !strings.Contains(notes[0], "あと 4 日") {
			t.Errorf("%s: obs %v notes %v", name, obs, notes)
		}
	}
}

func TestUserIDEnumeration(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	userCollected(m, 14)
	m.history("app", cwlogs.MetricUserIDs, "user:40|/orders/:id", 12)
	m.history("app", cwlogs.MetricUserIDsDist, "/orders/:id|max", 12) // アプリの平常帯 12 × 2 = 24
	d := "2026-10-21"
	put := func(key string, ids, ok, denied float64) {
		m.put(d, "app", cwlogs.MetricUserIDs, key, ids)
		m.put(d, "app", cwlogs.MetricUserIDsOK, key, ok)
		m.put(d, "app", cwlogs.MetricUserIDsDenied, key, denied)
	}
	put("user:42|/orders/:id", 480, 6, 412) // 拒否に混ざる成功 → high
	m.put(d, "app", cwlogs.MetricUserDeniedRedirects, "user:42|/orders/:id", 30)
	m.put(d, "app", cwlogs.MetricUserIDsMethods, "user:42|/orders/:id|GET", 470)
	m.put(d, "app", cwlogs.MetricUserIDsMethods, "user:42|/orders/:id|PATCH", 10)
	put("user:42|/users/:id/orders", 70, 0, 70) // 同じ利用者の 2 つ目の型 (拒否だけ)
	put("user:43|/items/:id", 60, 60, 0)        // 成功だけ → medium (success_only)
	put("user:44|/courses/:id", 200, 200, 0)    // exclude_templates の公開の画面
	put("user:45|/orders/:id", 40, 0, 40)       // min_distinct (50) 未満
	obs, _ := evalProbe(t, "user_id_enumeration", probeConfig(), st)
	if keysOf(obs) != "user:42,user:43" {
		t.Fatalf("keys: %s", keysOf(obs))
	}
	o := obs["user:42"]
	if o.Severity != High || !strings.Contains(strings.Join(o.Data["reasons"].([]string), ","), "success_amid_denied") {
		t.Fatalf("user:42: %+v", o)
	}
	tpls := o.Data["templates"].([]map[string]any)
	if len(tpls) != 2 || tpls[0]["template"] != "/orders/:id" || tpls[0]["ids"] != 480.0 || tpls[0]["ids_ok"] != 6.0 || tpls[0]["ids_denied"] != 412.0 ||
		tpls[0]["denied_redirects"] != 30.0 || tpls[0]["app_band"] != 24.0 || tpls[1]["template"] != "/users/:id/orders" {
		t.Fatalf("templates: %+v", tpls)
	}
	if ms := tpls[0]["methods"].(map[string]float64); ms["GET"] != 470 || ms["PATCH"] != 10 {
		t.Fatalf("methods: %v", ms)
	}
	if _, ok := tpls[1]["denied_redirects"]; ok {
		t.Fatalf("redirects without a value: %+v", tpls[1])
	}
	if !strings.Contains(o.Summary, "user:42") || !strings.Contains(o.Summary, "/orders/:id") || !strings.Contains(o.Summary, "480") {
		t.Fatalf("summary: %s", o.Summary)
	}
	if s := obs["user:43"]; s.Severity != Medium || !strings.Contains(strings.Join(s.Data["reasons"].([]string), ","), "success_only") {
		t.Fatalf("user:43: %+v", s)
	}
}

// 窓: 1 日では min_distinct 未満でも、7 日の和が min_count_window 以上でアプリの窓の平常帯も超えれば報告する。
func TestUserIDEnumerationWindow(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	userCollected(m, 14)
	m.history("app", cwlogs.MetricUserIDs, "user:40|/orders/:id", 12)
	m.history("app", cwlogs.MetricUserIDsDist, "/orders/:id|max", 12)
	for day := 16; day <= 21; day++ {
		m.put(fmt.Sprintf("2026-10-%02d", day), "app", cwlogs.MetricUserIDs, "user:46|/orders/:id", 30)
	}
	obs, _ := evalProbe(t, "user_id_enumeration", probeConfig(), st)
	o, ok := obs["user:46"]
	if !ok || o.Severity != Medium || !strings.Contains(strings.Join(o.Data["reasons"].([]string), ","), "window") {
		t.Fatalf("obs: %+v", obs)
	}
	tpl := o.Data["templates"].([]map[string]any)[0]
	if win := tpl["window"].(map[string]any); win["sum"] != 180.0 || win["app_band"] != 120.0 {
		t.Fatalf("window: %+v", win)
	}
}

func TestUserPathBreadth(t *testing.T) {
	st := newStore(t)
	m := metricSeed{st: st, t: t}
	userCollected(m, 14)
	m.history("app", cwlogs.MetricUserTemplates, "user:40", 20) // アプリの平常帯 20 × 2 = 40
	d := "2026-10-21"
	m.put(d, "app", cwlogs.MetricUserTemplates, "user:42", 80)
	m.put(d, "app", cwlogs.MetricUserTemplatesOK, "user:42", 30)
	m.put(d, "app", cwlogs.MetricUserTemplatesDenied, "user:42", 40)
	m.put(d, "app", cwlogs.MetricUserTemplatesNotFound, "user:42", 50)
	m.put(d, "app", cwlogs.MetricUserTemplates, "user:41", 45) // min_templates (50) 未満
	// 同じ日に user_denied の条件も満たす → related
	m.put(d, "app", cwlogs.MetricUserDenied, "user:42", 48)
	obs, _ := evalProbe(t, "user_path_breadth", probeConfig(), st)
	if keysOf(obs) != "user:42" {
		t.Fatalf("keys: %s", keysOf(obs))
	}
	o := obs["user:42"]
	if o.Severity != Low || o.Data["value"] != 80.0 || o.Data["templates_ok"] != 30.0 || o.Data["templates_denied"] != 40.0 || o.Data["templates_not_found"] != 50.0 {
		t.Fatalf("user:42: %+v", o)
	}
	if r, _ := o.Data["related"].([]string); strings.Join(r, ",") != "user_denied" {
		t.Fatalf("related: %v", o.Data["related"])
	}
	// user_denied の側からも指す
	den, _ := evalProbe(t, "user_denied", probeConfig(), st)
	if r, _ := den["user:42"].Data["related"].([]string); strings.Join(r, ",") != "user_path_breadth" {
		t.Fatalf("related from user_denied: %+v", den["user:42"])
	}
	// related は sources に書いたチェックだけを指す
	c := probeConfig()
	c.UserDenied.Sources = nil
	obs, _ = evalProbe(t, "user_path_breadth", c, st)
	if _, ok := obs["user:42"].Data["related"]; ok {
		t.Fatalf("related to a check without sources: %+v", obs["user:42"])
	}
}

// sources が空なら何も読まない (Disabled。engine は Disabled のチェックの要る記録を引かない)。path_ids のあるソースが無ければ、型の要る 2 つは skip。
func TestUserProbeDisabled(t *testing.T) {
	r := NewRegistryFor(config.DefaultChecks())
	for _, name := range []string{"user_denied", "user_id_enumeration", "user_path_breadth"} {
		c, _ := r.Get(name)
		if c.Cadence() != Daily || c.Mode() != ModeEvent || len(c.Needs()) != 1 || c.Needs()[0] != record.KindHTTPUser {
			t.Errorf("%s: %s %s %v", name, c.Cadence(), c.Mode(), c.Needs())
		}
		if d := c.(Disabler).Disabled(); !strings.Contains(d, "checks."+name+".sources is empty") {
			t.Errorf("%s: disabled %q", name, d)
		}
	}
	r = NewRegistryFor(probeConfig()) // path_ids のあるソースを渡さない
	for name, want := range map[string]string{"user_denied": "", "user_id_enumeration": "no path_ids", "user_path_breadth": "no path_ids"} {
		c, _ := r.Get(name)
		if d := c.(Disabler).Disabled(); want == "" && d != "" || want != "" && !strings.Contains(d, want) {
			t.Errorf("%s: disabled %q", name, d)
		}
		if len(c.Needs()) != 1 || c.Needs()[0] != record.KindHTTPUser {
			t.Errorf("%s: needs %v", name, c.Needs())
		}
	}
}

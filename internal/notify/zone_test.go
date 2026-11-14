package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/report/schema"
)

func mustZone(t testing.TB, name string) Zone {
	t.Helper()
	z, err := ParseZone(name)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestParseZone(t *testing.T) {
	for _, tc := range []struct{ in, name string }{
		{"", "UTC"}, {"UTC", "UTC"}, {"Asia/Tokyo", "Asia/Tokyo"}, {"America/New_York", "America/New_York"},
	} {
		z, err := ParseZone(tc.in)
		if err != nil || z.Name() != tc.name {
			t.Errorf("ParseZone(%q) = %q, %v", tc.in, z.Name(), err)
		}
	}
	// 決定: Local (実行環境のゾーン) は暗黙の値になるので受け付けない。略称 (JST) やオフセット (+09:00) は IANA 名ではない
	for _, bad := range []string{"Local", "local", "JST", "+09:00", "Asia/Tokio", "../etc/passwd", "/etc/localtime", " Asia/Tokyo", "Asia/Tokyo\n"} {
		if z, err := ParseZone(bad); err == nil {
			t.Errorf("ParseZone(%q) must fail, got %q", bad, z.Name())
		} else if !strings.Contains(err.Error(), "IANA") {
			t.Errorf("ParseZone(%q): the error must say what to write: %v", bad, err)
		}
	}
}

func TestZoneStamp(t *testing.T) {
	tokyo, utc := mustZone(t, "Asia/Tokyo"), Zone{}
	for _, tc := range []struct {
		z        Zone
		in, want string
	}{
		{tokyo, "2026-10-21T09:00:00Z", "2026-10-21T18:00:00+09:00"},
		{tokyo, "2026-10-21T20:30:00Z", "2026-10-22T05:30:00+09:00"}, // 日付をまたぐ
		{tokyo, "2026-10-21T09:00:00+00:00", "2026-10-21T18:00:00+09:00"},
		{utc, "2026-10-21T09:00:00Z", "2026-10-21T09:00:00Z"},
		{utc, "2026-10-21T18:00:00+09:00", "2026-10-21T09:00:00Z"},
		// 日付だけの値は UTC の日。時刻に直さない (意味をずらさない)
		{tokyo, "2026-10-21", "2026-10-21"},
		{tokyo, "", ""},
		{tokyo, "N/A", "N/A"},
		{tokyo, "<!channel>", "<!channel>"},
		// 年が 4 桁に収まらなくなる値は直さない (RFC 3339 で書けない)
		{tokyo, "9999-12-31T23:00:00Z", "9999-12-31T23:00:00Z"},
	} {
		if got := tc.z.Stamp(tc.in); got != tc.want {
			t.Errorf("%s Stamp(%q) = %q, want %q", tc.z.Name(), tc.in, got, tc.want)
		}
	}
}

func TestZoneSpan(t *testing.T) {
	for _, tc := range []struct{ zone, from, to, want string }{
		{"", "2026-10-20T09:00:00Z", "2026-10-21T09:00:00Z", "10/20 09:00 〜 10/21 09:00 (UTC)"},
		{"Asia/Tokyo", "2026-10-20T09:00:00Z", "2026-10-21T09:00:00Z", "10/20 18:00 〜 10/21 18:00 (JST)"},
		// 略称の無いゾーンは +04:00 の形
		{"Asia/Dubai", "2026-10-20T09:00:00Z", "2026-10-21T09:00:00Z", "10/20 13:00 〜 10/21 13:00 (+04:00)"},
		{"Asia/Kathmandu", "2026-10-20T09:00:00Z", "2026-10-21T09:00:00Z", "10/20 14:45 〜 10/21 14:45 (+05:45)"},
		// 夏時間の切り替わりをまたぐ窓は、それぞれに略称を付ける
		{"America/New_York", "2026-10-31T12:00:00Z", "2026-11-01T12:00:00Z", "10/31 08:00 (EDT) 〜 11/01 07:00 (EST)"},
		// 解釈できない値はそのまま (ラベルを付けない)
		{"Asia/Tokyo", "2026-10-20", "2026-10-21T09:00:00Z", "2026-10-20 〜 10/21 18:00 (JST)"},
		{"Asia/Tokyo", "x", "y", "x 〜 y"},
	} {
		if got := mustZone(t, tc.zone).span(tc.from, tc.to); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.zone, got, tc.want)
		}
	}
}

func TestConfigTimezone(t *testing.T) {
	// 雛形は timezone を明示する (暗黙の既定を持たない。ADR 0014)
	if !strings.Contains(webhookScaffold(), "\ntimezone: UTC") {
		t.Fatal("the scaffold must state timezone")
	}
	load := func(old, new string) (*Config, error) {
		body := webhookScaffold()
		if !strings.Contains(body, old) {
			t.Fatalf("scaffold lacks %q", old)
		}
		return LoadConfig(writeConfig(t, strings.Replace(body, old, new, 1)))
	}
	c, err := load("timezone: UTC", "timezone: Asia/Tokyo")
	if err != nil || c.Rules(false).Zone.Name() != "Asia/Tokyo" {
		t.Fatalf("%v %v", c, err)
	}
	// これまでの設定には timezone が無い。これまでどおり UTC で表示する
	c, err = load("timezone: UTC", "")
	if err != nil || c.Rules(false).Zone.Name() != "UTC" {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []string{"JST", "Local", "Asia/Tokio"} {
		if _, err := load("timezone: UTC", "timezone: "+bad); err == nil || !strings.Contains(err.Error(), "timezone") {
			t.Errorf("timezone %q must be rejected: %v", bad, err)
		}
	}
}

func tokyoRules(t testing.TB) Rules {
	r := rules
	r.Zone = mustZone(t, "Asia/Tokyo")
	return r
}

func withTokyo(t testing.TB) func(*Options) {
	return func(o *Options) { o.Rules = tokyoRules(t) }
}

// text の書式: 窓・初出・data の時刻・取れた期間が設定のゾーンになる。日付だけの値 (date) は UTC の日のまま。
func TestTextUsesConfiguredZone(t *testing.T) {
	s := &fakeSender{}
	run(t, inputDir(t, golden(t, "report.json"), ""), s, withTokyo(t))
	text := s.got[0].text
	for _, want := range []string{
		"2026-10-20T18:00:00+09:00 〜 2026-10-21T18:00:00+09:00", // window
		"初出 2026-10-21T18:00:00+09:00",
		"取れた期間 2026-10-21T05:00:00+09:00 〜 2026-10-21T18:00:00+09:00",
		"date 2026-10-20 (UTC)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "T09:00:00Z") {
		t.Errorf("a UTC time is left in:\n%s", text)
	}
}

func TestDetailTimeKeysUseZone(t *testing.T) {
	f := schema.Finding{ID: "f-1", Check: "unknown_assume_role", Summary: "引き受け", FirstSeen: "2026-10-20T08:00:00Z",
		Data: map[string]any{"count": 2.0, "last_time": "2026-10-21T01:00:00Z"}}
	want := "count 2 · last_time 2026-10-21T10:00:00+09:00 · 初出 2026-10-20T17:00:00+09:00 · `id: f-1`"
	if got := detail(f, mustZone(t, "Asia/Tokyo")); got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	// 時刻でない値 (credential report の N/A など) はそのまま
	f = schema.Finding{ID: "f-2", Check: "credential_hygiene", Summary: "使われていないキー", Data: map[string]any{"key": "1", "last_used": "N/A"}}
	if got := detail(f, mustZone(t, "Asia/Tokyo")); got != "key 1 · last_used N/A · `id: f-2`" {
		t.Errorf("got %s", got)
	}
}

func TestBlocksUseConfiguredZone(t *testing.T) {
	text := blocksText(t, golden(t, "report.json"), withTokyo(t))
	if !strings.Contains(text, "10/20 18:00 〜 10/21 18:00 (JST)") || strings.Contains(text, "(UTC)") {
		t.Fatalf("window:\n%s", text)
	}
	if !strings.Contains(text, "取れた期間 2026-10-21T05:00:00+09:00 〜 2026-10-21T18:00:00+09:00") {
		t.Fatalf("coverage:\n%s", text)
	}
	// on_quiet: short の 1 行も同じ
	s := &fakeSender{}
	run(t, inputDir(t, quietReport(t), ""), s, withBlocks, withTokyo(t))
	if got := PlainText(s.got[0].msg); !strings.Contains(got, "(JST): *新規なし*") {
		t.Fatalf("quiet:\n%s", got)
	}
	s = &fakeSender{}
	run(t, inputDir(t, quietReport(t), ""), s, withTokyo(t))
	if got := s.got[0].text; !strings.Contains(got, "+09:00 〜 ") || strings.Contains(got, "Z") {
		t.Fatalf("quiet text:\n%s", got)
	}
}

// 期間レポートの From / To は arata が UTC の日として決めた値。ゾーンを設定しても日付は変えず、UTC の日と明示する。
// 取れなかった run の時刻は設定のゾーンにする。
func TestPeriodDatesStayUTC(t *testing.T) {
	for _, mod := range [][]func(*Options){{withTokyo(t)}, {withTokyo(t), withBlocks}} {
		s := &fakeSender{}
		run(t, inputDir(t, golden(t, "period.json"), string(golden(t, "period.md"))), s, mod...)
		text := PlainText(s.got[0].msg)
		// text は arata の report.md (「(UTC、両端を含む)」と書いてある) を整形したもの
		if !strings.Contains(text, "2026-10-01 〜 2026-10-31 (UTC") || strings.Contains(text, "(JST)") {
			t.Errorf("period:\n%s", text)
		}
		if !strings.Contains(text, "`RUN_MISSED` 2026-10-07T18:00:00+09:00 〜 2026-10-20T18:00:00+09:00") || strings.Contains(text, "00Z") {
			t.Errorf("runs_missing:\n%s", text)
		}
		// 日次推移の日 (UTC の日) は変えない
		if len(mod) == 1 && !strings.Contains(text, "| 2026-10-06 | 0 | 123 |") {
			t.Errorf("metrics:\n%s", text)
		}
	}
	// blocks の期間の欄にも UTC の日と書く (UTC のままの設定でも)
	s := &fakeSender{}
	run(t, inputDir(t, golden(t, "period.json"), ""), s, withBlocks)
	if text := PlainText(s.got[0].msg); !strings.Contains(text, "*期間* 2026-10-01 〜 2026-10-31 (UTC)") {
		t.Errorf("period blocks:\n%s", text)
	}
}

func TestStaleInputShowsZone(t *testing.T) {
	stale := goldenRun(t)
	stale.GeneratedAt = "2026-10-19T00:00:00Z"
	for _, mod := range [][]func(*Options){{withTokyo(t)}, {withTokyo(t), withBlocks}} {
		s := &fakeSender{}
		_, logs := run(t, inputDir(t, marshal(t, stale), ""), s, mod...)
		if text := PlainText(s.got[0].msg); !strings.Contains(text, "generated_at 2026-10-19T09:00:00+09:00 は max_age") {
			t.Errorf("stale:\n%s", text)
		}
		// ログは report.json の値のまま (機械が読む)
		if !strings.Contains(logs.String(), "2026-10-19T00:00:00Z") {
			t.Errorf("logs: %s", logs)
		}
	}
}

// LLM には report.json を原文 (UTC) のまま渡し、文中に時刻を書くときの規則を system に足す。UTC の設定では足さない (これまでと同じ system)。
func TestLLMIsToldTheZone(t *testing.T) {
	for _, blocks := range []bool{false, true} {
		first := fixture(t, "ok.json")
		if blocks {
			first = `{"summary": "要約", "next": []}`
		}
		for _, tokyo := range []bool{true, false} {
			l := &fakeLLM{responses: []string{first, fixture(t, "proposals_ok.json")}}
			mod := []func(*Options){withLLM(l)}
			if blocks {
				mod = append(mod, withBlocks)
			}
			if tokyo {
				mod = append(mod, withTokyo(t))
			}
			run(t, inputDir(t, withProposals(t, goldenRun(t), testProposals(t)), ""), &fakeSender{}, mod...)
			if len(l.systems) != 2 {
				t.Fatalf("calls: %d", len(l.systems))
			}
			for i, sys := range l.systems {
				has := strings.Contains(sys, "Asia/Tokyo") && strings.Contains(sys, "UTC+09:00") && strings.Contains(sys, "JST")
				if tokyo && !has {
					t.Errorf("blocks=%v call %d: the system prompt lacks the zone rule", blocks, i)
				}
				if !tokyo && strings.Contains(sys, "タイムゾーン") {
					t.Errorf("blocks=%v call %d: UTC must not add the zone rule", blocks, i)
				}
			}
			if !strings.Contains(string(l.inputs[0]), "2026-10-21T09:00:00Z") || strings.Contains(string(l.inputs[0]), "+09:00") {
				t.Errorf("the report must be passed as is")
			}
		}
	}
}

func TestZonePromptRule(t *testing.T) {
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	if got := (Zone{}).promptRule(at); got != "" {
		t.Errorf("UTC: %q", got)
	}
	got := mustZone(t, "Asia/Kathmandu").promptRule(at)
	if !strings.Contains(got, "Asia/Kathmandu") || !strings.Contains(got, "UTC+05:45") || !strings.Contains(got, "(UTC)") {
		t.Errorf("got %q", got)
	}
}

// 設定のファイル由来の名前 (ParseZone) と、ログ由来の値 (Stamp / span) を解釈する。
func FuzzZone(f *testing.F) {
	for _, s := range []string{"", "UTC", "Asia/Tokyo", "Local", "JST", "../x", "America/New_York", "Etc/GMT+12", "Asia/Kathmandu"} {
		f.Add(s, "2026-10-21T09:00:00Z", "2026-10-21")
	}
	f.Add("Asia/Tokyo", "9999-12-31T23:59:59Z", "0000-01-01T00:00:00+14:00")
	f.Add("Pacific/Kiritimati", "2026-10-21T09:00:00.123456789-07:00", "<!channel>\n`x`")
	// 秒の端数を持つオフセットの時代 (RFC 3339 で書けないオフセット)
	f.Add("Asia/Katmandu", "0000-10-01T0:00:00Z", "0")
	f.Add("Africa/Monrovia", "1970-06-01T12:00:00Z", "1972-01-07T00:44:29.999999999Z")
	f.Add("Europe/Amsterdam", "1930-01-01T00:00:00.5+00:19", "1937-06-30T23:40:28Z")
	f.Fuzz(func(t *testing.T, name, a, b string) {
		z, err := ParseZone(name)
		if err != nil {
			z = Zone{} // 不正な名前は設定エラー。以降は UTC で性質を確かめる
		} else if z.Name() != "UTC" && z.Name() != name {
			t.Fatalf("ParseZone(%q) became %q", name, z.Name())
		}
		if strings.EqualFold(z.Name(), "Local") {
			t.Fatalf("ParseZone(%q) must not return the host's zone", name)
		}
		for _, s := range []string{a, b} {
			got := z.Stamp(s)
			orig, perr := time.Parse(time.RFC3339, s)
			if perr != nil {
				// 時刻でない値は 1 文字も変えない (呼び出し側のエスケープ・1 行化にそのまま渡る)
				if got != s {
					t.Fatalf("Stamp(%q) changed a non-time value to %q", s, got)
				}
				continue
			}
			// 時刻は同じ瞬間を指す RFC 3339 のまま (意味をずらさない)。使う文字は数字と T : - + . Z だけ
			back, err := time.Parse(time.RFC3339, got)
			if err != nil || !back.Equal(orig) {
				t.Fatalf("Stamp(%q) = %q does not denote the same instant (%v)", s, got, err)
			}
			if strings.Trim(got, "0123456789T:-+.Z") != "" {
				t.Fatalf("Stamp(%q) = %q has unexpected characters", s, got)
			}
			// オフセットを丸めない: 直したなら、書いたオフセットはそのゾーンのその瞬間の本当のオフセットか、UTC (秒の端数があって書けないとき) だけ。
			// 直さずに返した値 (直すと年が 4 桁に収まらない) は元のまま
			_, wrote := back.Zone()
			if _, real := orig.In(z.location()).Zone(); got != s && wrote != real && !(real%60 != 0 && wrote == 0 && strings.HasSuffix(got, "Z")) {
				t.Fatalf("Stamp(%q) = %q wrote the offset %ds, the zone's offset is %ds", s, got, wrote, real)
			}
		}
		// span は解釈できた側だけを書き換える。解釈できない値はそのまま含む
		span := z.span(a, b)
		for _, s := range []string{a, b} {
			if _, err := time.Parse(time.RFC3339, s); err != nil && !strings.Contains(span, s) {
				t.Fatalf("span(%q, %q) = %q dropped a non-time value", a, b, span)
			}
		}
		if _, e1 := time.Parse(time.RFC3339, a); e1 == nil {
			if _, e2 := time.Parse(time.RFC3339, b); e2 == nil && strings.Trim(span, "0123456789/: 〜()+-ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
				t.Fatalf("span(%q, %q) = %q has unexpected characters", a, b, span)
			}
		}
		// stampInText は時刻の形の部分だけを変える (それ以外は 1 文字も変えない)。UTC なら何も変えない
		text := a + " " + b + "\n" + b
		out := z.stampInText(text)
		if stampRe.ReplaceAllString(out, "") != stampRe.ReplaceAllString(text, "") {
			t.Fatalf("stampInText(%q) = %q changed text outside the timestamps", text, out)
		}
		if z.Name() == "UTC" && out != text {
			t.Fatalf("stampInText must not change anything in UTC: %q -> %q", text, out)
		}
		_ = z.promptRule(time.Unix(int64(len(a)), 0))
	})
}

// 秒の端数を持つオフセット (標準時が決まる前の地方平均時など。Africa/Monrovia は 1972 年まで -00:44:30) は RFC 3339 で書けない。
// オフセットを分に丸めると別の瞬間になるので、その時刻は UTC で書く (ファズで見つけた。ADR 0041)。
func TestZoneSecondsOffsetFallsBackToUTC(t *testing.T) {
	for _, c := range []struct{ zone, in, want string }{
		{"Africa/Monrovia", "1970-06-01T12:00:00Z", "1970-06-01T12:00:00Z"},
		{"Africa/Monrovia", "1970-06-01T12:00:00.5+09:00", "1970-06-01T03:00:00.5Z"},
		{"Asia/Kathmandu", "0000-10-01T00:00:00Z", "0000-10-01T00:00:00Z"},
		{"Europe/Amsterdam", "1930-01-01T00:00:00Z", "1930-01-01T00:00:00Z"},
		// 分単位のオフセットになってからは、これまでどおりそのゾーンで書く
		{"Africa/Monrovia", "1980-06-01T12:00:00Z", "1980-06-01T12:00:00Z"},
		{"Asia/Kathmandu", "2026-10-21T09:00:00Z", "2026-10-21T14:45:00+05:45"},
		{"Europe/Amsterdam", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00+01:00"},
	} {
		z := mustZone(t, c.zone)
		got := z.Stamp(c.in)
		if got != c.want {
			t.Errorf("%s Stamp(%q) = %q, want %q", c.zone, c.in, got, c.want)
		}
		orig, _ := time.Parse(time.RFC3339, c.in)
		if back, err := time.Parse(time.RFC3339, got); err != nil || !back.Equal(orig) {
			t.Errorf("%s Stamp(%q) = %q does not denote the same instant (%v)", c.zone, c.in, got, err)
		}
	}
	z := mustZone(t, "Africa/Monrovia")
	// 期間の表示も同じ扱い: 秒の端数のある側は UTC の時刻と (UTC) のラベル
	if got, want := z.span("1970-06-01T12:00:00Z", "1970-06-02T12:00:00Z"), "06/01 12:00 〜 06/02 12:00 (UTC)"; got != want {
		t.Errorf("span = %q, want %q", got, want)
	}
	if got, want := z.span("1970-06-01T12:00:00Z", "1980-06-01T12:00:00Z"), "06/01 12:00 (UTC) 〜 06/01 12:00 (GMT)"; got != want {
		t.Errorf("span = %q, want %q", got, want)
	}
	// 文中の時刻も同じ瞬間のまま
	if got, want := z.stampInText("at 1970-06-01T12:00:00+09:00."), "at 1970-06-01T03:00:00Z."; got != want {
		t.Errorf("stampInText = %q, want %q", got, want)
	}
	// LLM への時刻の書き方の節も、その時点では足さない (規則が書く時刻と同じく UTC のまま書かせる)
	if rule := z.promptRule(time.Date(1970, 6, 1, 12, 0, 0, 0, time.UTC)); rule != "" {
		t.Errorf("promptRule must be empty while the offset has seconds:\n%s", rule)
	}
	if rule := z.promptRule(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)); !strings.Contains(rule, "UTC+00:00)") {
		t.Errorf("promptRule:\n%s", rule)
	}
}

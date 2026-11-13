package notify

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	// 決定 (aratam 設計書 4-3 章): タイムゾーンのデータをバイナリに埋め込む。aratam は単一の静的バイナリで、
	// コンテナや最小構成のホストには tzdata が無いことがある。実行環境のデータがあればそちらが優先される (Go の標準の順)。
	_ "time/tzdata"
)

// Zone は通知に出す時刻のタイムゾーン (aratam.yaml の timezone)。ゼロ値は UTC。
//
// 決定 (aratam 設計書 4-3 章):
//   - 変えるのは表示だけ。arata の集計の日の区切り・窓・report.json は UTC のまま。
//   - 時刻 (RFC 3339) は設定のゾーンに直す。日付だけの値 (data.date、期間レポートの from / to) は arata が UTC の日として決めた値なので直さず、(UTC) と書く。
//   - LLM には report.json を原文のまま渡す (書き換えない)。文中に時刻を書くときの規則だけを system に足す (promptRule)。
type Zone struct {
	loc *time.Location
}

// zoneName は IANA 名の形 (Asia/Tokyo、Etc/GMT+9、UTC)。パスの区切りや空白を含む値を実行環境のファイルの探索に渡さない。
var zoneName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9][A-Za-z0-9_+-]*)*$`)

// ParseZone は IANA のタイムゾーン名を解釈する。空は UTC (timezone の無い設定は、これまでどおり UTC で表示する)。
//
// 決定: Local は受け付けない。実行環境の TZ で表示が変わり、設定に書いた値にならないため (暗黙の既定を持たない。ADR 0014)。
// 略称 (JST) やオフセット (+09:00) も受け付けない。略称は一意でなく、オフセットは夏時間を表せないため。
func ParseZone(name string) (Zone, error) {
	if name == "" {
		return Zone{}, nil
	}
	bad := fmt.Errorf("timezone must be an IANA time zone name such as Asia/Tokyo or UTC (got %q)", clipRunes(name, 64))
	if len(name) > 64 || !zoneName.MatchString(name) || strings.EqualFold(name, "Local") {
		return Zone{}, bad
	}
	loc, err := time.LoadLocation(name)
	if err != nil || loc.String() != name {
		return Zone{}, bad
	}
	return Zone{loc: loc}, nil
}

func (z Zone) location() *time.Location {
	if z.loc == nil {
		return time.UTC
	}
	return z.loc
}

// Name は IANA 名 (ゼロ値は UTC)。
func (z Zone) Name() string { return z.location().String() }

func (z Zone) isUTC() bool { return z.Name() == "UTC" }

// in は t を設定のゾーンで返す。ただし、その時刻のオフセットに秒の端数があれば UTC で返す。
//
// 決定 (ADR 0041。ファズで見つけた): 標準時が決まる前の地方平均時など (Asia/Kathmandu の古い時代は +05:41:16、Africa/Monrovia は 1972 年まで -00:44:30) は、
// オフセットを RFC 3339 (分まで) で書けない。分に丸めて書くと 60 秒未満ずれた別の瞬間になり、秒まで書くと RFC 3339 でなくなる
// (読む側と stampRe が解釈できない)。その時刻だけ UTC で書けば、同じ瞬間を指す RFC 3339 のままで、オフセットも丸めない。
// 監査の報告の時刻 (現在) では起きず、当たるのはログ由来の古い・壊れた時刻だけなので、表示の形を増やさない。
func (z Zone) in(t time.Time) time.Time {
	t = t.In(z.location())
	if _, offset := t.Zone(); offset%60 != 0 {
		return t.UTC()
	}
	return t
}

// label はその時刻でのゾーンの略称 (JST、EDT)。略称の無いゾーンは +04:00 の形。秒の端数のあるオフセットの時刻は UTC (in)。
func (z Zone) label(t time.Time) string {
	t = z.in(t)
	if name, _ := t.Zone(); name != "" && name[0] != '+' && name[0] != '-' {
		return name
	}
	return t.Format("-07:00")
}

// parseStamp は RFC 3339 の時刻を設定のゾーンで返す。時刻でない・直すと年が 4 桁に収まらない (RFC 3339 で書けない) なら false。
func (z Zone) parseStamp(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	t = z.in(t)
	if y := t.Year(); y < 0 || y > 9999 {
		return time.Time{}, false
	}
	return t, true
}

// Stamp は RFC 3339 の時刻を設定のゾーンの RFC 3339 (2026-10-21T18:00:00+09:00) に直す。オフセットが付くので、ラベルが無くても一意に読める。
// 時刻でない値 (日付だけ、N/A、空) は 1 文字も変えずに返す (ログ由来の値なので、呼び出し側のエスケープ・1 行化にそのまま渡す)。
func (z Zone) Stamp(s string) string {
	t, ok := z.parseStamp(s)
	if !ok {
		return s
	}
	return t.Format(time.RFC3339Nano)
}

// stampInText は文章の中の RFC 3339 の時刻を設定のゾーンに直す (期間レポートの text の書式で、arata が書いた report.md を送るときに使う)。
// UTC なら 1 文字も変えない (原文のまま)。時刻の形でない部分には触れない。
//
// 決定: report.md の中のログ由来の文 (summary) に時刻の形の文字列があれば、それも同じ瞬間を指す別の表記になる。
// 意味は変わらず、置き換え後の文字は数字と T : - + . Z だけなので、そのまま直す (節ごとに見分けない)。
func (z Zone) stampInText(s string) string {
	if z.isUTC() {
		return s
	}
	return stampRe.ReplaceAllStringFunc(s, z.Stamp)
}

var stampRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})`)

// span は blocks の期間の表示 (10/20 18:00 〜 10/21 18:00 (JST))。
// 夏時間の切り替わりをまたいで略称が違うときは、それぞれに付ける。時刻でない値はそのまま (ラベルを付けない)。
func (z Zone) span(from, to string) string {
	f, okF := z.parseStamp(from)
	t, okT := z.parseStamp(to)
	const layout = "01/02 15:04"
	if okF && okT && z.label(f) == z.label(t) {
		return f.Format(layout) + " 〜 " + t.Format(layout) + " (" + z.label(t) + ")"
	}
	if okF {
		from = f.Format(layout) + " (" + z.label(f) + ")"
	}
	if okT {
		to = t.Format(layout) + " (" + z.label(t) + ")"
	}
	return from + " 〜 " + to
}

// dateSpan は日付だけの期間 (期間レポートの from / to) の表示。arata が UTC の日として決めた値なので、ゾーンに依らず UTC と書く。
func dateSpan(from, to string) string {
	return from + " 〜 " + to + " (UTC)"
}

// promptRule は LLM の system の末尾に足す、時刻の書き方の節。UTC なら何も足さない (これまでと同じ system)。
// at はオフセットと略称を決める時刻 (報告の generated_at)。
//
// 決定: 規則が書く時刻 (期間・初出・主要キー・取れた期間) は Stamp / span で確実に直す。LLM の文の中の時刻は LLM が直すので、
// 検証はしない (文中の時刻は補足で、判定には使わない)。直し間違いを減らすため、オフセットを数値で渡す。
//
// 決定: at のオフセットに秒の端数があれば何も足さない。規則が書く時刻が UTC になる (in) ので、LLM にも UTC のまま書かせる。
func (z Zone) promptRule(at time.Time) string {
	if z.isUTC() || z.in(at).Location() == time.UTC {
		return ""
	}
	label := z.label(at)
	return fmt.Sprintf(`

---

# 時刻の書き方

通知に出す時刻のタイムゾーンは %s (この報告の時点で UTC%s) です。report.json の時刻は UTC です。
- 説明の文に時刻を書くときは %s に直し、時刻の後ろに「%s」と書く。
- 日付だけの値 (data の date、期間レポートの from / to、metrics の日) は UTC の日。直さずに、後ろに「(UTC)」と書く。
- finding_id などの識別子の中の時刻は直さない。`, z.Name(), at.In(z.location()).Format("-07:00"), z.Name(), label)
}

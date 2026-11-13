package allowlist

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// EntryError は Parse が 1 つの項目 (principals[2] など) で見つけた検証エラー。
// 文言は従来どおり「principals[2]: …」。Check が項目の行番号を引くために、節と番号を持つ。
type EntryError struct {
	Section string // principals / source_ips / secrets_access / assume_destinations
	Index   int
	Err     error
}

func (e *EntryError) Error() string { return fmt.Sprintf("%s[%d]: %v", e.Section, e.Index, e.Err) }
func (e *EntryError) Unwrap() error { return e.Err }

func entryErr(section string, i int, format string, args ...any) error {
	return &EntryError{Section: section, Index: i, Err: fmt.Errorf(format, args...)}
}

// Problem は Check が見つけた問題 1 件。
type Problem struct {
	// Line は問題のある項目の行 (1 始まり)。分からなければ 0 (YAML の構文や型の誤りは Msg の中に行がある)。
	Line int
	// Warn は警告 (run は止まらない)。false ならエラーで、run / doctor も同じ理由で止まる。
	Warn bool
	Msg  string
}

// Check は allowlist.yaml をオフラインで検査する (`arata config check`)。
//
// 決定:
//
//   - エラーの規則は Parse そのもの (run / doctor が起動時にする検証)。ここでは規則を足さず、項目の行番号を添えるだけにする。
//     Parse は最初のエラーで止まるので、エラーは多くても 1 件
//
//   - 同じ主体 (arn / account / arn_pattern が同じ) の項目の重複は警告にする。run は重複を受け付ける (expected_denied は項目ごとに
//     書いてよく、和で判定する) のでエラーにはできないが、expires・tags・dynamic_source は 1 つの項目のものしか使われないので、
//     片方だけ直したつもりの誤りになりやすい
//
//   - assume_destinations (ADR 0047) の重なる項目 (同じアカウントで、片方がアカウント全体か、絞ったロールの集合が同じ) も警告にする。
//     アカウント全体の項目があるのにロールを絞った項目を足しても絞れていない
//
//   - assume_destinations の、at の時点で期限の切れた項目は警告にする。run は止まらないが、その行き先への引き受けは次の run から high で
//     報告される (契約が続くなら期限を延ばし、終わったなら項目を消す)。principals の期限切れは見ない (従来どおり。期限切れは finding で知らせる)
//
// エラーがあれば List は nil。
func Check(b []byte, at time.Time) (*List, []Problem) {
	l, err := Parse(b)
	if err != nil {
		p := Problem{Msg: err.Error()}
		var ee *EntryError
		if errors.As(err, &ee) {
			p.Line = entryLines(b, ee.Section)[ee.Index]
		}
		return nil, []Problem{p}
	}
	var out []Problem
	lines := entryLines(b, "principals")
	first := map[string]int{}
	for i := range l.Principals {
		s := l.Principals[i].Subject()
		j, dup := first[s]
		if !dup {
			first[s] = i
			continue
		}
		out = append(out, Problem{Line: lines[i], Warn: true, Msg: fmt.Sprintf(
			"principals[%d]: duplicate of principals[%d] (line %d): %s (expires, tags and dynamic_source are taken from only one of them; merge the entries)", i, j, lines[j], s)})
	}
	lines = entryLines(b, "assume_destinations")
	for i := range l.AssumeDestinations {
		e := &l.AssumeDestinations[i]
		for j := 0; j < i; j++ {
			if x := &l.AssumeDestinations[j]; sameDestination(x.Account, x.Roles, e.Account, e.Roles) {
				out = append(out, Problem{Line: lines[i], Warn: true, Msg: fmt.Sprintf(
					"assume_destinations[%d]: duplicate of assume_destinations[%d] (line %d): account %s (an entry without roles covers the whole account; merge the entries)", i, j, lines[j], e.Account)})
				break
			}
		}
		if !e.active(at) {
			out = append(out, Problem{Line: lines[i], Warn: true, Msg: fmt.Sprintf(
				"assume_destinations[%d]: expired on %s: account %s (assuming roles there is reported as high again; extend expires if the work continues, or remove the entry)", i, e.Expires, e.Account)})
		}
	}
	return l, out
}

// entryLines は節 (principals など) の項目の番号 → 行。取れなければ空 (引くと 0)。
func entryLines(b []byte, section string) map[int]int {
	out := map[int]int{}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return out
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != section || root.Content[i+1].Kind != yaml.SequenceNode {
			continue
		}
		for j, n := range root.Content[i+1].Content {
			out[j] = n.Line
		}
	}
	return out
}

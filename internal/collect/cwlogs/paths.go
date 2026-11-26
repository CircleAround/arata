package cwlogs

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/CircleAround/arata/internal/pathids"
)

// パスの型 (path_ids。ADR 0071 の 2 節・0087 の 5・6 節) の、doctor 用の集計。
//
// クエリの形 (request_lines。ユーザー ID を読む設定のとき):
//
//	<1 段目の前まで> | <pathids.Query(rl_path)> | stats …, earliest(pi_tpl) as tpl, latest(rl_v_user_id) as user_id … by rl_request_id
//	| filter ispresent(tpl) | filter ispresent(user_id)
//	| stats sum(rl_starts) as rl_pn by day, tpl, user_kind, user_id
//	| stats sum(rl_pn) as path_requests, count(*) as path_users by day, tpl
//
// 決定 (0071 の 2 節の「doctor の path_ids の行」):
//   - 結果に出すのは (日, 型) ごとの件数と利用者の数だけ。利用者の ID と対象 ID は Insights の中で数えるだけに使い、持ち帰らない
//   - 型は Insights の結果を Sanitize してから使う (信用しない入力)。Sanitize で同じ型になった行は足す (利用者の数も足すので、1 人の型を見落とす向きにはならない)
//   - ユーザー ID を読まないソース (1 行のログなど) では、型ごとの件数だけを数える
const (
	rlTemplate      = "tpl" // request_lines の 1 段目の列 (最初の行のパスの型)
	pathRequestsCol = "path_requests"
	pathUsersCol    = "path_users"
	rlPathN         = "rl_pn"
)

// PathTemplate は型 1 つの集計。
type PathTemplate struct {
	Template string
	Requests int64
	// MaxUsers は 1 日に触った利用者の数の、日ごとの最大 (ユーザー ID を読まないソースでは -1)。
	MaxUsers int64
}

// PathSummary は [from, to) の型の一覧 (件数の多い順)。
type PathSummary struct {
	Templates []PathTemplate
	// Users はユーザー ID で数えたか (request_lines で request.user_id があるとき)。
	Users bool
	// Truncated は結果が行の上限に当たった (件数の少ない型が欠けている)。
	Truncated bool
}

// PathTemplatesQuery は型ごとの件数 (と利用者の数) のクエリ。path_ids の無いソースでは空。
func PathTemplatesQuery(p Profile) string {
	if p.paths == nil {
		return ""
	}
	var b strings.Builder
	users := p.req != nil && p.req.hasUserField("user_id")
	b.WriteString(p.head("1d", "day", "", nil, false, false, users, true))
	switch {
	case p.req == nil:
		b.WriteString("\n| filter ispresent(" + pathids.TemplateField + ")")
		b.WriteString("\n| stats count(*) as " + pathRequestsCol + " by bin(1d) as day, " + pathids.TemplateField)
	case users:
		b.WriteString("\n| filter ispresent(" + rlTemplate + ")\n| filter ispresent(user_id)")
		b.WriteString("\n| stats sum(" + rlStarts + ") as " + rlPathN + " by day, " + rlTemplate + ", user_kind, user_id")
		b.WriteString("\n| stats sum(" + rlPathN + ") as " + pathRequestsCol + ", count(*) as " + pathUsersCol + " by day, " + rlTemplate)
	default:
		b.WriteString("\n| filter ispresent(" + rlTemplate + ")")
		b.WriteString("\n| stats sum(" + rlStarts + ") as " + pathRequestsCol + " by day, " + rlTemplate)
	}
	b.WriteString("\n| sort " + pathRequestsCol + " desc")
	b.WriteString("\n| limit " + strconv.Itoa(MaxRows))
	return b.String()
}

// PathTemplates は [from, to) の型の一覧を返す (クエリを 1 本流す)。path_ids の無いソースでは nil。
func (c *Collector) PathTemplates(ctx context.Context, from, to time.Time) (*PathSummary, error) {
	q := PathTemplatesQuery(c.prof)
	if q == "" {
		return nil, nil
	}
	rows, err := c.Query(ctx, q, from, c.queryEnd(to))
	if err != nil {
		return nil, err
	}
	if c.prof.req != nil {
		rows = inRange(rows, "day", to)
	}
	s := &PathSummary{Users: strings.Contains(q, pathUsersCol), Truncated: len(rows) >= MaxRows}
	col := pathids.TemplateField
	if c.prof.req != nil {
		col = rlTemplate
	}
	clamp := func(v string) int64 { return int64(math.Max(0, math.Min(math.Floor(num(v)), maxRequestCount))) }
	type acc struct {
		requests int64
		users    map[string]int64 // 日 → 利用者の数
	}
	byTpl := map[string]*acc{}
	for _, r := range rows {
		t := c.prof.paths.Sanitize(r[col])
		if t == "" {
			continue
		}
		a := byTpl[t]
		if a == nil {
			a = &acc{users: map[string]int64{}}
			byTpl[t] = a
		}
		a.requests += clamp(r[pathRequestsCol])
		a.users[r["day"]] += clamp(r[pathUsersCol])
	}
	for t, a := range byTpl {
		pt := PathTemplate{Template: t, Requests: a.requests, MaxUsers: -1}
		if s.Users {
			pt.MaxUsers = 0
			for _, n := range a.users {
				pt.MaxUsers = max(pt.MaxUsers, n)
			}
		}
		s.Templates = append(s.Templates, pt)
	}
	sort.Slice(s.Templates, func(i, j int) bool {
		a, b := s.Templates[i], s.Templates[j]
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return a.Template < b.Template
	})
	return s, nil
}

// SingleUserExamples は、1 日に 1 人の利用者しか触らなかった型の例を、件数の多い順に n 個まで返す。
// 決定: 名前・ログイン名の区間 (templates に書き足すべき位置) を見つけるための例で、その値は出さない。
// 2 人以上が触った型の同じ位置にある値 (`users`・`orders` のような固定の区間) だけを残し、ほかの区間は `<長さ>` に伏せる。印 (:id など) はそのまま。
func (s *PathSummary) SingleUserExamples(n int) []string {
	if s == nil || !s.Users {
		return nil
	}
	shared := map[int]map[string]bool{}
	for _, t := range s.Templates {
		if t.MaxUsers < 2 {
			continue
		}
		for i, seg := range strings.Split(t.Template, "/") {
			if shared[i] == nil {
				shared[i] = map[string]bool{}
			}
			shared[i][seg] = true
		}
	}
	var out []string
	for _, t := range s.Templates {
		if t.MaxUsers != 1 || len(out) >= n {
			continue
		}
		segs := strings.Split(t.Template, "/")
		for i, seg := range segs {
			if i == 0 || shared[i][seg] || strings.HasPrefix(seg, ":") || seg == pathids.More {
				continue
			}
			segs[i] = "<" + strconv.Itoa(utf8.RuneCountInString(seg)) + ">"
		}
		out = append(out, strings.Join(segs, "/"))
	}
	return out
}

// SingleUser は、1 日に 1 人の利用者しか触らなかった型の数。
func (s *PathSummary) SingleUser() int {
	n := 0
	for _, t := range s.Templates {
		if t.MaxUsers == 1 {
			n++
		}
	}
	return n
}

package cwlogstest

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// Event はログの 1 行 (平坦化したフィールド名 → 値)。N は同じ行の繰り返し数 (0 なら 1)。
type Event struct {
	Time   time.Time
	Fields map[string]string
	N      int
}

// Sim はログの行の集まりから、Insights の集計クエリの結果を作るフェイク。クエリを上から順に解釈する。
//
//   - `fields <a> as <b>` (別名)、`fields bin(<N><d|h|m>) as <name>` (行の時刻の区切り)、
//     `fields if(<f> > 0 and not ispresent(<g>), "<値>", <g>) as <name>` (stats の後の補い。collector が作る形だけ)
//   - `parse <field> /<re>/` (名前付きキャプチャをフィールドにする。同じ名前を 2 度定義するクエリは、本物と同じく受け付けない)
//   - `filter ispresent(<f>)`。それ以外の `filter` はクエリから読まず、テストが Go で渡す (Response に渡す関数)。
//     評価する位置は、最初の stats より後ろに filter があればその位置 (リクエスト単位の filter)、無ければ最初の stats の直前
//   - `stats <集計>, ... [by <軸>, ...]` を何段でも (ADR 0051。2 段目以降は前の段の結果の行を集計する)。
//     集計は count(*) / count(<f>) / sum(<f>) / min(<f>) / max(<f>) / earliest(<f>) / latest(<f>)。
//     earliest / latest は、その項目の無い行を飛ばす。軸は `bin(<N><d|h|m>) as <name>` かフィールド
//   - `limit`
//
// 問い合わせの範囲 [StartTime, EndTime] (両端を含む) の行だけを数える。group by のフィールドが無い行は null の組にまとめ、結果の行にそのフィールドを出さない。
// 後ろに stats が続く段の min(@timestamp) / max(@timestamp) は、エポックからのミリ秒の数として渡す (時刻の型では渡らない。ADR 0051 の確かめた事実)。
type Sim struct {
	Events []Event
}

// Response は filter を通った行を集計する応答。filter が nil なら全行。
func (s *Sim) Response(filter func(map[string]string) bool) Response {
	return Response{RowsFor: func(in *cwl.StartQueryInput) []map[string]string {
		return s.Rows(aws.ToString(in.QueryString), time.Unix(aws.ToInt64(in.StartTime), 0), time.Unix(aws.ToInt64(in.EndTime), 0), filter)
	}}
}

var (
	parseLine   = regexp.MustCompile(`^parse (\S+) /(.*)/$`)
	statsLine   = regexp.MustCompile(`^stats (.*?)(?: by (.*))?$`)
	binExpr     = regexp.MustCompile(`^bin\((\d+)([dhm])\) as (\S+)$`)
	aggExpr     = regexp.MustCompile(`^(count|sum|min|max|earliest|latest)\(([^)]*)\) as (\S+)$`)
	ifExpr      = regexp.MustCompile(`^fields if\((\S+) > 0 and not ispresent\((\S+)\), "([^"]*)", (\S+)\) as (\S+)$`)
	presentExpr = regexp.MustCompile(`^filter ispresent\((\S+)\)$`)
)

const simTime = "2006-01-02 15:04:05.000"

type agg struct{ fn, arg, name string }

// simRow は処理の途中の 1 行。t は行の時刻 (stats の後は組の最初の時刻)、n は重み (行の繰り返し数。stats の後は 1)。
type simRow struct {
	f map[string]string
	t time.Time
	n float64
}

type simOp func(rows []simRow) []simRow

func binDur(n, unit string) time.Duration {
	v, _ := strconv.Atoi(n)
	return time.Duration(v) * map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "m": time.Minute}[unit]
}

func each(fn func(r simRow)) simOp {
	return func(rows []simRow) []simRow {
		for _, r := range rows {
			fn(r)
		}
		return rows
	}
}

func keep(fn func(f map[string]string) bool) simOp {
	return func(rows []simRow) []simRow {
		out := rows[:0:0]
		for _, r := range rows {
			if fn(r.f) {
				out = append(out, r)
			}
		}
		return out
	}
}

// Rows はクエリを [from, to] の行に流した結果。
func (s *Sim) Rows(query string, from, to time.Time, filter func(map[string]string) bool) []map[string]string {
	lines := strings.Split(query, "\n")
	for i := range lines {
		lines[i] = strings.TrimPrefix(strings.TrimSpace(lines[i]), "| ")
	}
	nStats := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "stats ") {
			nStats++
		}
	}
	var ops []simOp
	defined := map[string]bool{}
	define := func(name string) {
		if defined[name] {
			panic("sim: ephemeral field is already defined: " + name)
		}
		defined[name] = true
	}
	firstStats, userFilter := -1, -1
	limit := -1
	sortBy := ""
	seenStats := 0
	for _, line := range lines {
		switch {
		case ifExpr.MatchString(line):
			m := ifExpr.FindStringSubmatch(line)
			define(m[5])
			ops = append(ops, each(func(r simRow) {
				switch {
				case num(r.f[m[1]]) > 0 && r.f[m[2]] == "":
					r.f[m[5]] = m[3]
				case r.f[m[4]] != "":
					r.f[m[5]] = r.f[m[4]]
				}
			}))
		case strings.HasPrefix(line, "fields "):
			for _, part := range strings.Split(strings.TrimPrefix(line, "fields "), ", ") {
				if bm := binExpr.FindStringSubmatch(part); bm != nil {
					d, name := binDur(bm[1], bm[2]), bm[3]
					define(name)
					ops = append(ops, each(func(r simRow) { r.f[name] = r.t.UTC().Truncate(d).Format(simTime) }))
					continue
				}
				if a, b, ok := strings.Cut(part, " as "); ok && !strings.Contains(a, "(") {
					a, b := a, b
					define(b)
					ops = append(ops, each(func(r simRow) {
						if v, ok := r.f[a]; ok {
							r.f[b] = v
						}
					}))
				}
			}
		case parseLine.MatchString(line):
			m := parseLine.FindStringSubmatch(line)
			field, re := m[1], regexp.MustCompile(m[2])
			for _, n := range re.SubexpNames() {
				if n != "" {
					define(n)
				}
			}
			ops = append(ops, each(func(r simRow) {
				v, ok := r.f[field]
				if !ok {
					return
				}
				sm := re.FindStringSubmatch(v)
				if sm == nil {
					return
				}
				for i, n := range re.SubexpNames() {
					if n != "" && i < len(sm) && sm[i] != "" {
						r.f[n] = sm[i]
					}
				}
			}))
		case presentExpr.MatchString(line):
			name := presentExpr.FindStringSubmatch(line)[1]
			ops = append(ops, keep(func(f map[string]string) bool { return f[name] != "" }))
		case strings.HasPrefix(line, "filter "):
			if firstStats >= 0 {
				userFilter = len(ops)
				ops = append(ops, nil) // 後で filter に差し替える
			}
		case strings.HasPrefix(line, "stats "):
			m := statsLine.FindStringSubmatch(line)
			if m == nil {
				panic("sim: unsupported stats " + line)
			}
			seenStats++
			if firstStats < 0 {
				firstStats = len(ops)
				ops = append(ops, nil) // 最初の stats の直前の filter の場所
			}
			op, first := statsOp(m[1], m[2], seenStats == nStats, define)
			sortBy = first
			ops = append(ops, op)
		case strings.HasPrefix(line, "limit "):
			limit, _ = strconv.Atoi(strings.TrimPrefix(line, "limit "))
		}
	}
	pass := func(rows []simRow) []simRow { return rows }
	for i, op := range ops {
		if op != nil {
			continue
		}
		ops[i] = pass
		at := firstStats
		if userFilter >= 0 {
			at = userFilter
		}
		if i == at && filter != nil {
			ops[i] = keep(filter)
		}
	}
	var rows []simRow
	for _, e := range s.Events {
		if e.Time.Before(from) || e.Time.Unix() > to.Unix() {
			continue
		}
		f := map[string]string{}
		for k, v := range e.Fields {
			f[k] = v
		}
		n := e.N
		if n == 0 {
			n = 1
		}
		rows = append(rows, simRow{f: f, t: e.Time, n: float64(n)})
	}
	if firstStats < 0 && filter != nil {
		ops = append(ops, keep(filter))
	}
	for _, op := range ops {
		rows = op(rows)
	}
	out := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.f)
	}
	if sortBy != "" {
		sort.SliceStable(out, func(i, j int) bool { return num(out[i][sortBy]) > num(out[j][sortBy]) })
	}
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// statsOp は stats の 1 段。last は最後の段か (時刻の出し方が変わる)。返す名前は最初の集計の名前 (結果の並び順に使う)。
func statsOp(aggList, byList string, last bool, define func(string)) (simOp, string) {
	var aggs []agg
	for _, a := range strings.Split(aggList, ", ") {
		am := aggExpr.FindStringSubmatch(a)
		if am == nil {
			panic("sim: unsupported aggregate " + a)
		}
		define(am[3])
		aggs = append(aggs, agg{am[1], am[2], am[3]})
	}
	var groups []string
	var bin time.Duration
	binName := ""
	if byList != "" {
		for _, g := range strings.Split(byList, ", ") {
			if bm := binExpr.FindStringSubmatch(g); bm != nil {
				bin, binName = binDur(bm[1], bm[2]), bm[3]
				define(binName)
				continue
			}
			groups = append(groups, g)
		}
	}
	type state struct {
		sum      float64
		val      string
		at       time.Time
		min, max time.Time
		has      bool
	}
	type acc struct {
		row simRow
		st  []state
	}
	return func(rows []simRow) []simRow {
		accs := map[string]*acc{}
		var order []string
		for _, r := range rows {
			row := map[string]string{}
			var key strings.Builder
			if binName != "" {
				row[binName] = r.t.UTC().Truncate(bin).Format(simTime)
				key.WriteString(row[binName])
			}
			for _, g := range groups {
				key.WriteString("\x00")
				if v, ok := r.f[g]; ok && v != "" {
					row[g] = v
					key.WriteString(v)
				}
			}
			a := accs[key.String()]
			if a == nil {
				a = &acc{row: simRow{f: row, t: r.t, n: 1}, st: make([]state, len(aggs))}
				accs[key.String()] = a
				order = append(order, key.String())
			}
			if r.t.Before(a.row.t) {
				a.row.t = r.t
			}
			for i, ag := range aggs {
				st := &a.st[i]
				v, present := r.f[ag.arg]
				present = present && v != ""
				switch {
				case ag.fn == "count" && ag.arg == "*":
					st.sum += r.n
				case ag.fn == "count":
					if present {
						st.sum += r.n
					}
				case ag.fn == "sum":
					st.sum += num(v) * r.n
				case ag.arg == "@timestamp":
					if !st.has || r.t.Before(st.min) {
						st.min = r.t
					}
					if !st.has || r.t.After(st.max) {
						st.max = r.t
					}
					st.has = true
				case !present:
					// earliest / latest / min / max は値の無い行を飛ばす
				case ag.fn == "earliest":
					if !st.has || r.t.Before(st.at) {
						st.val, st.at = v, r.t
					}
					st.has = true
				case ag.fn == "latest":
					if !st.has || !r.t.Before(st.at) {
						st.val, st.at = v, r.t
					}
					st.has = true
				case ag.fn == "min":
					if !st.has || less(v, st.val) {
						st.val = v
					}
					st.has = true
				case ag.fn == "max":
					if !st.has || less(st.val, v) {
						st.val = v
					}
					st.has = true
				}
			}
		}
		out := make([]simRow, 0, len(order))
		for _, k := range order {
			a := accs[k]
			for i, ag := range aggs {
				st := a.st[i]
				switch {
				case ag.fn == "count" || ag.fn == "sum":
					a.row.f[ag.name] = strconv.FormatFloat(st.sum, 'f', -1, 64)
				case !st.has:
				case ag.arg == "@timestamp":
					t := st.min
					if ag.fn == "max" {
						t = st.max
					}
					if last {
						a.row.f[ag.name] = t.UTC().Format(simTime)
					} else {
						a.row.f[ag.name] = strconv.FormatInt(t.UnixMilli(), 10)
					}
				default:
					a.row.f[ag.name] = st.val
				}
			}
			out = append(out, a.row)
		}
		return out
	}, aggs[0].name
}

// less は数として読める値は数で、それ以外は文字列として比べる。
func less(a, b string) bool {
	x, errA := strconv.ParseFloat(a, 64)
	y, errB := strconv.ParseFloat(b, 64)
	if errA == nil && errB == nil {
		return x < y
	}
	return a < b
}

func num(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

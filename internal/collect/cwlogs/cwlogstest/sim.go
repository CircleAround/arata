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

// Sim はログの行の集まりから、Insights の 1 段の集計クエリの結果を作るフェイク。
// クエリの `fields <a> as <b>` (別名)・`parse <field> /<re>/`・最初の `stats` (count(*) / count(<f>) / min(@timestamp) / max(@timestamp)
// を `by bin(<N><d|h|m>) as <name>, <field>...` で)・`limit` を解釈する。`filter` はクエリから読まず、テストが Go で渡す
// (filter は Response に渡す関数で、parse の後のフィールドに対して評価する)。2 段目の stats は扱わない。
// 問い合わせの範囲 [StartTime, EndTime] (両端を含む) の行だけを数える。group by のフィールドが無い行は null の組にまとめ、結果の行にそのフィールドを出さない。
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
	parseLine = regexp.MustCompile(`^parse (\S+) /(.*)/$`)
	statsLine = regexp.MustCompile(`^stats (.*) by (.*)$`)
	binExpr   = regexp.MustCompile(`^bin\((\d+)([dhm])\) as (\S+)$`)
	aggExpr   = regexp.MustCompile(`^(count|min|max)\(([^)]*)\) as (\S+)$`)
)

type agg struct{ fn, arg, name string }

// Rows はクエリを [from, to] の行に流した結果。
func (s *Sim) Rows(query string, from, to time.Time, filter func(map[string]string) bool) []map[string]string {
	var steps []func(map[string]string)
	var aggs []agg
	var groups []string
	var bin time.Duration
	binName := ""
	limit := -1
	for _, line := range strings.Split(query, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "| ")
		switch {
		case strings.HasPrefix(line, "fields ") && aggs == nil:
			for _, part := range strings.Split(strings.TrimPrefix(line, "fields "), ", ") {
				if a, b, ok := strings.Cut(part, " as "); ok && !strings.Contains(a, "(") {
					a, b := a, b
					steps = append(steps, func(f map[string]string) {
						if v, ok := f[a]; ok {
							f[b] = v
						}
					})
				}
			}
		case parseLine.MatchString(line):
			m := parseLine.FindStringSubmatch(line)
			field, re := m[1], regexp.MustCompile(m[2])
			steps = append(steps, func(f map[string]string) {
				v, ok := f[field]
				if !ok {
					return
				}
				sm := re.FindStringSubmatch(v)
				if sm == nil {
					return
				}
				for i, n := range re.SubexpNames() {
					if n != "" && i < len(sm) && sm[i] != "" {
						f[n] = sm[i]
					}
				}
			})
		case statsLine.MatchString(line) && aggs == nil:
			m := statsLine.FindStringSubmatch(line)
			for _, a := range strings.Split(m[1], ", ") {
				am := aggExpr.FindStringSubmatch(a)
				if am == nil {
					panic("sim: unsupported aggregate " + a)
				}
				aggs = append(aggs, agg{am[1], am[2], am[3]})
			}
			for _, g := range strings.Split(m[2], ", ") {
				if bm := binExpr.FindStringSubmatch(g); bm != nil {
					n, _ := strconv.Atoi(bm[1])
					unit := map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "m": time.Minute}[bm[2]]
					bin, binName = time.Duration(n)*unit, bm[3]
					continue
				}
				groups = append(groups, g)
			}
		case strings.HasPrefix(line, "stats ") && aggs != nil:
			panic("sim: second stats is not supported")
		case strings.HasPrefix(line, "limit "):
			limit, _ = strconv.Atoi(strings.TrimPrefix(line, "limit "))
		}
	}
	type acc struct {
		row    map[string]string
		counts []float64
		min    []time.Time
		max    []time.Time
	}
	accs := map[string]*acc{}
	var order []string
	for _, e := range s.Events {
		if e.Time.Before(from) || e.Time.Unix() > to.Unix() {
			continue
		}
		f := map[string]string{}
		for k, v := range e.Fields {
			f[k] = v
		}
		for _, st := range steps {
			st(f)
		}
		if filter != nil && !filter(f) {
			continue
		}
		row := map[string]string{}
		var key strings.Builder
		if binName != "" {
			t := e.Time.UTC().Truncate(bin)
			row[binName] = t.Format("2006-01-02 15:04:05.000")
			key.WriteString(row[binName])
		}
		for _, g := range groups {
			key.WriteString("\x00")
			if v, ok := f[g]; ok && v != "" {
				row[g] = v
				key.WriteString(v)
			}
		}
		a := accs[key.String()]
		if a == nil {
			a = &acc{row: row, counts: make([]float64, len(aggs)), min: make([]time.Time, len(aggs)), max: make([]time.Time, len(aggs))}
			accs[key.String()] = a
			order = append(order, key.String())
		}
		n := e.N
		if n == 0 {
			n = 1
		}
		for i, ag := range aggs {
			switch {
			case ag.fn == "count" && ag.arg == "*":
				a.counts[i] += float64(n)
			case ag.fn == "count":
				if f[ag.arg] != "" {
					a.counts[i] += float64(n)
				}
			case ag.fn == "min":
				if a.min[i].IsZero() || e.Time.Before(a.min[i]) {
					a.min[i] = e.Time
				}
			case ag.fn == "max":
				if e.Time.After(a.max[i]) {
					a.max[i] = e.Time
				}
			}
		}
	}
	out := make([]map[string]string, 0, len(order))
	for _, k := range order {
		a := accs[k]
		for i, ag := range aggs {
			switch ag.fn {
			case "count":
				a.row[ag.name] = strconv.FormatFloat(a.counts[i], 'f', -1, 64)
			case "min":
				a.row[ag.name] = a.min[i].UTC().Format("2006-01-02 15:04:05.000")
			case "max":
				a.row[ag.name] = a.max[i].UTC().Format("2006-01-02 15:04:05.000")
			}
		}
		out = append(out, a.row)
	}
	if len(aggs) > 0 {
		first := aggs[0].name
		sort.SliceStable(out, func(i, j int) bool { return num(out[i][first]) > num(out[j][first]) })
	}
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func num(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

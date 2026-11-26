package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// SigninSession は aws login のログインのセッション (CreateOAuth2Token) の出し直しを見る (ADR 0092 の 2 節)。
// 出し直しの控え (refresh token) を写し取った者が、別の場所から鍵を出し直し続ける形を、本人の新しいログインと分けて報告する。
//
// 決定:
//   - 対象は IAM ユーザーの、形の合う signin_session を持つ CreateOAuth2Token (collector が残す。ADR 0092 の 1 節)。ストアから読み戻した値も形を確かめる
//   - 形 (Key の最後の欄) は 3 つ:
//     new_prefix: 同じセッションの成功した refresh_token の出し直しが、そのセッションでまだ見ていない /24・/48 から来た。
//     その /24 がその主体の平常帯 (過去 baseline_days の principal_source) に無ければ high、あれば low。Key は <主体>|<セッションの UUID>|new_prefix
//     failures: 失敗した出し直し (signin_success: false か errorCode がある。形は未確認。ADR 0092 の未確認の点 1) が主体 × UTC の日で min_failures 回以上 → low。
//     セッションの無い記録も数える。Key は <主体>|<日>|failures
//     sessions: 主体の 1 日のセッションの数 (principal_signin_session の異なるキー) が平常帯の最大より多く min_sessions 以上 → low。Key は <主体>|<日>|sessions
//   - 「そのセッションでまだ見ていない」は、そのセッションの過去の CreateOAuth2Token (最初のログインを含む。成功したものだけ) の送信元と、時刻の順に比べる。
//     過去は窓の始まりから session_lookback まで。そのセッションの記録が lookback の中にも窓の前にも無く、窓の最初の記録が出し直しなら
//     (first_outside_lookback)、その出し直しは主体の平常帯だけと比べる (無ければ high。あれば報告しない)
//   - 最初のログイン (authorization_code) は報告しない (principal_new_source が見る)。失敗した出し直しは送信元の移動に数えない (failures で数える)。
//     送信元が IP でない記録は判定しない
//   - 平常帯の日は ADR 0090 のとおり、CloudTrail を収集し終えた日と、principal_source の値のある日。min_baseline_days に足りない間は、
//     high を medium に下げ、data に baseline_short: true。sessions は判定しない (平常帯の最大を比べられない)
//   - sessions の平常帯は、そのうち principal_signin_session がストアに初めて現れた日より後の日だけ (足す前の版で集めた日を 0 と数えない)
//   - User-Agent は重大度に使わない。data の cli_versions は collector が形を確かめた値 (aws-cli/<版>) だけ
//   - session_lookback には既定を持たない (ADR 0014)。書かなければ skip (Disabled)
type SigninSession struct {
	Config config.SigninSession
}

func (SigninSession) Name() string     { return "signin_session" }
func (SigninSession) Cadence() Cadence { return Daily }
func (SigninSession) Mode() Mode       { return ModeEvent }
func (SigninSession) Needs() []record.Kind {
	return []record.Kind{record.KindTrailEvent, record.KindPrincipalSeen}
}

// Disabled は session_lookback を書いていないときの理由 (書いていれば "")。
func (c SigninSession) Disabled() string {
	if _, ok := c.Config.Lookback(); !ok {
		return "checks.signin_session.session_lookback is not set (no default; set it to the longest sign-in session duration, e.g. 3d. See `arata help ai playbook signin_session`)"
	}
	return ""
}

// Key の最後の欄 (形)。
const (
	signinFormNewPrefix = "new_prefix"
	signinFormFailures  = "failures"
	signinFormSessions  = "sessions"
)

// maxSigninPrefixes は data と見出しに出す /24 の数の上限。
const maxSigninPrefixes = 20

const signinEventSource, signinEventName = "signin.amazonaws.com", "CreateOAuth2Token"

// signinRecord は判定に使う 1 件 (形を確かめた値だけ)。
type signinRecord struct {
	e       record.TrailEvent
	session string // ARN
	uuid    string
	prefix  string // 送信元が IP でなければ空
	grant   string
	failed  bool
}

func signinRecordOf(e record.TrailEvent) (signinRecord, bool) {
	if e.EventSource != signinEventSource || e.Name != signinEventName || e.PrincipalKind != record.PrincipalUser || e.PrincipalARN == "" {
		return signinRecord{}, false
	}
	r := signinRecord{e: e, grant: record.SigninGrant(e.Data["grant_type"])}
	if v, ok := dataBool(e.Data, "signin_success"); ok && !v || e.ErrorCode != "" {
		r.failed = true
	}
	r.session = dataStr(e.Data, "signin_session")
	if id, ok := record.SigninSessionUUID(r.session); ok {
		r.uuid = id
	} else {
		r.session = ""
	}
	r.prefix, _ = record.SourcePrefix(e.IP)
	return r, true
}

// signinMove は 1 つのセッションの、窓の中の送信元の移動。
type signinMove struct {
	principal, session, uuid, client string
	newPrefixes                      []string
	outside                          map[string]bool // 平常帯の外の新しい /24
	refreshes                        int
	firstSeen                        time.Time
	firstOutsideLookback             bool
	cli                              map[string]bool
}

func (c SigninSession) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	lookback, ok := c.Config.Lookback()
	dates := windowDates(w)
	if !ok || len(dates) == 0 {
		return nil, nil
	}
	b := c.Config
	day0 := dates[0]
	bds := baseDates(day0, b.BaselineDays)
	from, to := addDays(day0, -b.BaselineDays), dates[len(dates)-1]
	src, err := loadSeries(ctx, q, record.MetricPrincipalSource, from, addDays(day0, -1))
	if err != nil {
		return nil, err
	}
	sess, err := loadSeries(ctx, q, record.MetricPrincipalSigninSession, from, to)
	if err != nil {
		return nil, err
	}
	collected, err := trailCollectedSet(ctx, q, bds)
	if err != nil {
		return nil, err
	}
	for _, d := range bds {
		if len(src[d]) > 0 {
			collected[d] = true
		}
	}
	short := len(collected) < b.MinBaselineDays
	baseline := map[string]map[string]bool{} // 主体 → 平常帯の /24
	for _, d := range bds {
		for k := range src[d] {
			arn, p, ok := record.SplitActivityKey(k)
			if !ok {
				continue
			}
			if baseline[arn] == nil {
				baseline[arn] = map[string]bool{}
			}
			baseline[arn][p] = true
		}
	}

	f := store.EventFilter{Names: []string{signinEventName}, EventSources: []string{signinEventSource}}
	win, err := windowEvents(ctx, q, w, f)
	if err != nil {
		return nil, err
	}
	past, err := q.Events(ctx, w.From.Add(-lookback), w.From, f)
	if err != nil {
		return nil, err
	}
	// 失敗は窓に重なる日の頭から数える (日の値。窓の前の分は窓に失敗が 1 件以上あるときだけ効く)
	dayPast, err := q.Events(ctx, dayOf(w.From), w.From, f)
	if err != nil {
		return nil, err
	}
	inWindow := map[string]bool{}
	var winRecs, pastRecs []signinRecord
	for _, e := range win {
		if r, ok := signinRecordOf(e); ok && !inWindow[e.EventID] {
			inWindow[e.EventID] = true
			winRecs = append(winRecs, r)
		}
	}
	for _, e := range past {
		if r, ok := signinRecordOf(e); ok && !inWindow[e.EventID] {
			pastRecs = append(pastRecs, r)
		}
	}
	byTime := func(l []signinRecord) {
		sort.SliceStable(l, func(i, j int) bool {
			if !l[i].e.Time.Equal(l[j].e.Time) {
				return l[i].e.Time.Before(l[j].e.Time)
			}
			return l[i].e.EventID < l[j].e.EventID
		})
	}
	byTime(winRecs)
	byTime(pastRecs)

	obs := map[string]Observation{}
	base := func(principal string) map[string]any {
		d := map[string]any{"principal": principal, "baseline_short": short, "baseline_days": b.BaselineDays, "baseline_days_collected": len(collected)}
		markAccountOnly(d, "principal_identity", principal, record.PrincipalUser)
		return d
	}

	// new_prefix
	type sk struct{ principal, uuid string }
	known := map[sk]map[string]bool{}
	first := map[sk]time.Time{}
	for _, r := range pastRecs {
		if r.uuid == "" || r.failed {
			continue
		}
		k := sk{r.e.PrincipalARN, r.uuid}
		if _, ok := first[k]; !ok {
			first[k] = r.e.Time
		}
		if r.prefix != "" {
			if known[k] == nil {
				known[k] = map[string]bool{}
			}
			known[k][r.prefix] = true
		}
	}
	moves := map[sk]*signinMove{}
	seen := map[sk]bool{} // 窓の中で記録を見たセッション
	for _, r := range winRecs {
		if r.uuid == "" || r.failed {
			continue
		}
		k := sk{r.e.PrincipalARN, r.uuid}
		firstHere := !seen[k] && first[k].IsZero()
		seen[k] = true
		m := moves[k]
		if m == nil {
			m = &signinMove{principal: k.principal, session: r.session, uuid: k.uuid, outside: map[string]bool{}, cli: map[string]bool{}, firstSeen: first[k]}
			if m.firstSeen.IsZero() {
				m.firstSeen = r.e.Time
			}
			moves[k] = m
		}
		if cl := dataStr(r.e.Data, "signin_client"); cl != "" {
			m.client = record.SigninClient(signinClientARN(cl))
		}
		if v, ok := record.CLIVersion(dataStr(r.e.Data, "cli_version")); ok {
			m.cli[v] = true
		}
		if r.grant == record.GrantRefreshToken {
			m.refreshes++
		}
		if r.prefix == "" {
			continue
		}
		if known[k] == nil {
			known[k] = map[string]bool{}
		}
		inBase := baseline[k.principal][r.prefix]
		switch {
		case r.grant != record.GrantRefreshToken || known[k][r.prefix]:
		case firstHere:
			// そのセッションの最初の記録が lookback の外: まだ見ていない /24 の判定はせず、主体の平常帯だけと比べる
			if !inBase {
				m.firstOutsideLookback = true
				m.newPrefixes = append(m.newPrefixes, r.prefix)
				m.outside[r.prefix] = true
			}
		default:
			if !contains(m.newPrefixes, r.prefix) {
				m.newPrefixes = append(m.newPrefixes, r.prefix)
				if !inBase {
					m.outside[r.prefix] = true
				}
			}
		}
		known[k][r.prefix] = true // 新しい /24 も、それより後の記録には見た /24 (known_prefixes には新しい /24 を出さない)
	}
	for k, m := range moves {
		if len(m.newPrefixes) == 0 {
			continue
		}
		var knownList []string
		for p := range known[k] {
			if !contains(m.newPrefixes, p) {
				knownList = append(knownList, p)
			}
		}
		sort.Strings(knownList)
		newList := append([]string(nil), m.newPrefixes...)
		sort.Strings(newList)
		sev := Low
		if len(m.outside) > 0 {
			sev = High
			if short {
				sev = Medium
			}
		}
		data := base(m.principal)
		data["form"] = signinFormNewPrefix
		data["signin_session"] = m.session
		data["new_prefixes"] = capList(newList, maxSigninPrefixes)
		data["known_prefixes"] = capList(knownList, maxSigninPrefixes)
		data["in_principal_baseline"] = len(m.outside) == 0
		data["refreshes"] = m.refreshes
		data["first_seen"] = m.firstSeen.UTC().Format(time.RFC3339)
		data["first_outside_lookback"] = m.firstOutsideLookback
		data["session_lookback"] = b.SessionLookback
		if m.client != "" {
			data["signin_client"] = m.client
		}
		if len(m.cli) > 0 {
			data["cli_versions"] = sortedKeys(m.cli)
		}
		var parts []string
		parts = append(parts, fmt.Sprintf("同じログインのセッションの出し直しが、そのセッションでまだ見ていない送信元 %s から来た", strings.Join(capList(newList, 5), ", ")))
		if m.firstOutsideLookback {
			parts[0] = fmt.Sprintf("ログインのセッションの出し直しが、主体のふだんの送信元に無い %s から来た (セッションの始まりは session_lookback より前)", strings.Join(capList(newList, 5), ", "))
		}
		if len(m.outside) > 0 {
			parts = append(parts, "主体のふだんの送信元にも無い")
		} else {
			parts = append(parts, "主体のふだんの送信元の内")
		}
		if short {
			parts = append(parts, fmt.Sprintf("平常帯が短い (収集した過去日 %d 日) ので下げた", len(collected)))
		}
		key := m.principal + "|" + m.uuid + "|" + signinFormNewPrefix
		obs[key] = Observation{Check: c.Name(), Key: key, Severity: sev, Data: data,
			Summary:     fmt.Sprintf("aws login のセッションの移動: %s の %s。%s", record.PrincipalLabel(m.principal, record.PrincipalUser), m.uuid, strings.Join(parts, "。")),
			Fingerprint: fingerprint(sev, nil, strings.Join(newList, ","))}
	}

	// failures
	type dk struct{ principal, date string }
	fails := map[dk]int{}
	failInWindow := map[dk]bool{}
	codes := map[dk]map[string]bool{}
	sessions := map[dk]map[string]bool{}
	count := func(r signinRecord, inWin bool) {
		if !r.failed {
			return
		}
		k := dk{r.e.PrincipalARN, r.e.Time.UTC().Format(record.DateLayout)}
		fails[k]++
		if inWin {
			failInWindow[k] = true
		}
		if r.e.ErrorCode != "" {
			if codes[k] == nil {
				codes[k] = map[string]bool{}
			}
			codes[k][r.e.ErrorCode] = true
		}
		if r.session != "" {
			if sessions[k] == nil {
				sessions[k] = map[string]bool{}
			}
			sessions[k][r.session] = true
		}
	}
	for _, e := range dayPast {
		if r, ok := signinRecordOf(e); ok && !inWindow[e.EventID] {
			count(r, false)
		}
	}
	for _, r := range winRecs {
		count(r, true)
	}
	for k, n := range fails {
		if n < b.MinFailures || !failInWindow[k] {
			continue
		}
		data := base(k.principal)
		data["form"] = signinFormFailures
		data["date"] = k.date
		data["failures"] = n
		data["min_failures"] = b.MinFailures
		if len(codes[k]) > 0 {
			data["error_codes"] = sortedKeys(codes[k])
		}
		if len(sessions[k]) > 0 {
			data["signin_sessions"] = capList(sortedKeys(sessions[k]), maxSigninPrefixes)
		}
		key := k.principal + "|" + k.date + "|" + signinFormFailures
		obs[key] = Observation{Check: c.Name(), Key: key, Severity: Low, Data: data,
			Summary:     fmt.Sprintf("aws login の出し直しの失敗: %s が %s に %d 回", record.PrincipalLabel(k.principal, record.PrincipalUser), k.date, n),
			Fingerprint: fingerprint(Low, nil, k.date)}
	}

	// sessions
	if !short {
		firstDay := ""
		for d := range sess {
			if firstDay == "" || d < firstDay {
				firstDay = d
			}
		}
		perDay := func(d string) map[string]int {
			out := map[string]int{}
			for key := range sess[d] {
				arn, id, ok := record.SplitActivityKey(key)
				if !ok || !strings.Contains(arn, ":user/") || len(id) != 36 {
					continue
				}
				out[arn]++
			}
			return out
		}
		var sessDays []string
		for _, d := range bds {
			if collected[d] && firstDay != "" && d >= firstDay {
				sessDays = append(sessDays, d)
			}
		}
		if len(sessDays) >= b.MinBaselineDays {
			maxOf := map[string]int{}
			for _, d := range sessDays {
				for arn, n := range perDay(d) {
					maxOf[arn] = max(maxOf[arn], n)
				}
			}
			for _, d := range dates {
				for arn, n := range perDay(d) {
					if n < b.MinSessions || n <= maxOf[arn] {
						continue
					}
					data := base(arn)
					data["form"] = signinFormSessions
					data["date"] = d
					data["sessions"] = n
					data["baseline_max"] = maxOf[arn]
					data["min_sessions"] = b.MinSessions
					data["baseline_days_sessions"] = len(sessDays)
					key := arn + "|" + d + "|" + signinFormSessions
					obs[key] = Observation{Check: c.Name(), Key: key, Severity: Low, Data: data,
						Summary: fmt.Sprintf("aws login のセッションの数: %s が %s に %d 個 (過去 %d 日の最大 %d)",
							record.PrincipalLabel(arn, record.PrincipalUser), d, n, b.BaselineDays, maxOf[arn]),
						Fingerprint: fingerprint(Low, nil, d)}
				}
			}
		}
	}
	return sortedObs(obs), nil
}

// signinClientARN は data の signin_client (collector が決めた値) を、record.SigninClient が読む形に戻す (ストアの値も決まった値に寄せるため)。
func signinClientARN(v string) string {
	switch v {
	case record.SigninCrossDevice, record.SigninSameDevice:
		return "arn:aws:signin:::devtools/" + v
	}
	return v
}

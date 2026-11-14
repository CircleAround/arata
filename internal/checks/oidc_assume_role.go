package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// OIDCAssumeRole は OIDC でのロールの引き受け (AssumeRoleWithWebIdentity) を、(プロバイダ, sub, ロール) の組で既知リストの oidc_subjects と比べる (ADR 0055)。
//
// 決定:
//   - ロールが oidc_subjects のどの項目にも (期限内で) 無い → medium。ロールは期限内の項目にあるが、その組が無い → high
//     (ロールが既知なら正規の入り口は書いてある。別の入り口から入れたなら、信頼ポリシーが広すぎるか、書き換えられている)
//   - 組は既知だが、項目に書いた時間帯 (hours)・送信元 (source_ips) の外 → medium。一致する期限内の項目のどれか 1 つが両方を許せば内
//   - 上の medium / high で、窓の中の引き受けが全部失敗 → low (ロールの ARN は秘密ではなく、誰でも自分のリポジトリから試せる)
//   - 組が既知で、上のどれでもない → 報告しない。ロールごとに info で 1 行残す (Key は known:<ロールの ARN>。ADR 0047 と同じ)
//   - 既知の組の、窓に重なる UTC の日の回数 (成功した引き受け) が、その組自身の過去 baseline_days 日の日次の回数の中央値 × factor
//     (下限 min_count) を超えたら low、その medium_ratio 倍を超えたら medium (Key は volume:<組>)。材料は保存済みの注目イベント。
//     CloudTrail を収集し終えた過去日が min_baseline_days 未満の間は判定しない。過去を読むのは、窓に既知の組の引き受けがあるときだけ
//   - sub を読むのは GitHub のプロバイダだけ (collector が各部分を残す)。ID 入りの形は ID を外した形で比べ、Key もその形にする。
//     読めない sub (unparsed) と GitHub 以外 (-) は、sub の部分を持たない組として扱う。読めない sub は既知リストに書けないので、既知にならない
//   - data はストアから読み戻した値 (元はログ由来)。決まった形のときだけ使い、外れたら unparsed にまとめる (見出しにそのまま出さない)
//   - Fingerprint は重大度と理由。IP は入れない (GitHub の実行環境の IP は毎回変わる)。run_id は呼ぶ側が書ける値なので判定に使わず、data に出すだけ
//   - 主体 (principals) は見ない。ロールを主体として承認しても、入り口は既知にならない
type OIDCAssumeRole struct {
	Config config.OIDCAssumeRole
}

func (OIDCAssumeRole) Name() string         { return "oidc_assume_role" }
func (OIDCAssumeRole) Cadence() Cadence     { return Hourly }
func (OIDCAssumeRole) Mode() Mode           { return ModeEvent }
func (OIDCAssumeRole) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

// OIDCAssumeEvent は oidc_assume_role が見る CloudTrail の操作の名前。unknown_assume_role はこの名前を対象から外す。
const OIDCAssumeEvent = "AssumeRoleWithWebIdentity"

// Key の先頭。
const (
	// KnownOIDCKeyPrefix は、報告しなかった引き受けをまとめた info の行 (後ろにロールの ARN)。
	KnownOIDCKeyPrefix = "known:"
	// OIDCVolumeKeyPrefix は、既知の組の回数が平常帯を超えた行 (後ろに組の Key)。
	OIDCVolumeKeyPrefix = "volume:"
)

// 理由 (data.reasons)。
const (
	reasonUnknownSubject   = "unknown_subject"
	reasonOutsideHours     = "outside_hours"
	reasonUnexpectedSource = "unexpected_source"
)

const (
	maxOIDCRunIDs   = 10
	maxOIDCSubjects = 20
	oidcUnparsed    = "unparsed"
	oidcNoSub       = "-"
)

// oidcTuple は 1 つの引き受けの組。
type oidcTuple struct {
	provider  string // 名前。決まった形でなければ unparsed
	sub       string // 正規化した sub。読めなければ unparsed、GitHub 以外は -
	role      string // ロールの ARN。決まった形でなければ unparsed
	roleLabel string // role/ より後ろ
	form      string // record.OIDCSub*
	gh        record.GitHubSub
}

func (t oidcTuple) key() string { return t.provider + "|" + t.sub + "|" + t.role }

func (t oidcTuple) assume() allowlist.OIDCAssume {
	a := allowlist.OIDCAssume{Provider: t.provider, Repo: t.gh.Repo, Kind: t.gh.Kind, Ref: t.gh.Ref, Environment: t.gh.Environment}
	if t.role != oidcUnparsed {
		a.Role = t.role
	}
	return a
}

// entrance は見出しに出す入り口の表記。
func (t oidcTuple) entrance() string {
	switch {
	case t.provider == oidcUnparsed:
		return "プロバイダを読めない"
	case t.form == record.OIDCSubGitHub && t.gh.Kind == record.OIDCKindRef:
		return t.gh.Repo + " のブランチ・タグ " + t.gh.Ref
	case t.form == record.OIDCSubGitHub && t.gh.Kind == record.OIDCKindEnvironment:
		return t.gh.Repo + " の environment " + t.gh.Environment
	case t.form == record.OIDCSubGitHub:
		return t.gh.Repo + " の pull_request"
	case t.form == record.OIDCSubUnparsed:
		return "GitHub Actions。sub を読めない"
	}
	return "プロバイダ " + t.provider
}

// data は組の各項目 (既知リストに書くときに使う値)。
func (t oidcTuple) data(d map[string]any) {
	d["provider"], d["sub_form"] = t.provider, t.form
	if t.role != oidcUnparsed {
		d["role_arn"] = t.role
	}
	if t.form != record.OIDCSubGitHub {
		return
	}
	d["repo"], d["sub_kind"] = t.gh.Repo, t.gh.Kind
	if t.gh.Ref != "" {
		d["ref"] = t.gh.Ref
	}
	if t.gh.Environment != "" {
		d["environment"] = t.gh.Environment
	}
}

// oidcTupleOf は、イベントの data (collector が残した値) から組を作る。決まった形でない値は unparsed にまとめる。
func oidcTupleOf(data map[string]any) oidcTuple {
	t := oidcTuple{provider: oidcUnparsed, sub: oidcNoSub, role: oidcUnparsed, roleLabel: "(読めない)", form: record.OIDCSubNotRead}
	if p := dataStr(data, "oidc_provider"); record.ValidOIDCProvider(p) {
		t.provider = p
	}
	if m := assumeRoleRe.FindStringSubmatch(dataStr(data, "role_arn")); m != nil && len(m[2]) <= maxAssumeLabel {
		t.role, t.roleLabel = m[0], m[2]
	}
	if t.provider != record.GitHubOIDCProvider {
		return t
	}
	t.sub, t.form = oidcUnparsed, record.OIDCSubUnparsed
	if dataStr(data, "oidc_sub_form") != record.OIDCSubGitHub {
		return t
	}
	// 各部分から正規化した sub を組み立て、読み直して同じになるときだけ使う
	g := record.GitHubSub{Repo: dataStr(data, "oidc_repo"), Kind: dataStr(data, "oidc_sub_kind"), Ref: dataStr(data, "oidc_ref"), Environment: dataStr(data, "oidc_environment")}
	if again, ok := record.ParseGitHubSub(g.Normalized()); ok && again == g {
		t.sub, t.form, t.gh = g.Normalized(), record.OIDCSubGitHub, g
	}
	return t
}

// oidcAgg は 1 つの組の、窓の中の引き受けの集計。
type oidcAgg struct {
	*eventAgg
	t                 oidcTuple
	errors            int
	accounts          map[string]bool
	ownerIDs, repoIDs map[string]bool
	runIDs            map[string]bool
}

func newOIDCAgg(t oidcTuple) *oidcAgg {
	return &oidcAgg{eventAgg: newEventAgg(), t: t, accounts: map[string]bool{}, ownerIDs: map[string]bool{}, repoIDs: map[string]bool{}, runIDs: map[string]bool{}}
}

func (a *oidcAgg) addEvent(e record.TrailEvent) {
	a.add(e.Time, "", e.IP)
	if e.ErrorCode != "" {
		a.errors++
	}
	if v := dataStr(e.Data, "oidc_provider_account"); accountIDRe.MatchString(v) {
		a.accounts[v] = true
	}
	for k, set := range map[string]map[string]bool{"oidc_owner_id": a.ownerIDs, "oidc_repo_id": a.repoIDs, "gha_run_id": a.runIDs} {
		if v := dataStr(e.Data, k); v != "" && len(v) <= 20 && strings.Trim(v, "0123456789") == "" {
			set[v] = true
		}
	}
}

// fill は finding の data を作る。
func (a *oidcAgg) fill() map[string]any {
	a.t.data(a.extra)
	if len(a.accounts) == 1 {
		a.extra["provider_account"] = sortedKeys(a.accounts)[0]
	}
	// ID は 1 つに決まるときだけ出す (同じ名前で ID が違うなら、名前の付け替え・取り直しがあった)
	for k, set := range map[string]map[string]bool{"owner_id": a.ownerIDs, "repo_id": a.repoIDs} {
		switch len(set) {
		case 0:
		case 1:
			a.extra[k] = sortedKeys(set)[0]
		default:
			a.extra[k+"s"] = capList(sortedKeys(set), maxOIDCRunIDs)
		}
	}
	if len(a.runIDs) > 0 {
		a.extra["run_ids"] = capList(sortedKeys(a.runIDs), maxOIDCRunIDs)
	}
	if a.errors > 0 {
		a.extra["has_errors"] = true
	}
	return a.eventAgg.data()
}

func (c OIDCAssumeRole) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	f := store.EventFilter{NamePrefixes: []string{OIDCAssumeEvent}}
	evs, err := windowEvents(ctx, q, w, f)
	if err != nil {
		return nil, err
	}
	if al == nil {
		al = &allowlist.List{}
	}
	unknown, outside, known := map[string]*oidcAgg{}, map[string]*oidcAgg{}, map[string]*oidcAgg{}
	status := map[string]allowlist.Status{}
	reasons := map[string]map[string]bool{}
	get := func(m map[string]*oidcAgg, t oidcTuple) *oidcAgg {
		a, ok := m[t.key()]
		if !ok {
			a = newOIDCAgg(t)
			m[t.key()] = a
		}
		return a
	}
	for _, e := range evs {
		if e.Name != OIDCAssumeEvent || e.EventSource != "sts.amazonaws.com" {
			continue
		}
		t := oidcTupleOf(e.Data)
		k := t.key()
		entries, st := al.OIDCSubject(t.assume(), w.To)
		status[k] = st
		if st != allowlist.StatusApproved {
			get(unknown, t).addEvent(e)
			continue
		}
		// 既知の組: 一致する期限内の項目のどれか 1 つが、時間帯と送信元の両方を許せば内
		inside, hoursOK, sourceOK := false, false, false
		for _, en := range entries {
			h, s := en.InHours(e.Time), en.SourceAllowed(e.IP)
			inside, hoursOK, sourceOK = inside || h && s, hoursOK || h, sourceOK || s
		}
		if inside {
			get(known, t).addEvent(e)
			continue
		}
		if reasons[k] == nil {
			reasons[k] = map[string]bool{}
		}
		if !hoursOK || sourceOK {
			reasons[k][reasonOutsideHours] = true
		}
		if !sourceOK || hoursOK {
			reasons[k][reasonUnexpectedSource] = true
		}
		get(outside, t).addEvent(e)
	}

	obs := map[string]Observation{}
	for k, a := range unknown {
		roleKnown := a.t.role != oidcUnparsed && al.OIDCRoleKnown(a.t.role, w.To)
		sev := Medium
		if roleKnown {
			sev = High
		}
		denied := a.errors == a.count
		if denied {
			sev = Low
			a.extra["denied"] = true
		}
		a.extra["reasons"] = []string{reasonUnknownSubject}
		a.extra["role_known"] = roleKnown
		a.extra["allowlist_status"] = string(status[k])
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev, Data: a.fill(),
			Summary:     oidcUnknownSummary(a.t, roleKnown, denied, status[k] == allowlist.StatusExpired, a.count),
			Fingerprint: fingerprint(sev, nil, reasonUnknownSubject, status[k], roleKnown)}
	}
	for k, a := range outside {
		rs := sortedKeys(reasons[k])
		sev := Medium
		denied := a.errors == a.count
		if denied {
			sev = Low
			a.extra["denied"] = true
		}
		a.extra["reasons"] = rs
		a.extra["role_known"] = true
		a.extra["allowlist_status"] = string(allowlist.StatusApproved)
		a.extra["outside_count"] = a.count
		var parts []string
		for _, r := range rs {
			parts = append(parts, map[string]string{reasonOutsideHours: "項目の時間帯の外", reasonUnexpectedSource: "項目の送信元の外"}[r])
		}
		verb := "引き受け"
		if denied {
			verb = "試みて全部失敗"
		}
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev, Data: a.fill(),
			Summary:     fmt.Sprintf("ロール %s を、既知の入り口だが、%s (%s) から OIDC で %d 回%s", a.t.roleLabel, strings.Join(parts, "・"), a.t.entrance(), a.count, verb),
			Fingerprint: fingerprint(sev, nil, strings.Join(rs, ","))}
	}

	// 決定 (ADR 0047 と同じ): 報告しなかった分を黙って消さない。ロールごとに info で 1 行 (件数・通知には数えない)。Fingerprint は固定
	type knownRole struct {
		*eventAgg
		label    string
		subjects map[string]bool
	}
	roles := map[string]*knownRole{}
	for _, a := range known {
		kr, ok := roles[a.t.role]
		if !ok {
			kr = &knownRole{eventAgg: newEventAgg(), label: a.t.roleLabel, subjects: map[string]bool{}}
			roles[a.t.role] = kr
		}
		kr.merge(a.eventAgg)
		kr.subjects[a.t.provider+"|"+a.t.sub] = true
		if a.errors > 0 {
			kr.extra["has_errors"] = true
		}
	}
	for role, kr := range roles {
		kr.extra["known_oidc"] = true
		kr.extra["role_arn"] = role
		kr.extra["subjects"] = capList(sortedKeys(kr.subjects), maxOIDCSubjects)
		kr.extra["subjects_total"] = len(kr.subjects)
		k := KnownOIDCKeyPrefix + role
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: Info, Data: kr.data(),
			Summary:     fmt.Sprintf("既知の入り口からの OIDC の引き受け %d 回は報告していない (ロール %s、入り口 %d)", kr.count, kr.label, len(kr.subjects)),
			Fingerprint: fingerprint(Info, nil, "known-oidc")}
	}

	vol, err := c.volume(ctx, q, w, al, f, known)
	if err != nil {
		return nil, err
	}
	for _, o := range vol {
		obs[o.Key] = o
	}
	return sortedObs(obs), nil
}

func oidcUnknownSummary(t oidcTuple, roleKnown, denied, expired bool, count int) string {
	who := "既知リストに無いロール " + t.roleLabel + " を、"
	if roleKnown {
		who = "既知のロール " + t.roleLabel + " を、既知リストに無い入り口 "
	}
	verb := "引き受け"
	if denied {
		verb = "試みて全部失敗 (信頼ポリシーなどが止めた)"
	}
	s := fmt.Sprintf("%s(%s) から OIDC で %d 回%s", who, t.entrance(), count, verb)
	if expired {
		s += "。入り口の承認は期限切れ"
	}
	return s
}

// volume は、窓に引き受けのあった既知の組について、窓に重なる UTC の日の回数 (成功した引き受け) を平常帯と比べる。
// 組ごとに、いちばん超えた日を 1 件返す。
func (c OIDCAssumeRole) volume(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List, f store.EventFilter, known map[string]*oidcAgg) ([]Observation, error) {
	dates := windowDates(w)
	if len(known) == 0 || len(dates) == 0 {
		return nil, nil
	}
	b := c.Config.Baseline
	bds0 := baseDates(dates[0], b.BaselineDays)
	withData, err := collectedDays(ctx, q, bds0)
	if err != nil {
		return nil, err
	}
	if withData < b.MinBaselineDays {
		return nil, nil
	}
	from, _ := time.Parse(record.DateLayout, addDays(dates[0], -b.BaselineDays))
	past, err := q.Events(ctx, from, w.To, f)
	if err != nil {
		return nil, err
	}
	counts := map[string]map[string]float64{} // 組 → 日 → 成功した引き受けの回数
	for _, e := range past {
		if e.Name != OIDCAssumeEvent || e.EventSource != "sts.amazonaws.com" || e.ErrorCode != "" {
			continue
		}
		k := oidcTupleOf(e.Data).key()
		if known[k] == nil {
			continue
		}
		if counts[k] == nil {
			counts[k] = map[string]float64{}
		}
		counts[k][e.Time.UTC().Format(record.DateLayout)]++
	}
	var out []Observation
	for k, a := range known {
		var best *spike
		for _, d := range dates {
			n := counts[k][d]
			vals := make([]float64, 0, b.BaselineDays)
			for _, bd := range baseDates(d, b.BaselineDays) {
				vals = append(vals, counts[k][bd])
			}
			med := median(vals)
			th := max(b.MinCount, med*b.Factor)
			if n > th && (best == nil || n/th > best.Count/best.Threshold) {
				best = &spike{Key: k, Date: d, Count: n, Median: med, Threshold: th, Reason: reasonAboveBaseline, BaselineDays: withData}
			}
		}
		if best == nil {
			continue
		}
		sev := Low
		if best.Count > best.Threshold*c.Config.MediumRatio {
			sev = Medium
		}
		data := map[string]any{"date": best.Date, "count": best.Count, "baseline_median": best.Median, "threshold": best.Threshold,
			"reasons": []string{reasonAboveBaseline}, "baseline_days_with_data": withData, "allowlist_status": string(allowlist.StatusApproved), "role_known": true}
		a.t.data(data)
		out = append(out, Observation{Check: c.Name(), Key: OIDCVolumeKeyPrefix + k, Severity: sev, Data: data,
			Summary: fmt.Sprintf("既知の入り口 (%s) からのロール %s の OIDC の引き受けが、%s に %.0f 回 (ふだんは 1 日 %.0f 回、しきい値 %.0f)",
				a.t.entrance(), a.t.roleLabel, best.Date, best.Count, best.Median, best.Threshold),
			Fingerprint: fingerprint(sev, nil, reasonAboveBaseline, best.Date)})
	}
	return out, nil
}

// IsKnownOIDCLine は、finding が「報告しなかった引き受けをまとめた info の行」か。ロールの ARN も返す。
func IsKnownOIDCLine(key string, data map[string]any) (role string, ok bool) {
	if v, _ := data["known_oidc"].(bool); !v || !strings.HasPrefix(key, KnownOIDCKeyPrefix) {
		return "", false
	}
	return strings.TrimPrefix(key, KnownOIDCKeyPrefix), true
}

// KnownOIDCSubjectOf は、oidc_assume_role の finding (知らない組として報告したもの) の組が、at 時点で既知リストの oidc_subjects にあるかを返す。
// 人が既知リストに入り口を足した後の解消 (engine) が使う。info の行・平常帯の行・時間帯や送信元の外の finding (組は既に既知) は対象外。
// data はストアから読み戻した値なので、決まった形のときだけ照合する。
func KnownOIDCSubjectOf(al *allowlist.List, key string, data map[string]any, at time.Time) (*allowlist.OIDCSubjectEntry, bool) {
	if al == nil || strings.HasPrefix(key, KnownOIDCKeyPrefix) || strings.HasPrefix(key, OIDCVolumeKeyPrefix) {
		return nil, false
	}
	if rs := dataStrings(data, "reasons"); len(rs) != 1 || rs[0] != reasonUnknownSubject {
		return nil, false
	}
	t := oidcTupleOf(map[string]any{"oidc_provider": data["provider"], "role_arn": data["role_arn"], "oidc_sub_form": data["sub_form"],
		"oidc_repo": data["repo"], "oidc_sub_kind": data["sub_kind"], "oidc_ref": data["ref"], "oidc_environment": data["environment"]})
	if t.key() != key {
		return nil, false
	}
	entries, st := al.OIDCSubject(t.assume(), at)
	if st != allowlist.StatusApproved {
		return nil, false
	}
	return entries[0], true
}

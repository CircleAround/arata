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

// SecretAccess は秘匿値 (Secrets Manager のシークレット・SSM の SecureString) の読み取りの異常を主体ごとに報告する (ADR 0027)。
//
// 決定:
//   - 対象は成功した (errorCode なし) GetSecretValue / BatchGetSecretValue と、復号した (withDecryption=true) GetParameter /
//     GetParameters / GetParametersByPath。失敗は access_denied が扱う。サービス主体と root (root_usage が扱う) は除く
//   - 秘匿値は名前 / ARN で数える (値は CloudTrail に入らない)。GetParametersByPath は 1 回で多数を読むがパス単位で 1 と数え、
//     Data に recursive を残す。BatchGetSecretValue のフィルタ指定は名前が分からないので「(filters)」を 1 と数える
//   - 初出: 窓の前 baseline_days の間にその主体が読んでいない秘匿値を読んだ → low。その主体が秘匿値を読むこと自体が初めてなら medium。
//     履歴は日の区切りに依らず窓の直前まで見る。「その名前を読んだことがある」には復号しない読み取りも数える。
//     「秘匿値を読んだことがある」は復号した読み取りか、with_decryption の無い (以前の版で集めた) ssm の読み取り。
//     CloudTrail を収集し終えた過去日 (collectedDays。活動の有無ではない) が min_baseline_days 未満の間 (導入直後) は初出を報告しない
//   - 一括読み出し: 窓の異なる秘匿値の数が max(min_distinct, 中央値 × factor) を超える → high (持ち出しの兆候)。
//     平常帯は窓の始まりの日の前日から baseline_days 日の、その主体自身の日ごとの異なり数 (無い日は 0) の中央値。導入直後でも判定する
//   - allowlist の secrets_access に書いた秘匿値は初出に数えない (一括読み出しの数には数える)
//   - 主体ごとに 1 件 (重い方の重大度)。allowlist で承認済みでも下げない (承認は「居ること」を認めるもので、何でも読んでよいではない)
type SecretAccess struct {
	Config config.SecretAccess
}

func (SecretAccess) Name() string     { return "secret_access" }
func (SecretAccess) Cadence() Cadence { return Daily }
func (SecretAccess) Mode() Mode       { return ModeEvent }
func (SecretAccess) Needs() []record.Kind {
	return []record.Kind{record.KindTrailEvent}
}

const (
	srcSecretsManager = "secretsmanager.amazonaws.com"
	srcSSM            = "ssm.amazonaws.com"
	maxSecretsShown   = 20
)

var secretReadAPIs = concatAPIs(
	apisOf(srcSecretsManager, "GetSecretValue", "BatchGetSecretValue"),
	apisOf(srcSSM, "GetParameter", "GetParameters", "GetParametersByPath"),
)

// SecretReadAPIs は secret_access が見る操作 (cloudtrail collector のテストで、すべて注目イベントとして残ることを固定する)。
func SecretReadAPIs() []API { return append([]API(nil), secretReadAPIs...) }

// IsSecretRead は e が秘匿値の読み取りの操作か (成否・復号の有無を問わない)。run の stats の保存量に使う。
func IsSecretRead(e record.TrailEvent) bool {
	_, ok := findAPI(secretReadAPIs, e)
	return ok
}

// secretRef は読み取った秘匿値 1 つ。
type secretRef struct {
	key  string // "secretsmanager:<id>" / "ssm:<name>" / "ssm-path:<path>"
	path string // パス単位の読み取りなら表示 ("/example/ (recursive)")
}

// secretsOf は e が読んだ秘匿値。decrypted が false なら ssm の復号しない読み取りも含める (履歴用)。
func secretsOf(e record.TrailEvent, decrypted bool) []secretRef {
	d := e.Data
	var out []secretRef
	switch e.EventSource {
	case srcSecretsManager:
		switch e.Name {
		case "GetSecretValue":
			if id := dataStr(d, "secret_id"); id != "" {
				out = append(out, secretRef{key: "secretsmanager:" + id})
			}
		case "BatchGetSecretValue":
			for _, id := range dataStrings(d, "secret_ids") {
				out = append(out, secretRef{key: "secretsmanager:" + id})
			}
			if v, _ := dataBool(d, "secret_filters"); v {
				out = append(out, secretRef{key: "secretsmanager:(filters)"})
			}
		}
	case srcSSM:
		if v, _ := dataBool(d, "with_decryption"); decrypted && !v {
			return nil
		}
		switch e.Name {
		case "GetParameter":
			if n := dataStr(d, "name"); n != "" {
				out = append(out, secretRef{key: "ssm:" + n})
			}
		case "GetParameters":
			for _, n := range dataStrings(d, "names") {
				out = append(out, secretRef{key: "ssm:" + n})
			}
		case "GetParametersByPath":
			if p := dataStr(d, "path"); p != "" {
				shown := p
				if v, _ := dataBool(d, "recursive"); v {
					shown += " (recursive)"
				}
				out = append(out, secretRef{key: "ssm-path:" + p, path: shown})
			}
		}
	}
	return out
}

// decryptedOrLegacy は秘匿値を読んだとみなせる読み取りか: Secrets Manager は常に、ssm は復号したもの。
// with_decryption が無い ssm の読み取りは以前の版で集めたもので復号の有無が分からないので、読んだとみなす (初めての読み手として重くしない)。
func decryptedOrLegacy(e record.TrailEvent) bool {
	if e.EventSource != srcSSM {
		return true
	}
	v, ok := dataBool(e.Data, "with_decryption")
	return !ok || v
}

// secretName は secretRef.key から種類の接頭辞を落とした名前 / ARN / パス (allowlist の secrets_access と比べる)。
func secretName(key string) string {
	_, name, _ := strings.Cut(key, ":")
	return name
}

func secretTarget(e record.TrailEvent) bool {
	return e.ErrorCode == "" && e.PrincipalARN != "" && e.PrincipalKind != record.PrincipalService && e.PrincipalKind != record.PrincipalRoot
}

func (c SecretAccess) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	f := store.EventFilter{EventSources: apiSources(secretReadAPIs), Names: apiNames(secretReadAPIs)}
	evs, err := windowEvents(ctx, q, w, f)
	if err != nil {
		return nil, err
	}
	type cur struct {
		agg     *eventAgg
		kind    record.PrincipalKind
		secrets map[string]bool
		paths   map[string]bool
	}
	byP := map[string]*cur{}
	for _, e := range evs {
		if !secretTarget(e) {
			continue
		}
		refs := secretsOf(e, true)
		if len(refs) == 0 {
			continue
		}
		p, ok := byP[e.PrincipalARN]
		if !ok {
			p = &cur{agg: newEventAgg(), kind: e.PrincipalKind, secrets: map[string]bool{}, paths: map[string]bool{}}
			byP[e.PrincipalARN] = p
		}
		p.agg.add(e.Time, e.Name, e.IP)
		for _, r := range refs {
			p.secrets[r.key] = true
			if r.path != "" {
				p.paths[r.path] = true
			}
		}
	}
	if len(byP) == 0 {
		return nil, nil
	}

	b := c.Config
	day0 := dayOf(w.From)
	bds := baseDates(day0.Format(record.DateLayout), b.BaselineDays)
	withData, err := collectedDays(ctx, q, bds)
	if err != nil {
		return nil, err
	}
	// 履歴: 一括読み出しの平常帯は [day0 - baseline_days, day0) の日ごと、初出は [From - baseline_days, From)
	histFrom := day0.AddDate(0, 0, -b.BaselineDays)
	if t := w.From.AddDate(0, 0, -b.BaselineDays); t.Before(histFrom) {
		histFrom = t
	}
	past, err := q.Events(ctx, histFrom, w.From, f)
	if err != nil {
		return nil, err
	}
	firstFrom := w.From.AddDate(0, 0, -b.BaselineDays)
	readSecret := map[string]bool{}                  // 主体 → 秘匿値を読んだことがある (初めての読み手の判定)
	known := map[string]map[string]bool{}            // 主体 → 読んだ秘匿値 (初出の判定)
	daily := map[string]map[string]map[string]bool{} // 主体 → 日 → 秘匿値 (平常帯)
	for _, e := range past {
		if !secretTarget(e) || byP[e.PrincipalARN] == nil || lateInWindow(e, w) {
			continue
		}
		if !e.Time.Before(firstFrom) {
			for _, r := range secretsOf(e, false) {
				if known[e.PrincipalARN] == nil {
					known[e.PrincipalARN] = map[string]bool{}
				}
				known[e.PrincipalARN][r.key] = true
			}
			if decryptedOrLegacy(e) && len(secretsOf(e, false)) > 0 {
				readSecret[e.PrincipalARN] = true
			}
		}
		if e.Time.Before(day0) && !e.Time.Before(histFrom) {
			date := e.Time.UTC().Format(record.DateLayout)
			var refs []secretRef
			if decryptedOrLegacy(e) {
				refs = secretsOf(e, false)
			}
			for _, r := range refs {
				if daily[e.PrincipalARN] == nil {
					daily[e.PrincipalARN] = map[string]map[string]bool{}
				}
				if daily[e.PrincipalARN][date] == nil {
					daily[e.PrincipalARN][date] = map[string]bool{}
				}
				daily[e.PrincipalARN][date][r.key] = true
			}
		}
	}
	firstReads := withData >= b.MinBaselineDays

	obs := map[string]Observation{}
	for arn, p := range byP {
		vals := make([]float64, 0, len(bds))
		for _, bd := range bds {
			vals = append(vals, float64(len(daily[arn][bd])))
		}
		med := median(vals)
		thr := med * b.Factor
		if thr < float64(b.MinDistinct) {
			thr = float64(b.MinDistinct)
		}
		distinct := len(p.secrets)
		bulk := float64(distinct) > thr
		var newSecrets []string
		matched := 0
		for s := range p.secrets {
			if al.SecretExpected(arn, secretName(s)) {
				matched++
			} else if firstReads && !known[arn][s] {
				newSecrets = append(newSecrets, s)
			}
		}
		sort.Strings(newSecrets)
		// secrets_access に書いた秘匿値を読む主体は、読むことが想定されているので「初めての読み手」として重くしない
		firstReader := !readSecret[arn] && matched == 0
		var sev Severity
		switch {
		case bulk:
			sev = High
		case len(newSecrets) > 0 && firstReader:
			sev = Medium
		case len(newSecrets) > 0:
			sev = Low
		default:
			continue
		}

		_, status := al.Principal(arn, w.To)
		a := p.agg
		a.extra["principal"] = arn
		a.extra["principal_kind"] = string(p.kind)
		a.extra["allowlist_status"] = string(status)
		a.extra["distinct_secrets"] = distinct
		a.extra["secrets"] = capList(sortedKeys(p.secrets), maxSecretsShown)
		if len(p.paths) > 0 {
			a.extra["paths"] = sortedKeys(p.paths)
		}
		a.extra["bulk"] = bulk
		if matched > 0 {
			a.extra["secrets_access_matched"] = matched
		}
		a.extra["threshold"] = thr
		a.extra["baseline_median_distinct"] = med
		a.extra["baseline_days_with_data"] = withData
		if firstReads {
			a.extra["new_secrets"] = capList(newSecrets, maxSecretsShown)
			a.extra["new_secret_count"] = len(newSecrets)
			a.extra["first_reader"] = firstReader
		}
		markAccountOnly(a.extra, "principal_identity", arn, p.kind)
		label := record.PrincipalLabel(arn, p.kind)
		var parts []string
		if bulk {
			parts = append(parts, fmt.Sprintf("1 日に %d 個の秘匿値を一括で読み出し (閾値 %.0f 個。持ち出しの兆候)", distinct, thr))
		}
		if len(newSecrets) > 0 {
			if firstReader {
				parts = append(parts, fmt.Sprintf("秘匿値の読み取りが初めて (%d 個)", len(newSecrets)))
			} else {
				parts = append(parts, fmt.Sprintf("初めて読む秘匿値 %d 個 (%s)", len(newSecrets), strings.Join(capList(newSecrets, 3), ", ")))
			}
		}
		summary := fmt.Sprintf("秘匿値の読み取り: %s が%s", label, strings.Join(parts, "。"))
		obs[arn] = Observation{Check: c.Name(), Key: arn, Severity: sev, Summary: summary, Data: a.data(),
			Fingerprint: fingerprint(sev, nil, bulk, strings.Join(newSecrets, ","))}
	}
	return sortedObs(obs), nil
}

// lateInWindow は e が再走査で遅れて届いたイベント (windowEvents が窓に含めるもの) か。履歴から除く (窓と二重に数えて初出を隠さない)。
func lateInWindow(e record.TrailEvent, w collect.Window) bool {
	return !w.ScanFrom.IsZero() && !w.CollectedAt.IsZero() && !e.Time.Before(w.ScanFrom) && e.Time.Before(w.From) && !e.CollectedAt.Before(w.CollectedAt)
}

// TrailCollectedStat は run の stats のキー。その run (init はその時点の done_until まで) で、主体の活動の日次集計を出す cloudtrail-lookup の
// ソースの収集が成功したことを示す (engine が付ける。ADR 0027)。
const TrailCollectedStat = "trail_collected"

// collectedDays は dates (UTC の日) のうち、arata が CloudTrail を収集し終えた日の数。導入直後の判定に使う (ADR 0027)。
//
// 決定: 「データ (日次集計) のある日」ではなく「収集し終えた日」で数える。操作の少ないアカウントでは活動の無い日が多く、
// データのある日で数えると、漏れたキーが使われると目立つはずのアカウントほどいつまでも判定しないため。収集済みで日次集計の無い日は「活動なし」。
// 収集し終えた範囲は、stats に TrailCollectedStat のある run の窓の和 (init は stats の done_until まで)。日の全体が覆われた日だけを数える。
// 印の無い run (CloudTrail を引かないプロファイル・CloudTrail の収集に失敗した run・日次集計を出す前の版の run) は数えない
// (版を上げた既存のストアで、日次集計の無い過去を「活動なし」とみなして全部の送信元を新しいとしないため)。
func collectedDays(ctx context.Context, q store.Query, dates []string) (int, error) {
	if len(dates) == 0 {
		return 0, nil
	}
	lo := dates[0]
	for _, d := range dates {
		lo = min(lo, d)
	}
	from, _ := time.Parse(record.DateLayout, lo)
	// 窓が from 以降を覆う run は from より後に始まっている (init も窓の終わりの時点で始まる)
	runs, err := q.Runs(ctx, from, from.AddDate(100, 0, 0))
	if err != nil {
		return 0, err
	}
	type span struct{ from, to time.Time }
	var spans []span
	for _, r := range runs {
		if v, _ := r.Stats[TrailCollectedStat].(bool); !v || r.Status == "failed" {
			continue
		}
		end := r.WindowTo
		if s, ok := r.Stats["done_until"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil && t.Before(end) {
				end = t
			}
		}
		if end.After(r.WindowFrom) {
			spans = append(spans, span{r.WindowFrom, end})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].from.Before(spans[j].from) })
	var merged []span
	for _, sp := range spans {
		if n := len(merged); n > 0 && !sp.from.After(merged[n-1].to) {
			if sp.to.After(merged[n-1].to) {
				merged[n-1].to = sp.to
			}
			continue
		}
		merged = append(merged, sp)
	}
	n := 0
	for _, d := range dates {
		start, _ := time.Parse(record.DateLayout, d)
		end := start.AddDate(0, 0, 1)
		for _, sp := range merged {
			if !sp.from.After(start) && !sp.to.Before(end) {
				n++
				break
			}
		}
	}
	return n, nil
}

func apiNames(apis []API) []string {
	set := map[string]bool{}
	for _, a := range apis {
		set[a.Name] = true
	}
	return sortedKeys(set)
}

func capList(l []string, n int) []string {
	if len(l) > n {
		return append([]string(nil), l[:n]...)
	}
	return l
}

package checks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// OIDC で入ったセッションから先の記録を、1 段目 (AssumeRoleWithWebIdentity) までキーのハッシュでたどる (ADR 0081)。
//
// 決定:
//   - 記録の session_key_hash と、発行の記録の issued_key_hash の一致でたどる (collector が残す。キーそのものは残さない)。
//     役割の連鎖の AssumeRole は両方を持つので、3 段目以降もたどれる (最大 maxOriginChainDepth)
//   - 発行は run の窓によらず保存済みの注目イベントから引く。時刻の範囲は発行の種類ごとの寿命 (OIDC は 12 時間、連鎖は 1 時間、ECS は 12 時間) と ±originSkew
//   - 付けた値 (oidc_origins) は信用しない。重大度・Key・Fingerprint・見出し・既知リストの判定に使わず、data に出すだけ。
//     付けるときにもう一度形を確かめる (oidcTupleOf と数字だけの run_id)
//   - たどれなかった理由 (oidc_origin_unmatched) は、一部だけたどれたときと、鎖の上に OIDC の入り口のロールがあるときだけ出す
//     (人の SSO のセッションの finding に毎回 no_issuance が付かないように)

const (
	maxOriginChainDepth = 4
	maxOriginsShown     = 10
	originSkew          = 5 * time.Second
	webIdentityLifetime = 12 * time.Hour
	chainedLifetime     = time.Hour
	ecsIssuedLifetime   = 12 * time.Hour
	// originLookback は窓の記録から引く発行の範囲の長さ (1 段目の寿命 + 連鎖の寿命 × (最大の段数 - 1))。
	originLookback = webIdentityLifetime + chainedLifetime*(maxOriginChainDepth-1)
)

// たどれなかった理由 (data.oidc_origin_unmatched の鍵)。
const (
	originNoKey      = "no_key"
	originNoIssuance = "no_issuance"
	originNotOIDC    = "not_oidc"
	originTooDeep    = "too_deep"
)

type issueKind int

const (
	issueWebIdentity issueKind = iota + 1
	issueChained
	issueECS
)

// issuedCred は保存済みの発行 1 つ。
type issuedCred struct {
	kind    issueKind
	at      time.Time
	session string // 役割の連鎖のとき、呼び出し側のキーのハッシュ
	caller  string // 役割の連鎖のとき、呼び出し側のロール
	data    map[string]any
}

// originUse は finding にまとめた記録 1 つの、たどるのに要る値。
type originUse struct {
	hash      string
	at        time.Time
	principal string
}

// originIndex は発行をキーのハッシュで引く表と、OIDC の入り口のロールの集合。
type originIndex struct {
	issued map[string][]issuedCred
	entry  map[string]bool
}

// newOriginIndex は AssumeRole* の記録から表を作る。発行の種類が決まらない記録・失敗した記録は入れない。
func newOriginIndex(evs []record.TrailEvent) originIndex {
	ix := originIndex{issued: map[string][]issuedCred{}, entry: map[string]bool{}}
	for _, e := range evs {
		if e.EventSource != "sts.amazonaws.com" || e.ErrorCode != "" {
			continue
		}
		c := issuedCred{at: e.Time, data: e.Data}
		switch {
		case e.Name == OIDCAssumeEvent:
			c.kind = issueWebIdentity
			if r := dataStr(e.Data, "role_arn"); r != "" {
				ix.entry[r] = true
			}
		case e.Name == "AssumeRole" && e.PrincipalKind == record.PrincipalService && e.PrincipalARN == ecsTasksService:
			c.kind = issueECS
		case e.Name == "AssumeRole" && dataStr(e.Data, "session_key_hash") != "":
			c.kind, c.session, c.caller = issueChained, dataStr(e.Data, "session_key_hash"), e.PrincipalARN
		default:
			continue
		}
		if h := dataStr(e.Data, "issued_key_hash"); h != "" {
			ix.issued[h] = append(ix.issued[h], c)
		}
	}
	return ix
}

func (k issueKind) lifetime() time.Duration {
	switch k {
	case issueWebIdentity:
		return webIdentityLifetime
	case issueChained:
		return chainedLifetime
	}
	return ecsIssuedLifetime
}

// find は、時刻 at に使われたキー h の発行を返す (寿命と ±originSkew の内のもの。複数あれば最も近い発行)。
func (ix originIndex) find(h string, at time.Time) (issuedCred, bool) {
	var best issuedCred
	found := false
	for _, c := range ix.issued[h] {
		d := at.Sub(c.at)
		if d < -originSkew || d > c.kind.lifetime()+originSkew {
			continue
		}
		if !found || absDur(d) < absDur(at.Sub(best.at)) {
			best, found = c, true
		}
	}
	return best, found
}

// trace は記録 u を 1 段目までたどる。たどれたら 1 段目の発行と段数、たどれなければ理由。roles は鎖の上のロール (記録の主体と、途中の発行の呼び出し側)。
func (ix originIndex) trace(u originUse) (origin issuedCred, depth int, reason string, roles []string) {
	roles = []string{u.principal}
	if u.hash == "" {
		return issuedCred{}, 0, originNoKey, roles
	}
	h, at, seen := u.hash, u.at, map[string]bool{}
	for depth = 1; ; depth++ {
		if seen[h] {
			return issuedCred{}, 0, originTooDeep, roles
		}
		seen[h] = true
		c, ok := ix.find(h, at)
		if !ok {
			return issuedCred{}, 0, originNoIssuance, roles
		}
		switch c.kind {
		case issueWebIdentity:
			return c, depth, "", roles
		case issueECS:
			return issuedCred{}, 0, originNotOIDC, roles
		}
		roles = append(roles, c.caller)
		if depth == maxOriginChainDepth {
			return issuedCred{}, 0, originTooDeep, roles
		}
		h, at = c.session, c.at
	}
}

// originElement は 1 段目の記録から、data に出す要素を作る。値は形を確かめたものだけ (ストアの値も信用しない)。
func originElement(c issuedCred, depth int) map[string]any {
	el := map[string]any{"assumed_at": c.at.UTC().Format(time.RFC3339), "chain_depth": depth}
	t := oidcTupleOf(c.data)
	if t.provider != oidcUnparsed {
		el["provider"] = t.provider
	}
	if t.role != oidcUnparsed && t.role != oidcNoRole {
		el["role_arn"] = t.role
	}
	if t.form == record.OIDCSubGitHub {
		el["repo"], el["sub_kind"] = t.gh.Repo, t.gh.Kind
		if t.gh.Ref != "" {
			el["ref"] = t.gh.Ref
		}
		if t.gh.Environment != "" {
			el["environment"] = t.gh.Environment
		}
	}
	if v := dataStr(c.data, "gha_run_id"); v != "" && len(v) <= 20 && strings.Trim(v, "0123456789") == "" {
		el["run_id"] = v
	}
	return el
}

// originTracer は 1 回の Evaluate の中で、finding の記録をたどる。note で記録を覚え、load で発行を 1 度だけ引き、attach で data に付ける。
type originTracer struct {
	need     bool
	from, to time.Time
	ix       originIndex
}

// note は記録 e を覚え、たどるのに要る値を返す。AssumedRole の記録が 1 つも無ければ、load は何も引かない。
func (tr *originTracer) note(e record.TrailEvent) originUse {
	u := originUse{hash: dataStr(e.Data, "session_key_hash"), at: e.Time, principal: e.PrincipalARN}
	if u.hash != "" || e.PrincipalKind == record.PrincipalAssumedRole {
		if !tr.need || e.Time.Before(tr.from) {
			tr.from = e.Time
		}
		if !tr.need || e.Time.After(tr.to) {
			tr.to = e.Time
		}
		tr.need = true
	}
	return u
}

// load は覚えた記録の時刻から originLookback 前までの AssumeRole* を引く。
func (tr *originTracer) load(ctx context.Context, q store.Query) error {
	if !tr.need {
		return nil
	}
	evs, err := q.Events(ctx, tr.from.Add(-originLookback-originSkew), tr.to.Add(originSkew+time.Second), store.EventFilter{NamePrefixes: []string{"AssumeRole"}})
	if err != nil {
		return err
	}
	tr.ix = newOriginIndex(evs)
	return nil
}

// attach は finding の記録 uses をたどり、extra に oidc_origins・oidc_origins_total・oidc_origin_unmatched を足す。
func (tr *originTracer) attach(extra map[string]any, uses []originUse) {
	if !tr.need || len(uses) == 0 {
		return
	}
	origins := map[string]map[string]any{}
	unmatched := map[string]int{}
	entry := false
	for _, u := range uses {
		c, depth, reason, roles := tr.ix.trace(u)
		for _, r := range roles {
			entry = entry || tr.ix.entry[r]
		}
		if reason != "" {
			unmatched[reason]++
			continue
		}
		el := originElement(c, depth)
		origins[originSortKey(el)] = el
	}
	if len(origins) > 0 {
		keys := make([]string, 0, len(origins))
		for k := range origins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		list := []map[string]any{}
		for _, k := range capList(keys, maxOriginsShown) {
			list = append(list, origins[k])
		}
		extra["oidc_origins"] = list
		extra["oidc_origins_total"] = len(origins)
	}
	if len(unmatched) > 0 && (len(origins) > 0 || entry) {
		extra["oidc_origin_unmatched"] = unmatched
	}
}

// originSortKey は要素の並びと重複の判定に使う文字列 (時刻が先頭なので、古い 1 段目から並ぶ)。
func originSortKey(el map[string]any) string {
	return fmt.Sprintf("%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v\x00%v", el["assumed_at"], el["role_arn"], el["repo"], el["sub_kind"], el["ref"], el["environment"], el["run_id"], el["chain_depth"])
}

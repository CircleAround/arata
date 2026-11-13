package checks

import (
	"context"
	"fmt"
	"regexp"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// UnknownAssumeRole は呼び出し元 ARN が allowlist に無い AssumeRole を報告する (high)。
// 決定: AWS サービス主体 (EC2 / Lambda などがインスタンスロールを引き受けるもの) は対象外。
// 決定 (設計書 6 章): 引き受けの向き (外向き / 内向き / 内部) と MFA の有無を規則で決め、見出しと data に出す。
// 決められないときは書かない (向き)・「不明」と書く (MFA)。Key と Fingerprint は変えない。
type UnknownAssumeRole struct{}

func (UnknownAssumeRole) Name() string         { return "unknown_assume_role" }
func (UnknownAssumeRole) Cadence() Cadence     { return Hourly }
func (UnknownAssumeRole) Mode() Mode           { return ModeEvent }
func (UnknownAssumeRole) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

// 引き受けの向き (data.direction)。
const (
	dirOutbound = "outbound" // 呼び出し元が監査対象のアカウント、ロールが別のアカウント
	dirInbound  = "inbound"  // 呼び出し元が別のアカウント、ロールが監査対象のアカウント
	dirInternal = "internal" // どちらも監査対象のアカウント
)

// MFA の判定 (data.mfa)。mixed は 1 つの finding のイベントで判定が揃わないとき。
const (
	mfaYes     = "true"
	mfaNo      = "false"
	mfaUnknown = "unknown"
	mfaMixed   = "mixed"
)

// maxAssumeLabel は見出しに出す呼び出し元・ロールの表記の長さの上限 (IAM のパス 512 + 名前 64 より短く切る。超えたら向きを書かない)。
const maxAssumeLabel = 128

// ARN はログ由来の値なので、向きを書くのは決まった形のときだけにする (ADR 0037・0041)。
// 名前の文字は IAM が許すもの (英数字と `+=,.@_-`、パスの `/`)。`$` は末尾の改行にも合うので \z。
var (
	assumeCallerRe = regexp.MustCompile(`^arn:aws[a-z-]*:(?:iam|sts)::([0-9]{12}):([A-Za-z0-9+=,.@_/-]+)\z`)
	assumeRoleRe   = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]+)\z`)
	accountIDRe    = regexp.MustCompile(`^[0-9]{12}\z`)
)

// assumeParties は 1 つの引き受け (呼び出し元 → ロール) の向きと、見出しに出す表記。向きが決まらなければ全部空。
type assumeParties struct {
	direction     string
	callerAccount string
	roleAccount   string
	callerLabel   string // ARN のアカウントより後ろ (user/alice、role/Deploy、root)
	roleLabel     string // role/ より後ろ (パスを含む)
}

// newAssumeParties は向きを規則で決める。recipient は記録を受け取ったアカウント (CloudTrail の recipientAccountId。無ければ空)。
//
// 決定 (設計書 6 章): 監査対象のアカウントは recipientAccountId (証跡のアカウント)。無い記録 (以前の版で集めたもの) は、
// AWS の文書にある記録の形から決まるときだけ決める:
//   - 呼び出し元とロールが同じアカウント → 内部 (同じアカウントどうしの呼び出しは、そのアカウントにしか記録されない)
//   - 呼び出し元が「外部アカウントそのもの」(userIdentity.type=AWSAccount。ロール側の記録の形) → 内向き
//   - 呼び出し元が IAM ユーザーの ARN (呼び出し側の記録の形。ロール側にはアカウント ID と principalId しか載らない) → 外向き
//   - それ以外 (ロールからのクロスアカウント) は recipientAccountId が無ければ決めない
//
// recipientAccountId が上の形と食い違うとき・呼び出し元とロールのどちらのアカウントでもないときは決めない (推測しない)。
func newAssumeParties(callerARN string, kind record.PrincipalKind, roleARN, recipient string) assumeParties {
	c := assumeCallerRe.FindStringSubmatch(callerARN)
	r := assumeRoleRe.FindStringSubmatch(roleARN)
	if c == nil || r == nil || len(c[2]) > maxAssumeLabel || len(r[2]) > maxAssumeLabel {
		return assumeParties{}
	}
	if recipient != "" && (!accountIDRe.MatchString(recipient) || (recipient != c[1] && recipient != r[1])) {
		return assumeParties{}
	}
	p := assumeParties{callerAccount: c[1], roleAccount: r[1], callerLabel: c[2], roleLabel: r[2]}
	_, external := record.ExternalAccount(callerARN, kind)
	switch {
	case p.callerAccount == p.roleAccount:
		p.direction = dirInternal
	case external:
		if recipient == p.callerAccount {
			return assumeParties{}
		}
		p.direction = dirInbound
	case kind == record.PrincipalUser:
		if recipient == p.roleAccount {
			return assumeParties{}
		}
		p.direction = dirOutbound
	case recipient == p.callerAccount:
		p.direction = dirOutbound
	case recipient == p.roleAccount:
		p.direction = dirInbound
	default:
		return assumeParties{}
	}
	return p
}

// assumeMFA は 1 件の AssumeRole が MFA を伴ったかを、イベントの data から決める。
// 決定 (設計書 6 章): 「あり」は呼び出しに MFA デバイスを指定した (requestParameters.serialNumber。collector が有無だけ mfa_serial に残す) か、
// 呼び出し元のセッションが MFA で認証済み (userIdentity.sessionContext.attributes.mfaAuthenticated=true。session_mfa)。
// 「なし」は mfaAuthenticated=false が記録にあり、serialNumber が無いときだけ。どちらの項目も無い記録
// (長期のアクセスキーでの呼び出し、ロール側の記録など) は「不明」で、「なし」と書かない。
func assumeMFA(data map[string]any) string {
	if v, ok := data["mfa_serial"].(bool); ok && v {
		return mfaYes
	}
	switch v, _ := data["session_mfa"].(string); v {
	case "true":
		return mfaYes
	case "false":
		return mfaNo
	}
	return mfaUnknown
}

var (
	dirLabels = map[string]string{dirOutbound: "外向き", dirInbound: "内向き", dirInternal: "内部"}
	mfaLabels = map[string]string{mfaYes: "MFA あり", mfaNo: "MFA なし", mfaUnknown: "MFA 不明", mfaMixed: "MFA の有無が混在"}
)

// assumeSummary は見出し。向きが決まれば「自アカウントの … / 外部アカウント NNN の …」と向きを書き、決まらなければ従来の形 (ARN のまま) にする。
// 決定 (設計書 6 章): accountOnly (呼び出し元がアカウントしか分からない) なら、呼び出し元を record.AccountOnlyLabel の文で書く。
// ARN の末尾の `root` を表記に使わない (ルートユーザーと読める)。向きが決まらないときの caller も、呼ぶ側が同じ文にして渡す。
func assumeSummary(p assumeParties, accountOnly bool, caller, role string, count int, mfa string) string {
	if p.direction == "" {
		return fmt.Sprintf("既知リストに無い %s が %s を %d 回引き受け (%s)", caller, role, count, mfaLabels[mfa])
	}
	who := "自アカウントの " + p.callerLabel
	switch {
	case accountOnly && p.direction == dirInternal:
		who = "自アカウント (呼び出した主体は記録に無い)" // 自アカウントの ID しか無い記録。「外部」とも root とも書かない
	case accountOnly:
		who = record.AccountOnlyLabel(p.callerAccount)
	case p.direction == dirInbound:
		who = "外部アカウント " + p.callerAccount + " の " + p.callerLabel
	}
	target := "自アカウントのロール " + p.roleLabel
	if p.direction == dirOutbound {
		target = "外部アカウント " + p.roleAccount + " のロール " + p.roleLabel
	}
	return fmt.Sprintf("既知リストに無い%s が%s を %d 回引き受け (%s、%s)", who, target, count, dirLabels[p.direction], mfaLabels[mfa])
}

// assumeAgg は Key ごとの集計に、向きと MFA の判定に要る値を足したもの。
type assumeAgg struct {
	*eventAgg
	caller, role string
	kind         record.PrincipalKind
	recipients   map[string]bool
	mfa          map[string]bool
	services     map[string]bool
}

func (c UnknownAssumeRole) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{NamePrefixes: []string{"AssumeRole"}})
	if err != nil {
		return nil, err
	}
	aggs := map[string]*assumeAgg{}
	for _, e := range evs {
		if e.PrincipalKind == record.PrincipalService || e.PrincipalARN == "" {
			continue
		}
		_, status := al.Principal(e.PrincipalARN, w.To)
		if status == allowlist.StatusApproved {
			continue
		}
		role, _ := e.Data["role_arn"].(string)
		if role == "" {
			role = e.Resource
		}
		k := e.PrincipalARN + "->" + role
		a, ok := aggs[k]
		if !ok {
			a = &assumeAgg{eventAgg: newEventAgg(), caller: e.PrincipalARN, role: role, kind: e.PrincipalKind,
				recipients: map[string]bool{}, mfa: map[string]bool{}, services: map[string]bool{}}
			a.extra["caller"] = e.PrincipalARN
			a.extra["caller_kind"] = string(e.PrincipalKind)
			a.extra["role_arn"] = role
			a.extra["allowlist_status"] = string(status)
			// 決定 (設計書 6 章): 呼び出し元がアカウントしか分からないとき (ロール側の記録) は caller_identity: account_only を足す。
			// caller と Key は ARN (`...:root`) のまま。caller_kind は主体の種類の語彙のまま (approve が種類として読む)
			markAccountOnly(a.extra, "caller_identity", e.PrincipalARN, e.PrincipalKind)
			aggs[k] = a
		}
		a.add(e.Time, e.Name, e.IP)
		a.recipients[dataStr(e.Data, "recipient_account")] = true
		a.mfa[assumeMFA(e.Data)] = true
		if name, ok := record.ServiceName(dataStr(e.Data, "invoked_by")); ok {
			a.services[name] = true
		}
		if e.ErrorCode != "" {
			a.extra["has_errors"] = true
		}
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		// 受け取ったアカウントがイベントによって違うなら向きを決めない (1 つの証跡なら同じ値になる)
		var p assumeParties
		if len(a.recipients) == 1 {
			for recipient := range a.recipients {
				p = newAssumeParties(a.caller, a.kind, a.role, recipient)
			}
		}
		if p.direction != "" {
			a.extra["direction"] = p.direction
			a.extra["caller_account"] = p.callerAccount
			a.extra["role_account"] = p.roleAccount
		}
		// 決定: MFA は全イベントの判定が揃ったときだけ「あり / なし / 不明」。揃わなければ mixed
		// (1 件の「あり」で全体を「あり」と書かない。「不明」を「なし」に寄せない)
		mfa := mfaMixed
		if len(a.mfa) == 1 {
			for v := range a.mfa {
				mfa = v
			}
		}
		a.extra["mfa"] = mfa
		// 決定: 送信元の IP が無いとき (コンソールのスイッチロールなど、送信元が AWS のサービス名の記録) は、どのサービス経由かを出す (root_usage と同じ)
		if len(a.ips) == 0 && len(a.services) > 0 {
			a.extra["invoked_by"] = capList(sortedKeys(a.services), maxInvokedBy)
		}
		caller := a.caller
		acct, accountOnly := record.ExternalAccount(a.caller, a.kind)
		if accountOnly {
			caller = record.AccountOnlyLabel(acct)
		}
		obs[k] = Observation{
			Check:    c.Name(),
			Key:      k,
			Severity: High,
			Summary:  assumeSummary(p, accountOnly, caller, a.role, a.count, mfa),
			// 決定: Fingerprint は変えない (向きは Key から決まる。MFA を足すと既存の finding が一斉に changed になる)
			Fingerprint: fingerprint(High, a.ips, a.extra["allowlist_status"]),
			Data:        a.data(),
		}
	}
	return sortedObs(obs), nil
}

package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/config"
)

// CheckAuditAccount は設定の audit_account (監査する側のアカウント) と既知リストの食い違いを見る (config check と doctor が使う)。
// status は ok / warn / ng。見るものが無ければ (none) 空を返す。l が nil なら空の既知リストとして扱う。
//
// 決定 (ADR 0045):
//   - 選んでいない (この項目より前の版で作った設定) は warn。run は止めない: 版を上げただけで監査が止まるほうが、誤報より悪い
//   - ID を書いたのに、期限内の account: の項目が既知リストに無ければ ng。unknown_assume_role が監査そのものを high で報告する状態で、
//     これを PR の時点 (config check) と導入の時点 (doctor) で止めるのがこの項目の目的。run は止めない (その run が high で知らせる)
//   - audit_account は判定に使わない。承認は既知リストだけが持つ (人が見て承認した一覧を 1 か所に保つ)
func CheckAuditAccount(cfg *config.Config, l *allowlist.List, now time.Time) (status, msg string) {
	if cfg.AuditAccount == "" {
		return DoctorWarn, `audit_account is not set: choose who runs the audit of this target. Add audit_account: "<12-digit AWS account ID>" if a role in another account assumes this target's read-only role ` +
			`(and list that account in the allowlist as account:, or unknown_assume_role reports the audit itself as high), or audit_account: none if the audit runs inside the target account or with your own credentials`
	}
	id, none, err := config.ParseAuditAccount(cfg.AuditAccount)
	if err != nil {
		return DoctorNG, "audit_account: " + err.Error() // Load が先に止めるので、ふつうは来ない
	}
	if none {
		return "", ""
	}
	st := allowlist.StatusUnknown
	if l != nil {
		st = l.Account(id, now)
	}
	fix := fmt.Sprintf(`add an entry with account: %q and a note to principals in the allowlist (unknown_assume_role reports the audit itself as high without it), or set audit_account: none if the audit no longer runs from another account`, id)
	switch st {
	case allowlist.StatusApproved:
		return DoctorOK, fmt.Sprintf("audit_account %s is approved in the allowlist (account:)", id)
	case allowlist.StatusExpired:
		return DoctorNG, fmt.Sprintf("audit_account %s: the allowlist entry (account:) has expired: extend or remove expires, or %s", id, fix)
	}
	return DoctorNG, fmt.Sprintf("audit_account %s is not in the allowlist: %s", id, fix)
}

// auditAccount は audit_account に ID を書いた設定で、既知リストとの食い違いと、その ID が監査対象のアカウントそのものでないことを確かめる。
//
// 決定 (ADR 0045): 「監査する側」を「arata を動かしているアカウント」と読んで監査対象の ID を書くと、account: の項目が監査対象の
// 全主体を承認してしまう (new_principal などが黙る)。オフラインでは分からないので、doctor が sts:GetCallerIdentity (権限不要) で比べる。
// none・未選択のときは問い合わせない。
func (d *doctor) auditAccount(ctx context.Context, l *allowlist.List) {
	id, none, err := config.ParseAuditAccount(d.cfg.AuditAccount)
	if err != nil || none {
		return
	}
	row := func(status, code, detail string) {
		d.res.Rows = append(d.res.Rows, DoctorRow{Source: "-", Kind: "-", Item: "audit_account", Status: status, Code: code, Detail: detail})
	}
	cl, err := d.deps.Account(ctx, d.cfg, config.Source{ID: "-", Kind: "-"}, d.cfg.AWS.Region)
	if err == nil {
		var out *sts.GetCallerIdentityOutput
		if out, err = cl.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil && out.Account != nil && *out.Account == id {
			row(DoctorNG, CodeConfigInvalid, fmt.Sprintf("audit_account %s は監査対象のアカウントそのもの。account: の項目がこのアカウントの全主体を承認してしまう。"+
				"同じアカウントの中で動かすなら audit_account: %s にし、allowlist の account: \"%s\" を消して、実行用ロールを arn: で書く", id, config.AuditAccountNone, id))
			return
		}
	}
	if status, msg := CheckAuditAccount(d.cfg, l, d.now); status == DoctorNG {
		row(status, CodeConfigInvalid, msg)
	} else {
		row(status, "", msg)
	}
	if err != nil {
		row(DoctorWarn, "", "監査対象のアカウントを確かめられない (sts:GetCallerIdentity): "+err.Error())
	}
}

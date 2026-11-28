package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// sharedChecks は `approve --shared` を使えるチェック (人の多い送信元の下限が効くもの。ADR 0094 の 1 節)。
var sharedChecks = map[string]bool{"rate_limited_ip": true, "login_bruteforce": true}

// sharedTargetOf は、`approve --shared` で人の多い送信元にする IP の、既定の範囲 (/32。IPv6 は /128) を finding から決める。
// IP は finding の data (ログ由来の値) なので、netip で読み直した正規の形だけを使う。既に shared の IP (data の shared) には使えない。
func sharedTargetOf(f store.Finding) (string, error) {
	if !sharedChecks[f.Check] {
		return "", fmt.Errorf("%w: --shared is only for rate_limited_ip and login_bruteforce findings (this is %s)", errNotApprovable, f.Check)
	}
	if v, _ := f.Data["shared"].(bool); v {
		return "", fmt.Errorf("%w: this IP is already in shared_sources (edit the entry directly to change note / expires)", errNotApprovable)
	}
	addr, err := netip.ParseAddr(str(f.Data["ip"]))
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("%w: finding has no valid IP", errNotApprovable)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// approveShared は `approve <id> --shared`: finding (rate_limited_ip・login_bruteforce) の IP を、allowlist.yaml の shared_sources に追記し、
// finding を resolved にする (ADR 0094 の 1 節)。
//
// 決定:
//   - 主体は承認しない。外すのではなく、その送信元を別のしきい値 (shared_min_count) で見るようにする
//   - 既定は IP そのもの (/32、IPv6 は /128)。--shared-cidr で範囲を書ける。範囲は finding の IP を含むネットワークの形だけで、
//     IPv4 は /24、IPv6 は /48 より広いものは書かない (総当たりのしきい値を広く上げる穴になる)
//   - --expires は任意 (試験の日だけ、のような使い方)。過去の日付は拒む (approve の --expires と同じ)
//   - 主体の承認の指定 (--account / --arn-pattern / --tag / --expected-denied) とは一緒に使えない
//   - LLM は実行しない。人が判断して実行する (approve と同じ。arata help ai approve)
func (e *Engine) approveShared(ctx context.Context, f *store.Finding, o ApproveOptions) (*ApproveResult, error) {
	if o.Account || o.ARNPattern != "" || len(o.Tags) > 0 || len(o.ExpectedDenied) > 0 {
		return nil, e.configErr(errors.New("--shared adds a source to shared_sources, not a principal: it cannot be combined with --account, --arn-pattern, --tag or --expected-denied"))
	}
	cidr, err := sharedTargetOf(*f)
	if err != nil {
		return nil, e.configErr(fmt.Errorf("finding %s: %w", f.ID, err))
	}
	if o.SharedCIDR != "" {
		p, err := netip.ParsePrefix(o.SharedCIDR)
		if err != nil {
			return nil, e.configErr(fmt.Errorf("--shared-cidr %q: %w", o.SharedCIDR, err))
		}
		ip := netip.MustParsePrefix(cidr).Addr()
		if p.Addr().Is4In6() || !p.Contains(ip) {
			return nil, e.configErr(fmt.Errorf("--shared-cidr %s does not contain the IP of the finding (%s)", o.SharedCIDR, ip))
		}
		cidr = o.SharedCIDR
	}
	if allowlist.SharedCIDRTooBroad(cidr) {
		return nil, e.configErr(fmt.Errorf("--shared-cidr %s is broader than /%d (IPv4) or /%d (IPv6): narrow it to the network of the school or venue", cidr, allowlist.SharedMinPrefixV4, allowlist.SharedMinPrefixV6))
	}
	now := e.deps.Now()
	s := allowlist.NewSharedSource{CIDR: cidr, Note: o.Note, ApprovedAt: now.UTC().Format(record.DateLayout), ApprovedBy: e.approvedBy(o)}
	if s.Expires, err = e.approveExpires(o.Expires, now); err != nil {
		return nil, err
	}
	if err := e.checkCommit(ctx, o); err != nil {
		return nil, err
	}
	added, err := allowlist.AppendShared(e.cfg.Allowlist, s)
	if err != nil {
		return nil, e.configErr(err)
	}
	res := &ApproveResult{Finding: *f, Shared: &s, Added: added}
	if err := e.st.SetFindingStatus(ctx, f.ID, store.FindingResolved, time.Time{}, now, store.Action{Name: store.ActionApprove, By: s.ApprovedBy, Reason: o.Note}); err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("allowlist: shared source %s\n\nfinding: %s (%s)\nnote: %s\napproved_by: %s\n", s.Subject(), f.ID, f.Check, o.Note, s.ApprovedBy)
	return res, e.finishApprove(ctx, res, s.ApprovedBy, msg, o.Commit, now)
}

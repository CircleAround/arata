package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// 人の判断による finding の操作 (設計書 6-2): review / approve / ack / snooze / resolve。

// ApproveTarget は approve が allowlist に追記する対象。
type ApproveTarget struct {
	ARN        string `json:"arn,omitempty"`
	Account    string `json:"account,omitempty"`
	ARNPattern string `json:"arn_pattern,omitempty"`
	// Label はレポートと同じ表示 (外部アカウントの root は「外部アカウント NNN」)。
	Label string `json:"label"`
}

// Subject は allowlist のエントリと同じ形の表示。
func (t ApproveTarget) Subject() string {
	return allowlist.NewEntry{ARN: t.ARN, Account: t.Account, ARNPattern: t.ARNPattern}.Subject()
}

// ReviewItem は review の 1 行。
type ReviewItem struct {
	ID          string         `json:"id"`
	Check       string         `json:"check"`
	Key         string         `json:"key"`
	Severity    string         `json:"severity"`
	Status      string         `json:"status"`
	Summary     string         `json:"summary"`
	FirstSeen   string         `json:"first_seen"`
	LastSeen    string         `json:"last_seen"`
	SnoozeUntil string         `json:"snooze_until,omitempty"`
	Data        map[string]any `json:"data"`
	// Approve は approve できる finding (主体に関するもの) の追記対象。それ以外は ack / snooze / resolve で扱う。
	Approve *ApproveTarget `json:"approve,omitempty"`
}

// DefaultReviewStatuses は review の既定 (未対応の一覧)。
var DefaultReviewStatuses = []string{store.FindingOpen, store.FindingAcked}

// Review は指定した状態の finding を重大度の高い順 → 初出の古い順に返す。対話はしない (組み込み側の LLM が人に聞く材料)。
func (e *Engine) Review(ctx context.Context, statuses []string) ([]ReviewItem, error) {
	if len(statuses) == 0 {
		statuses = DefaultReviewStatuses
	}
	for _, s := range statuses {
		switch s {
		case store.FindingOpen, store.FindingAcked, store.FindingSnoozed, store.FindingResolved:
		default:
			return nil, e.configErr(fmt.Errorf("unknown status %q (open|acked|snoozed|resolved)", s))
		}
	}
	fs, err := e.st.Findings(ctx, "", statuses)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := checks.Severity(fs[i].Severity).Rank(), checks.Severity(fs[j].Severity).Rank()
		if ri != rj {
			return ri > rj
		}
		if !fs[i].FirstSeen.Equal(fs[j].FirstSeen) {
			return fs[i].FirstSeen.Before(fs[j].FirstSeen)
		}
		return fs[i].ID < fs[j].ID
	})
	out := make([]ReviewItem, 0, len(fs))
	for _, f := range fs {
		it := ReviewItem{ID: f.ID, Check: f.Check, Key: f.Key, Severity: f.Severity, Status: f.Status, Summary: f.Summary,
			FirstSeen: f.FirstSeen.UTC().Format(time.RFC3339), LastSeen: f.LastSeen.UTC().Format(time.RFC3339), Data: f.Data}
		if !f.SnoozeUntil.IsZero() {
			it.SnoozeUntil = f.SnoozeUntil.UTC().Format(time.RFC3339)
		}
		if it.Data == nil {
			it.Data = map[string]any{}
		}
		if t, err := ApproveTargetOf(f); err == nil {
			it.Approve = t
		}
		out = append(out, it)
	}
	return out, nil
}

// errNotApprovable は主体に関しない finding を approve しようとしたとき。
var errNotApprovable = errors.New("not approvable")

// ApproveTargetOf は finding から allowlist に追記する主体を決める。
//
// 決定:
//   - new_principal: Key の主体。unknown_assume_role: 呼び出し元 (caller)。iam_changes: 変更した主体 (`--tag deploy` で既知デプロイ主体にする用途)
//   - 主体が外部アカウントの root (SaaS 連携のクロスアカウント AssumeRole) なら `account:` で承認する
//   - それ以外のチェック (root_usage、アプリ層など) は主体の承認ではないので approve できない (ack / snooze / resolve を使う)
func ApproveTargetOf(f store.Finding) (*ApproveTarget, error) {
	arn, k, err := subjectPrincipal(f)
	if err != nil {
		return nil, err
	}
	if acct, ok := record.ExternalAccount(arn, k); ok {
		return &ApproveTarget{Account: acct, Label: record.PrincipalLabel(arn, k)}, nil
	}
	return &ApproveTarget{ARN: arn, Label: arn}, nil
}

// subjectPrincipal は finding の対象主体 (approve で承認する主体) の ARN と種類。
func subjectPrincipal(f store.Finding) (string, record.PrincipalKind, error) {
	var arn, kind string
	switch f.Check {
	case "new_principal":
		arn, kind = f.Key, str(f.Data["kind"])
	case "unknown_assume_role":
		arn, kind = str(f.Data["caller"]), str(f.Data["caller_kind"])
	case "iam_changes":
		arn, kind = str(f.Data["principal"]), str(f.Data["principal_kind"])
		if kind == string(record.PrincipalRoot) {
			return "", "", fmt.Errorf("%w: the root user cannot be approved", errNotApprovable)
		}
	default:
		return "", "", fmt.Errorf("%w: %s findings are not about a principal; use ack, snooze or resolve", errNotApprovable, f.Check)
	}
	if arn == "" {
		return "", "", fmt.Errorf("%w: finding has no principal ARN", errNotApprovable)
	}
	return arn, record.PrincipalKind(kind), nil
}

// allowlistResolvable は、主体が allowlist で承認されたら解消してよいチェック。どちらも「allowlist に無いこと」自体を報告している。
//
// 決定: iam_changes は含めない。承認済み (deploy タグ無し) の主体による IAM 変更も medium で報告するチェックなので、
// 承認を理由に解消すると次の観測で new に戻り、毎回 resolved → new を繰り返す。iam_changes は approve した 1 件だけを resolved にする。
var allowlistResolvable = map[string]bool{"new_principal": true, "unknown_assume_role": true}

// ReasonAllowlisted は allowlist の承認で解消した finding の Data["resolved_reason"]。
const ReasonAllowlisted = "allowlisted"

// resolveAllowlisted は open / acked / snoozed の finding のうち、対象主体が al で承認済み (at 時点で有効) のものを resolved にして返す。
// approve の直後と evaluate の冒頭 (人が allowlist.yaml を直接編集した場合の経路) で呼ぶ。
func (e *Engine) resolveAllowlisted(ctx context.Context, al *allowlist.List, at, now time.Time, skipID string) ([]store.Finding, error) {
	fs, err := e.st.Findings(ctx, "", []string{store.FindingOpen, store.FindingAcked, store.FindingSnoozed})
	if err != nil {
		return nil, err
	}
	var out []store.Finding
	for _, f := range fs {
		if f.ID == skipID || !allowlistResolvable[f.Check] {
			continue
		}
		arn, _, err := subjectPrincipal(f)
		if err != nil {
			continue
		}
		entry, st := al.Principal(arn, at)
		if st != allowlist.StatusApproved {
			continue
		}
		data := map[string]any{}
		for k, v := range f.Data {
			data[k] = v
		}
		data["resolved_reason"] = ReasonAllowlisted
		data["allowlist_subject"] = entry.Subject()
		f.Data, f.Status, f.LastChanged, f.SnoozeUntil = data, store.FindingResolved, now, time.Time{}
		if err := e.st.UpsertFinding(ctx, f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	evs := make([]store.FindingEvent, 0, len(out))
	for _, f := range out {
		evs = append(evs, findingEvent(f, string(checks.ClassResolved), now, e.runID, e.runProfile))
	}
	return out, e.st.AddFindingEvents(ctx, evs)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// ApproveOptions は approve の指定。
type ApproveOptions struct {
	Note    string
	Expires string // YYYY-MM-DD
	Tags    []string
	By      string // 空なら OS のユーザー名
	Commit  bool   // allowlist.yaml を git commit する
	// Account は主体のアカウント全体を承認する (`account:`)。ARNPattern は glob で承認する。どちらも空なら主体そのもの。
	Account    bool
	ARNPattern string
	// ExpectedDenied は access_denied の finding の主体に、想定済みの拒否 (「サービス:操作」の glob) を付けて追記する (ADR 0022)。
	ExpectedDenied []string
}

// ApproveResult は approve の結果。
type ApproveResult struct {
	Finding   store.Finding
	Entry     allowlist.NewEntry
	Added     string // allowlist.yaml に追記したテキスト
	Committed bool
	// AlsoResolved は、追記後の allowlist で対象主体が承認済みになったため一緒に resolved にした他の finding。
	AlsoResolved []store.Finding
	// KeptOpen は finding を resolved にしなかったこと (--expected-denied。次の run で除いて数え直す)。
	KeptOpen bool
}

// deniedTargetOf は access_denied の finding の主体 (expected_denied を付ける対象)。
func deniedTargetOf(f store.Finding) (*ApproveTarget, error) {
	arn, kind := str(f.Data["principal"]), record.PrincipalKind(str(f.Data["principal_kind"]))
	if arn == "" {
		return nil, fmt.Errorf("%w: finding has no principal ARN", errNotApprovable)
	}
	if acct, ok := record.ExternalAccount(arn, kind); ok {
		return &ApproveTarget{Account: acct, Label: record.PrincipalLabel(arn, kind)}, nil
	}
	return &ApproveTarget{ARN: arn, Label: arn}, nil
}

// Approve は finding の主体を allowlist.yaml に追記し、finding を resolved にする (設計書 6-2)。
// 人 (または人の承認を得た LLM) が実行する前提。git への commit は既定では人が行い、Commit で代行する。
func (e *Engine) Approve(ctx context.Context, id string, o ApproveOptions) (*ApproveResult, error) {
	f, err := e.findingForUpdate(ctx, id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(o.Note) == "" {
		return nil, e.configErr(errors.New("--note is required (why this principal is legitimate)"))
	}
	var target *ApproveTarget
	switch {
	case len(o.ExpectedDenied) > 0 && f.Check != "access_denied":
		return nil, e.configErr(fmt.Errorf("finding %s: --expected-denied is only for access_denied findings (this is %s)", id, f.Check))
	case len(o.ExpectedDenied) > 0:
		target, err = deniedTargetOf(*f)
	case f.Check == "access_denied":
		// 決定 (ADR 0021・0022): 主体の承認は「居ること」を認めるもので、権限を探ってよいではない。access_denied は主体ごと承認しない
		err = fmt.Errorf("%w: approve access_denied with --expected-denied <service:Action> for expected denials, or use ack / snooze", errNotApprovable)
	default:
		target, err = ApproveTargetOf(*f)
	}
	if err != nil {
		return nil, e.configErr(fmt.Errorf("finding %s: %w", id, err))
	}
	for _, g := range o.ExpectedDenied {
		if err := allowlist.CheckDeniedGlob(g); err != nil {
			return nil, e.configErr(fmt.Errorf("--expected-denied %w", err))
		}
	}
	now := e.deps.Now()
	entry := allowlist.NewEntry{Note: o.Note, ApprovedAt: now.UTC().Format(record.DateLayout), Tags: o.Tags, ExpectedDenied: o.ExpectedDenied}
	switch {
	case o.ARNPattern != "":
		entry.ARNPattern = o.ARNPattern
		if target.ARN != "" {
			if ok, err := allowlist.MatchPattern(o.ARNPattern, target.ARN); err != nil || !ok {
				return nil, e.configErr(fmt.Errorf("--arn-pattern %q does not match %s", o.ARNPattern, target.ARN))
			}
		}
	case o.Account || target.Account != "":
		entry.Account = target.Account
		if entry.Account == "" {
			entry.Account = allowlist.AccountOf(target.ARN)
		}
	default:
		entry.ARN = target.ARN
	}
	if o.Expires != "" {
		t, err := time.Parse(record.DateLayout, o.Expires)
		if err != nil {
			return nil, e.configErr(fmt.Errorf("--expires %q: want YYYY-MM-DD", o.Expires))
		}
		if !t.Add(24 * time.Hour).After(now) {
			return nil, e.configErr(fmt.Errorf("--expires %s is already past", o.Expires))
		}
		entry.Expires = o.Expires
	}
	entry.ApprovedBy = o.By
	if entry.ApprovedBy == "" {
		entry.ApprovedBy = e.deps.User()
	}
	if o.Commit {
		if _, err := e.deps.Git(ctx, filepath.Dir(e.cfg.Allowlist), "rev-parse", "--is-inside-work-tree"); err != nil {
			return nil, e.configErr(fmt.Errorf("--commit: %s is not in a git work tree: %w", filepath.Dir(e.cfg.Allowlist), err))
		}
	}
	added, err := allowlist.Append(e.cfg.Allowlist, entry)
	if errors.Is(err, allowlist.ErrAlreadyListed) && len(o.ExpectedDenied) > 0 {
		// 既存の項目は書き換えない (ADR 0010)。足す行を示して人に任せる
		return nil, e.configErr(fmt.Errorf("%s is already in %s; add (or merge into) this line of that entry by hand:\n    expected_denied: %s",
			entry.Subject(), e.cfg.Allowlist, allowlist.FormatExpectedDenied(o.ExpectedDenied)))
	}
	if err != nil {
		return nil, e.configErr(err)
	}
	res := &ApproveResult{Finding: *f, Entry: entry, Added: added}
	if len(o.ExpectedDenied) > 0 {
		// 決定: access_denied は resolved にしない。次の run で想定済みの拒否を除いて数え直し、閾値を下回れば報告されなくなる
		res.KeptOpen = true
	} else if err := e.st.SetFindingStatus(ctx, f.ID, store.FindingResolved, time.Time{}, now); err != nil {
		return nil, err
	}
	// 同じ主体 (account / arn_pattern なら一致する全主体) の他の finding も解消する。evaluate を待つと event 型の finding は open のまま残るため
	al, err := allowlist.Load(e.cfg.Allowlist)
	if err != nil {
		return res, err
	}
	e.al = al
	if res.AlsoResolved, err = e.resolveAllowlisted(ctx, al, now, now, f.ID); err != nil {
		return res, err
	}
	e.log.Info("approved", "finding", f.ID, "check", f.Check, "subject", entry.Subject(), "by", entry.ApprovedBy, "allowlist", e.cfg.Allowlist, "also_resolved", len(res.AlsoResolved))
	if o.Commit {
		dir, name := filepath.Dir(e.cfg.Allowlist), filepath.Base(e.cfg.Allowlist)
		msg := fmt.Sprintf("allowlist: approve %s\n\nfinding: %s (%s)\nnote: %s\napproved_by: %s\n", entry.Subject(), f.ID, f.Check, o.Note, entry.ApprovedBy)
		if len(o.ExpectedDenied) > 0 {
			msg = fmt.Sprintf("allowlist: expected_denied for %s\n\nfinding: %s (%s)\nexpected_denied: %s\nnote: %s\napproved_by: %s\n",
				entry.Subject(), f.ID, f.Check, allowlist.FormatExpectedDenied(o.ExpectedDenied), o.Note, entry.ApprovedBy)
		}
		if _, err := e.deps.Git(ctx, dir, "add", "--", name); err != nil {
			return res, fmt.Errorf("git add: %w", err)
		}
		// パスを指定して commit し、他に stage されている変更を巻き込まない
		if _, err := e.deps.Git(ctx, dir, "commit", "-m", msg, "--", name); err != nil {
			return res, fmt.Errorf("git commit: %w", err)
		}
		res.Committed = true
	}
	return res, nil
}

// SetStatus は ack / snooze / resolve。snooze は until (その日の 0 時 UTC まで沈黙し、以後の再観測で new として再報告) が必要。
func (e *Engine) SetStatus(ctx context.Context, id, status string, until time.Time) (*store.Finding, error) {
	f, err := e.findingForUpdate(ctx, id)
	if err != nil {
		return nil, err
	}
	now := e.deps.Now()
	if status == store.FindingSnoozed && !until.After(now) {
		return nil, e.configErr(fmt.Errorf("--until must be in the future"))
	}
	if err := e.st.SetFindingStatus(ctx, f.ID, status, until, now); err != nil {
		return nil, err
	}
	f.Status, f.LastChanged = status, now
	if status == store.FindingSnoozed {
		f.SnoozeUntil = until
	}
	e.log.Info("finding status changed", "finding", f.ID, "check", f.Check, "status", status)
	return f, nil
}

func (e *Engine) findingForUpdate(ctx context.Context, id string) (*store.Finding, error) {
	f, err := e.st.Finding(ctx, id)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, e.configErr(fmt.Errorf("finding %q not found (see `arata review`)", id))
	}
	if f.Status == store.FindingResolved {
		return nil, e.configErr(fmt.Errorf("finding %s is already resolved", id))
	}
	return f, nil
}

// OSUser は approved_by の既定 (OS のユーザー名)。
func OSUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// RunGit は dir で git を実行する。
func RunGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/CircleAround/arata/internal/engine"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
	"github.com/CircleAround/arata/internal/subcmd"
)

// 人の判断による finding の操作 (設計書 6-2)。

func newReviewCmd(d *Deps, g *globalFlags) *subcmd.Command {
	var statuses []string
	var format string
	cmd := &subcmd.Command{
		Use:   "review",
		Short: "未対応 (open / acked) の finding を一覧する (対話なし。approve できるものは対象を示す)",
		Run: func(ctx context.Context, _ []string) error {
			e, err := openEngineForRead(ctx, d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			items, err := e.Review(ctx, statuses)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				b, err := json.MarshalIndent(items, "", "  ")
				if err != nil {
					return err
				}
				_, err = d.Stdout.Write(append(b, '\n'))
				return err
			case "table":
				if len(items) == 0 {
					fmt.Fprintln(d.Stdout, "該当する finding はありません。")
					return nil
				}
				tw := tabwriter.NewWriter(d.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tCHECK\tFIRST_SEEN\tAPPROVE\tLAST_ACTION\tSUMMARY")
				for _, it := range items {
					approve := "-"
					if it.Approve != nil {
						approve = it.Approve.Subject()
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", it.ID, it.Severity, it.Status, it.Check, it.FirstSeen, approve, lastActionCell(it), it.Summary)
				}
				return tw.Flush()
			}
			return formatErr(format, "table|json")
		},
	}
	cmd.StringSliceVar(&statuses, "status", "対象の状態 (open,acked,snoozed,resolved。既定 open,acked)")
	cmd.StringVar(&format, "format", "table", "出力形式 (table|json)")
	return cmd
}

func newApproveCmd(d *Deps, g *globalFlags) *subcmd.Command {
	o := engine.ApproveOptions{}
	cmd := &subcmd.Command{
		Use:   "approve <finding-id>",
		Short: "finding の主体を allowlist.yaml に追記し、finding を resolved にする (人が判断して実行する)",
		Long: `finding の主体を allowlist.yaml の principals の末尾に追記する。ファイルの他の部分 (コメント・順序・空行) は変えない。

  - new_principal は主体、unknown_assume_role は呼び出し元、iam_changes は変更した主体を承認する
  - 主体が外部アカウントの root なら account: で承認する (SaaS 連携)。--account で主体のアカウント全体を、--arn-pattern で glob を承認できる
  - access_denied は --expected-denied <サービス:操作の glob> (複数可) でだけ approve できる。想定済みの拒否として主体の項目を追記し、
    次の run から数えない。finding は resolved にしない。主体の項目が既にあれば書き換えず、足す行を示して止まる (手で足す)。
    項目を追記すると主体そのものも承認される (new_principal なども止まる)
  - unknown_assume_role の外向き (自アカウントの主体が別のアカウントのロールを引き受けた) で MFA ありの finding は、--destination で
    主体ではなく行き先のアカウントを assume_destinations に追記できる (ADR 0047)。以後、そのアカウントへの MFA ありの引き受けは誰のものでも
    報告しない (info の 1 行に件数を残す)。MFA なし・不明の引き受けと、ほかのアカウントへの引き受けは報告する。主体は承認されない。
    --destination-role <ロール名の glob> (複数可) でロールに絞れる。MFA ありと確かめられない finding には使えない
  - rate_limited_ip・login_bruteforce の finding は、--shared で主体ではなく finding の IP を人の多い送信元 (shared_sources) に追記できる
    (ADR 0094)。以後、その送信元は外さずに高い下限 (shared_min_count) で見る。既定は IP そのもの (/32、IPv6 は /128)。
    --shared-cidr <CIDR> で、IP を含むネットワーク (IPv4 は /24、IPv6 は /48 まで) を書ける。--expires で期限を付けられる (試験の日だけ、など)
  - approved_by は --by、省略時は OS のユーザー名。approved_at は今日 (UTC)
  - git への commit は人が行う。--commit を付けると allowlist.yaml だけを commit する

LLM は approve を実行せず、人に提案するだけにすること (arata help ai approve)。`,
		Args: subcmd.ExactArgs(1),
		Run: func(ctx context.Context, args []string) error {
			e, cfg, err := openEngine(ctx, d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			res, err := e.Approve(ctx, args[0], o)
			if res != nil {
				if cerr := e.Commit(ctx); cerr != nil {
					fmt.Fprintf(d.Stdout, "%s には追記しましたが、finding の状態はストアに保存できませんでした。arata resolve %s で片付けてください。\n", cfg.Allowlist, res.Finding.ID)
					return cerr
				}
				fmt.Fprintf(d.Stdout, "%s に追記しました (%s):\n%s", cfg.Allowlist, res.Subject(), res.Added)
				if res.KeptOpen {
					fmt.Fprintf(d.Stdout, "finding %s (access_denied) は open のままです。次の run で想定済みの拒否を除いて数え直します。\n", res.Finding.ID)
				} else {
					fmt.Fprintf(d.Stdout, "finding %s は resolved になりました。\n", res.Finding.ID)
				}
				if n := len(res.AlsoResolved); n > 0 {
					fmt.Fprintf(d.Stdout, "同じ承認に一致する他の %d 件も resolved にしました:\n", n)
					for _, f := range res.AlsoResolved {
						fmt.Fprintf(d.Stdout, "  - %s %s %s\n", f.ID, f.Check, f.Summary)
					}
				}
				if res.Committed {
					fmt.Fprintln(d.Stdout, "git commit しました。push は人が行ってください。")
				} else if err == nil {
					fmt.Fprintln(d.Stdout, "git commit は行っていません (差分を確認して commit してください)。")
				}
			}
			return err
		},
	}
	cmd.StringVar(&o.Note, "note", "", "承認の理由 (必須)")
	cmd.StringVar(&o.Expires, "expires", "", "期限 (YYYY-MM-DD)。過ぎたら expired として再報告")
	cmd.StringArrayVar(&o.Tags, "tag", "タグ (deploy: IAM 変更を info に下げる / ai: 監査・AI 用の主体として利用を毎回 info に出す)")
	cmd.StringVar(&o.By, "by", "", "承認者 (省略時は OS のユーザー名)")
	cmd.BoolVar(&o.Commit, "commit", false, "allowlist.yaml を git commit する")
	cmd.BoolVar(&o.Account, "account", false, "主体のアカウント全体を承認する (account:)")
	cmd.StringVar(&o.ARNPattern, "arn-pattern", "", "主体ではなく glob で承認する (arn_pattern:)")
	cmd.BoolVar(&o.Destination, "destination", false, "unknown_assume_role (外向き・MFA あり) の行き先のアカウントを既知にする (assume_destinations:。主体は承認しない)")
	cmd.StringArrayVar(&o.DestinationRoles, "destination-role", "--destination をこのロールだけに絞る (ロール名の glob。例 ReadOnly、ops-*。複数可)")
	cmd.BoolVar(&o.Shared, "shared", false, "rate_limited_ip・login_bruteforce の IP を人の多い送信元にする (shared_sources:。外さず高い下限で見る。主体は承認しない)")
	cmd.StringVar(&o.SharedCIDR, "shared-cidr", "", "--shared で書く範囲 (finding の IP を含む CIDR。IPv4 は /24、IPv6 は /48 まで。既定は IP そのもの)")
	cmd.StringArrayVar(&o.ExpectedDenied, "expected-denied", "access_denied の想定済みの拒否 (サービス:操作の glob。例 logs:StartQuery、logs:Get*。複数可)")
	return cmd
}

func newStatusCmd(d *Deps, g *globalFlags, use, status, short string) *subcmd.Command {
	var until, format string
	var o engine.StatusOptions
	cmd := &subcmd.Command{
		Use:   use + " <finding-id>...",
		Short: short,
		Long: fmt.Sprintf(`finding を %[1]s にする。ID は 1 つ以上 (%[2]d 件まで)。空白かカンマで区切る (arata %[3]s <id> <id>、arata %[3]s <id>,<id>)。
同じ status・--reason・--by (と --until・--force) を全部の ID に当て、ストアへの確定は 1 回 (S3 のストアでも 1 回の書き込み)。
検査 (ID の形と重複・finding の有無・片付けの表・期日) は書く前に全部済ませ、1 件でも通らなければ何も書かずに止め、止めた ID と理由を全部出す (ADR 0080)。
--format json は ID ごとの結果 (arata schema triage-result)。`, status, engine.MaxFindingIDs, use),
		Run: func(ctx context.Context, args []string) error {
			if format != "text" && format != "json" {
				return formatErr(format, "text|json")
			}
			ids, err := engine.ParseFindingIDs(args)
			if err != nil {
				d.Engine.Logger.Error("invalid finding ids", "code", engine.CodeConfigInvalid, "error", err.Error())
				return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: err}
			}
			var u time.Time
			if status == store.FindingSnoozed {
				t, err := time.Parse(record.DateLayout, until)
				if err != nil {
					d.Engine.Logger.Error("invalid --until", "code", engine.CodeConfigInvalid, "until", until)
					return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("--until %q: want YYYY-MM-DD", until)}
				}
				u = t
			}
			var e *engine.Engine
			if o.DryRun {
				// 試しはストアを書かない (Commit しない)。S3 でも何も送らない
				e, err = openEngineForRead(ctx, d, g)
			} else {
				e, _, err = openEngine(ctx, d, g)
			}
			if err != nil {
				return err
			}
			defer e.Close()
			b, err := e.ChangeStatuses(ctx, ids, status, u, o)
			if b == nil {
				return err
			}
			written := false
			if err == nil && !o.DryRun {
				err = e.Commit(ctx)
				written = err == nil
			}
			if format == "json" {
				out, merr := json.MarshalIndent(b.Result(use, written), "", "  ")
				if merr != nil {
					return merr
				}
				if _, werr := d.Stdout.Write(append(out, '\n')); werr != nil {
					return werr
				}
				return err
			}
			if b.Stopped > 0 {
				fmt.Fprint(d.Stdout, stoppedText(b, use))
				return err
			}
			if err != nil {
				return err
			}
			for _, it := range b.Items {
				fmt.Fprintln(d.Stdout, statusLine(it.Change, status, o.DryRun))
			}
			if n := len(b.Items); n > 1 {
				if o.DryRun {
					fmt.Fprintf(d.Stdout, "試し: %d 件を %s にします (ストアは変えていません)。\n", n, status)
				} else {
					fmt.Fprintf(d.Stdout, "%d 件を %s にしました。\n", n, status)
				}
			}
			return nil
		},
	}
	if status == store.FindingSnoozed {
		cmd.StringVar(&until, "until", "", "期日 (YYYY-MM-DD、その日の 0 時 UTC まで沈黙)")
		cmd.MarkFlagRequired("until")
	}
	cmd.StringVar(&o.Reason, "reason", "", "理由 (1 行、300 文字まで。ストアに残り、review と報告に出る。ARN・アカウント ID などは書かない)")
	if status == store.FindingAcked {
		cmd.BoolVar(&o.Force, "force", false, "片付けの表が ack を許さない finding (high・critical など) も ack する (--reason が必須。記録に force が残る。ADR 0068)")
	}
	cmd.BoolVar(&o.DryRun, "dry-run", false, "試し: 検査 (形・finding の有無・片付けの表・期日) だけ行い、ID ごとに何をどう変えるかを出す。ストアは書かない (ADR 0068)")
	cmd.StringVar(&o.By, "by", "", "操作した人 (英数字と . _ - のハンドル。省略時は OS のユーザー名。メールアドレスや氏名は書けない)")
	cmd.StringVar(&format, "format", "text", "出力形式 (text|json。json は ID ごとの結果。arata schema triage-result)")
	return cmd
}

// statusLine は 1 件の結果の行 (人向け)。
func statusLine(c *engine.StatusChange, status string, dryRun bool) string {
	f := c.Finding
	if dryRun {
		msg := fmt.Sprintf("試し: finding %s (%s、重大度 %s、%s) を %s から %s にします (ストアは変えていません)。", f.ID, f.Check, f.Severity, f.Summary, c.Before, f.Status)
		if status == store.FindingSnoozed {
			msg += fmt.Sprintf(" 期日 %s (UTC)。", f.SnoozeUntil.UTC().Format(record.DateLayout))
		}
		if c.Forced {
			msg += " 片付けの表が許さない ack を force で通します (記録に force が残ります)。"
		}
		return msg
	}
	msg := fmt.Sprintf("finding %s (%s) を %s にしました。", f.ID, f.Check, f.Status)
	if status == store.FindingSnoozed {
		msg += fmt.Sprintf(" %s (UTC) 以降の再観測で再報告します。", f.SnoozeUntil.UTC().Format(record.DateLayout))
	}
	return msg
}

// stoppedText は検査で止めたときの案内 (人向け。機械は --format json か、ログの code を読む)。
// 1 件だけで ack を止めたときは、今までと同じ案内 (AckRefusedError.Guidance) を出す。
func stoppedText(b *engine.StatusBatch, use string) string {
	if len(b.Items) == 1 && b.Items[0].Refused != nil {
		return b.Items[0].Refused.Guidance()
	}
	var sb strings.Builder
	if len(b.Items) > 1 {
		fmt.Fprintf(&sb, "%d 件のうち %d 件が通らないので、何も変えていません (ストアは書いていません)。止めた ID:\n", len(b.Items), b.Stopped)
	}
	refused, approvable := false, false
	for _, it := range b.Items {
		if it.Err == nil {
			continue
		}
		switch {
		case it.Refused != nil && it.Refused.NoReason:
			fmt.Fprintf(&sb, "  - %s (%s、重大度 %s): --force には --reason (なぜ黙らせてよいか、1 行) が要ります\n", it.ID, it.Refused.Check, it.Refused.Severity)
		case it.Refused != nil:
			refused = true
			approvable = approvable || it.Refused.Approvable
			fmt.Fprintf(&sb, "  - %s (%s、重大度 %s): 片付けの表が ack を許しません (arata help ai playbook %s の「片付け」)\n", it.ID, it.Refused.Check, it.Refused.Severity, it.Refused.Check)
		case it.Found == nil:
			fmt.Fprintf(&sb, "  - %s: 見つかりません (arata review で ID を確かめる)\n", it.ID)
		case it.Found.Status == store.FindingResolved:
			fmt.Fprintf(&sb, "  - %s (%s): 既に resolved です (%s から外す)\n", it.ID, it.Found.Check, use)
		default:
			fmt.Fprintf(&sb, "  - %s: %v\n", it.ID, it.Err)
		}
	}
	if refused {
		sb.WriteString("ack できない finding は、同じ指摘のまま重大度が上がる余地が無い (または最も重い側) ので、ack すると後で本物が起きても二度と報告されません。次のどれかを使ってください:\n")
		if approvable {
			sb.WriteString("  - approve: 正規の主体だと確かめた (arata approve <id> --note \"<理由>\"。Actions の運用では allowlist.yaml を PR で直す)\n")
		}
		sb.WriteString("  - snooze --until YYYY-MM-DD: 期日を決めて見直す (期日の後に再び観測されたら再報告される)\n")
		sb.WriteString("  - resolve: 直した (再び観測されたら新規として報告される)\n")
		sb.WriteString("根拠: arata help ai playbook <check> の「片付け」\n")
		sb.WriteString("終わった出来事だと確かめたうえでどうしても ack するなら、人が --force --reason \"<理由>\" を付けて実行します (記録に force が残り、週次の報告に出ます)。\n")
	}
	if len(b.Items) > 1 {
		sb.WriteString("止めた ID を外す (または直す) と、残りを 1 回で実行できます。\n")
	}
	return sb.String()
}

// lastActionCell は表の LAST_ACTION の欄 (`ack alice 2026-11-17`)。理由は json と報告に出す (表の幅を崩さない)。
// acked / snoozed なのに記録が無いのは、ストアの schema 8 より前の操作。
func lastActionCell(it engine.ReviewItem) string {
	a := it.LastAction
	if a == nil {
		if it.Status == store.FindingAcked || it.Status == store.FindingSnoozed {
			return "(記録なし)"
		}
		return "-"
	}
	cell := a.Action + " " + a.By + " " + a.At[:min(len(a.At), len(record.DateLayout))]
	if a.Forced {
		cell += " (force)"
	}
	return cell
}

func formatErr(format, want string) error {
	return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("unknown format %q (%s)", format, want)}
}

func reviewCommands(d *Deps, g *globalFlags) []*subcmd.Command {
	return []*subcmd.Command{
		newReviewCmd(d, g),
		newApproveCmd(d, g),
		newStatusCmd(d, g, "ack", store.FindingAcked, "finding を acked にする (再報告しないが review の未対応一覧には残る。high・critical は --force --reason が要る)"),
		newStatusCmd(d, g, "snooze", store.FindingSnoozed, "finding を期日まで沈黙させる (--until。期日以降の再観測で new として再報告)"),
		newStatusCmd(d, g, "resolve", store.FindingResolved, "finding を resolved にする (再び観測されたら new として報告)"),
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
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
			e, _, err := openEngine(d, g)
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
				fmt.Fprintln(tw, "ID\tSEVERITY\tSTATUS\tCHECK\tFIRST_SEEN\tAPPROVE\tSUMMARY")
				for _, it := range items {
					approve := "-"
					if it.Approve != nil {
						approve = it.Approve.Subject()
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", it.ID, it.Severity, it.Status, it.Check, it.FirstSeen, approve, it.Summary)
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
  - approved_by は --by、省略時は OS のユーザー名。approved_at は今日 (UTC)
  - git への commit は人が行う。--commit を付けると allowlist.yaml だけを commit する

LLM は approve を実行せず、人に提案するだけにすること (arata help ai approve)。`,
		Args: subcmd.ExactArgs(1),
		Run: func(ctx context.Context, args []string) error {
			e, cfg, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			res, err := e.Approve(ctx, args[0], o)
			if res != nil {
				fmt.Fprintf(d.Stdout, "%s に追記しました (%s):\n%s", cfg.Allowlist, res.Entry.Subject(), res.Added)
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
	cmd.StringArrayVar(&o.ExpectedDenied, "expected-denied", "access_denied の想定済みの拒否 (サービス:操作の glob。例 logs:StartQuery、logs:Get*。複数可)")
	return cmd
}

func newStatusCmd(d *Deps, g *globalFlags, use, status, short string) *subcmd.Command {
	var until string
	cmd := &subcmd.Command{
		Use:   use + " <finding-id>",
		Short: short,
		Args:  subcmd.ExactArgs(1),
		Run: func(ctx context.Context, args []string) error {
			var u time.Time
			if status == store.FindingSnoozed {
				t, err := time.Parse(record.DateLayout, until)
				if err != nil {
					d.Engine.Logger.Error("invalid --until", "code", engine.CodeConfigInvalid, "until", until)
					return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("--until %q: want YYYY-MM-DD", until)}
				}
				u = t
			}
			e, _, err := openEngine(d, g)
			if err != nil {
				return err
			}
			defer e.Close()
			f, err := e.SetStatus(ctx, args[0], status, u)
			if err != nil {
				return err
			}
			msg := fmt.Sprintf("finding %s (%s) を %s にしました。", f.ID, f.Check, f.Status)
			if status == store.FindingSnoozed {
				msg += fmt.Sprintf(" %s (UTC) 以降の再観測で再報告します。", f.SnoozeUntil.UTC().Format(record.DateLayout))
			}
			fmt.Fprintln(d.Stdout, msg)
			return nil
		},
	}
	if status == store.FindingSnoozed {
		cmd.StringVar(&until, "until", "", "期日 (YYYY-MM-DD、その日の 0 時 UTC まで沈黙)")
		cmd.MarkFlagRequired("until")
	}
	return cmd
}

func formatErr(format, want string) error {
	return &engine.ExitError{Code: engine.CodeConfigInvalid, Exit: engine.ExitConfig, Err: fmt.Errorf("unknown format %q (%s)", format, want)}
}

func reviewCommands(d *Deps, g *globalFlags) []*subcmd.Command {
	return []*subcmd.Command{
		newReviewCmd(d, g),
		newApproveCmd(d, g),
		newStatusCmd(d, g, "ack", store.FindingAcked, "finding を acked にする (再報告しないが review の未対応一覧には残る)"),
		newStatusCmd(d, g, "snooze", store.FindingSnoozed, "finding を期日まで沈黙させる (--until。期日以降の再観測で new として再報告)"),
		newStatusCmd(d, g, "resolve", store.FindingResolved, "finding を resolved にする (再び観測されたら new として報告)"),
	}
}

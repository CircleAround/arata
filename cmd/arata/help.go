package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/CircleAround/arata/docs/ai"
)

// rootLong はルートのヘルプ。「とりあえず叩けば何をすればよいか分かる」ように、人向けの手順と AI 向けの入口を最初に出す。
const rootLong = `arata は AWS のログと設定を定期的に改め、前回から新しく発生したもの (新規の主体・送信元・設定変更) を報せる監査エンジン。
収集・保存・差分判定・レポート生成 (report.json / report.md) までを行う。通知と要約は組み込み側の仕事。

はじめての手順:
  1. arata config init --out config.yaml                       推奨設定の雛形を書き出す (name / store / sources を編集する)
  2. arata doctor -c config.yaml                               権限・ロググループ・ログ形式の解釈率を確かめる
  3. arata init   -c config.yaml                               ベースラインを収集する (findings は出さない)
  4. arata run    -c config.yaml --profile daily --out out/    差分を判定し out/report.md と report.json を出す

実行されるのは設定の profiles に書いたチェックだけ (暗黙の既定は無い)。効いている中身は arata profiles -c config.yaml、
新しい版との差分は arata config init --diff -c config.yaml で確かめる。

AI (LLM) から使う場合は ` + "`arata help ai`" + ` を最初に読んでください (report の読み方は ` + "`arata help ai report`" + `、承認判断は ` + "`arata help ai approve`" + `)。`

// newAICmd は AI 向けの文書を出すトップレベルのコマンド。`arata help ai [topic]` も同じものを出す。
// 決定: cobra の help の下に置くとコマンド一覧に出ないので、トップレベルの ai として一覧に見せる。
func newAICmd(d *Deps) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:       "ai [report|approve]",
		Short:     "AI (LLM) 向けの使い方 (arata help ai と同じ。最初に読む)",
		Long:      "AI (LLM) 向けの使い方を出す。トピック: (なし) 全体像 / report report.json の読み方と要約の手順 / approve 承認判断の基準。\n--format json で {topic, title, sections: [{title, body}]} を返す。",
		Args:      cobra.MaximumNArgs(1),
		ValidArgs: []string{"report", "approve"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeAIDoc(d.Stdout, strings.Join(args, " "), format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "md", "出力形式 (md|json)")
	return cmd
}

func writeAIDoc(w io.Writer, sub, format string) error {
	t, err := ai.Lookup(sub)
	if err != nil {
		return err // Execute が CONFIG_INVALID としてログに出し、終了コード 2
	}
	switch format {
	case "md":
		_, err = io.WriteString(w, t.Markdown())
		return err
	case "json":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(t.Parse())
	}
	return fmt.Errorf("unknown format %q (md|json)", format)
}

// newHelpCmd は cobra の help を置き換え、`arata help ai [topic]` を ai コマンドに渡す。それ以外は通常の help。
func newHelpCmd(d *Deps, root *cobra.Command) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "help [command]",
		Short: "コマンドのヘルプ (arata help ai で AI 向けの使い方)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && args[0] == "ai" {
				if len(args) > 2 {
					return errors.New("usage: arata help ai [report|approve]")
				}
				return writeAIDoc(d.Stdout, strings.Join(args[1:], " "), format)
			}
			target, _, err := root.Find(args)
			if err != nil || target == nil {
				target = root
			}
			target.InitDefaultHelpFlag()
			return target.Help()
		},
	}
	cmd.Flags().StringVar(&format, "format", "md", "help ai の出力形式 (md|json)")
	return cmd
}

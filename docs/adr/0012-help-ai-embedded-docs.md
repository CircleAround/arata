# 0012. LLM 向けの使い方は skill として配らず、`arata help ai` としてバイナリに埋め込む

- 日付: 2026-10-21
- 状態: 採用 (設計書 4-1 / 9 章の「skills/aws-audit/SKILL.md を同梱」を置き換える)

## 背景

設計書 9 章は、LLM がレポートを要約する手順を `skills/aws-audit/SKILL.md` としてリポジトリに同梱し、組み込み側がそれを使う前提だった。
しかし arata は顧客環境 (オンプレの cron、Lambda) に単一バイナリとして配る (ADR 0002)。skill ファイルを別に配ると、

- バイナリの版と手順の版がずれる (新しい code やレポートの欄が手順に書かれていない、またはその逆)
- 顧客環境に skill を置く場所と仕組みが要る。LLM の実行環境 (claude -p、AgentConsole など) ごとに置き方が違う

## 決定

- LLM 向けの使い方は `docs/ai/*.md` に書き、`embed` でバイナリに入れる。トピックは 3 つ:
  - `arata help ai`: 全体像。概念 (二層判定、イベント型 / 状態型、recurred)、コマンドと終了コード、標準エラーの code と対処、allowlist.yaml の形式、認証の注意
  - `arata help ai report`: report.json の構造と読み方、要約の手順、相関付け、分類の基準、個人特定値を書かないこと、approve は提案のみ
  - `arata help ai approve`: 承認判断の基準 (SaaS 連携は account、期限付き承認、tags の語彙、外部アカウント root の見方)
- `--format json` で `{topic, title, sections: [{title, body}]}` を返す (見出し `##` 単位)。各トピックの見出しはテストで固定する
- help の下だけに置くとコマンド一覧に出ないので、同じ内容をトップレベルの `arata ai` としても出し、`arata help ai ...` はそこへ振り分ける
- 引数なしの `arata` (ルートのヘルプ) は、人向けの 3 行手順 (doctor → init → run) と「AI から使う場合は `arata help ai` を最初に読む」を最初に出す
- 固定語彙の code が `arata help ai` に全部書かれていることをテストで保証する (code を足したら文書も直す)

## 検討した選択肢

- skill ファイルを同梱し、install コマンドで所定の場所に書き出す: LLM の実行環境ごとに置き場所が違い、書き出した後の版のずれも残る。却下
- README に AI 向けの節を書く: 顧客環境にはバイナリしか無い。却下
- `--help` の Long に全部書く: 人向けのヘルプが長くなり、トピック別に引けない。却下

## 結果

- 組み込み側のプロンプトは「最初に `arata help ai` を読み、レポートは `arata help ai report` に従って要約する」だけで済む
- 手順を変えるにはバイナリのリリースが要る (版が揃う代わりに、手順だけ先に直すことはできない)
- 1 トピック 150 行以内を目安に保つ (テストで行数を確かめる)

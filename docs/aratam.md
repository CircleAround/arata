# aratam 設計書

作成: 2026-10-21

`aratam` は arata の出力 (`report.json` / `report.md`) を読み、LLM で要約して通知するコマンド。
arata 設計書 9-1 章 (「report.json から通知までの LLM の仕事」) で組み込み側に任せた仕事を、毎回作らずに済むよう標準品にしたもの。
判断の経緯は ADR 0018。

## 1. 決定事項

| 項目 | 決定 |
|---|---|
| arata との関係 | **出力リソースを介してだけ連携する**。aratam は arata を呼ばず、arata のパス・AWS の監査ロール・ストアを知らない。組み合わせは cron / シェル側で行う |
| 配置 | 同じリポジトリの `cmd/aratam`。リリースには arata と aratam のバイナリを並べる。report.json の形と `docs/ai` の版が arata とずれない |
| 権限 | arata は AWS の読み取りロールだけ、aratam は LLM と通知の鍵だけを持つ。別の OS ユーザーで動かしてもよい |
| LLM | `bedrock` と `claude-cli` (`claude -p`) に対応する。将来 `openai-api`。`none` (LLM を使わず report.md を整形して送る) も選べる |
| 通知先 | Slack Incoming Webhook。通常用と緊急用の 2 本まで。SNS などは後続 |
| 書式 | Block Kit (`slack.format: blocks`。3-4 章、ADR 0029)。`text` で v0.3.0 までの mrkdwn の本文も選べる |
| 依存 | 標準の `net/http` で書く。例外は Bedrock で、AWS SDK (`service/bedrockruntime`) を使ってよい (arata が AWS SDK の core を既に持つため増分が小さい) |
| 状態 | 持たない。二重送信の防止だけ、入力ディレクトリに `.aratam-notified` (通知済みの run_id) を書く。ほかに書くのは WAF の提案の全文 `waf-proposals.md` だけ (3-4 章) |
| 判定 | LLM に判定させない。重大度の下限・必ず載せる finding・失敗時のフォールバックは aratam の規則で固定する (2 章) |

## 2. 処理の流れ

```
arata run -c config.yaml --profile daily --out /var/lib/arata/out/daily
aratam notify --in /var/lib/arata/out/daily
```

`aratam notify` は次の順で動く。

1. **入力の検査** (LLM を使わない)
   - `report.json` が無い、読めない、`generated_at` が `max_age` より古い → 「arata が実行されていない / 失敗した」と緊急用に直接送って終了 (終了コード 4)。
     cron 側で `arata run ... ; aratam notify ...` とつなげば、arata が出力すら書けなかった場合もここで拾える。
     S3 ストアの `STORE_CONFLICT` もこの経路で人に届く (arata は確定していない結果を出さない)。毎回消える環境では `report.json` が無いので直ちに緊急用に送る。
     `--out` が残る環境では前回の `report.json` が `max_age` を超えたときに送る (それまでは同じ `run_id` なので送らない)。
   - `.aratam-notified` に同じ `run_id` がある → 送らずに終了 (`--force` で再送)。
2. **規則による振り分け** (LLM を使わない)
   - 送り先: `summary.max_severity` が `urgent_severity` (既定 high) 以上、または `coverage.sources_failed` がある → 緊急用。それ以外 → 通常用。
   - 新規・変化・再発が 0 件で、取れなかったものも無い → `on_quiet` に従う (`short` = 「新規なし」と 1 行、`silent` = 送らない)。
3. **LLM による要約** (`llm.provider` が `none` 以外のとき)
   - 入力は `report.json` だけ。system には `docs/ai/report.md` (arata が `arata help ai report` で出すのと同じ文書) を埋め込んで渡す。
   - system には、その run に出たチェックの対処手順 (playbook。3-3 章) も入れる。
   - 出力は決まった JSON (3 章) に限る。形が合わない、時間切れ、エラー → 4 へ。
4. **組み立てと検証** (LLM を使わない)
   - LLM が返した分類と説明を、aratam が決まった書式で Slack のメッセージに組み立てる (`slack.format: blocks` のときは 3-4 章の構成と契約)。
   - new / changed / recurred の finding が LLM の出力から漏れていたら、規則で組み立てた行として末尾に足す (LLM が finding を消す経路を作らない)。
   - LLM が使えなかったときは report.md を送る (Slack の上限に合わせて切り詰め、出力ディレクトリのパスを添える)。冒頭に「要約に失敗したため原文を送ります」と書く。
5. **送信** → 成功したら `.aratam-notified` に run_id を書く。
6. **WAF の改善提案** (report.json に `proposals` があるとき。3-2 章) → 2 通目として常に通常用に送る。LLM を使うときは候補だけを渡して書き起こさせる。

期間レポート (`"kind": "period"`) も同じ流れで扱う。違いは 3 の system 文書と、2 の振り分け (期間レポートは常に通常用) だけ。

決定 (実装順 1):
- 入力: `report.json` が JSON として読めない・`generated_at` が無いか RFC 3339 でない・知らない `kind` も「失敗した」とみなす。
  ログと通知の code は `INPUT_MISSING` (無い・読めない) / `INPUT_INVALID` (解釈できない) / `INPUT_STALE` (古い)。未知のフィールドは無視する (arata が足したフィールドで止まらないように)。
- 入力: 期間レポートの `report.md` が無ければ `report.json` から arata と同じ関数 (`internal/report/schema` の `Markdown`) で作る。
- 入力: 設定の `name` と report.json の `name` が違えば、標準エラーに `NAME_MISMATCH` を出し、通知の冒頭にも警告の行を足す (別の監査対象の出力を送っている取り違えに気付けるように)。
- 二重送信の防止: `.aratam-notified` の中身は直近の 1 件の識別子だけ (入力ディレクトリは監査対象・プロファイルごとに分かれ、arata が毎回上書きするため)。
  識別子は run の `run_id`。期間レポートは run_id を持たないので `period:<from>/<to>@<generated_at>` にする (作り直したら別の報告として送る)。
  入力の問題 (終了コード 4) は記録しない (次の cron でもう一度知らせる)。`on_quiet: silent` で送らなかったときは記録する。
- 二重送信の防止: `.aratam-notified` を書けなくても送信は済んでいるので終了コードは変えず、`MARK_FAILED` の警告だけ出す (次回は同じ報告を再送する)。
- `--dry-run` は `.aratam-notified` を見る (通知済みなら送らない旨をログに出す。中身を見たいときは `--force`) が、書かない。Webhook の環境変数も要らない。
- 期間レポートは件数が 0 でも「静か」とみなさず送る (月次などの定期の報告は、何も無かったことも伝える)。
- メッセージ: Slack の mrkdwn の本文だけで送る (8 章の未決は「まずは本文だけ」で進める)。
  → 決定 (ADR 0029): Block Kit にした (3-4 章)。ここから下のメッセージの決定は `slack.format: text` のときのもの。
- メッセージ (`none` と LLM が使えなかったときの原文): run は report.md をそのまま送らず、report.json から短い形を作る。
  finding 1 件は「重大度・概要・チェック名」の行と「チェックごとの主要キー · id (初出)」の行の 2 行にする
  (report.md は data の全キーを列挙するので 1 件が 10 行を超え、Slack では読めない)。主要キーの対応表は `internal/notify/compact.go` の `keyFields`
  (例: unknown_assume_role = caller・count・ips・last_time、new_principal = kind・count・ips・external_account、login_bruteforce = ip・count・date・reason・threshold)。
  対応表に無いチェックは count と ips だけ。summary の文に既に入っている値は繰り返さない (文字列は部分一致、数値は「N 件」「N 回」の形で見る)。リストは 3 個まで。
  件数 0 の区分は出さない。カバレッジは問題 (取れなかったソース・解釈率の code・スキップしたチェック) があるときだけ出す。末尾に `全文: <dir>/report.md` を添える。
  期間レポートは report.md から件数 0 の節 (`## 見出し (0)`) を除き、見出しを `*見出し*`、`**太字**` を `*太字*` に置き換えて送る。
  決定 (ADR 0041): このとき行ごとに目に見えない文字を除く (report.md の summary はログ由来で、この経路だけ下の規則が掛かっていなかった)。
- メッセージ: report 由来の文字列は `&` `<` `>` をエスケープする。ログ由来の値 (User-Agent など) が `<!channel>` やリンクとして働かないようにするため。メンションは設定に書いたものだけを付ける。
- メッセージ (ADR 0037): ログ由来の値は 1 行にし、制御文字・向きの制御・ゼロ幅の文字を除いてから埋め込む。mrkdwn には `verbatim: true` を付け、`unfurl_links` / `unfurl_media` を false で送る (Slack に URL・チャンネル名・メンションを自動で解釈させず、ログの URL を取りに行かせない)。
  このため `slack.urgent_mention` は `<!channel>` や `<@U012AB3CD>` の形で書く (`@channel` の文字列は働かない)。
- メッセージ: 1 通は 3,800 文字までに切り詰める (Slack は text を 4,000 文字程度までにするよう求めている)。
  決定 (ADR 0041): 静かな通知 (on_quiet: short) と入力の問題の通知も同じ上限で切る。入力の問題の理由 (report.json の `kind`・`generated_at` が入る) は 500 字まで、
  Block Kit の通知用の text は 300 字まで。
  文字数は Unicode のコードポイント数 (Go の rune 数) で数え、バイト数では数えない (Slack の上限も文字数)。理由文などの上限を含め、切り詰めはすべて文字単位で行う。行の境目で切り、`…(長いため省略)` と report.md のパスを添える。
- 入力 (ADR 0023): arata の weekly の report.json に `proposals` (WAF の修正提案の候補と observation) が足された。
  本文の通知は変えず (要約の入力の report.json には含まれる)、「WAF の改善提案」を 2 通目として送る (3-2 章、ADR 0024)
- 送信: 再送はしない (Slack が受け取ったのに応答が届かなかった場合の二重送信を避ける。失敗は終了コード 5 で cron 側に任せる)。
  `net/http` のエラーは URL を含むので、中身だけを取り出してから返す (Webhook の URL をログに出さない)。

## 3. LLM との契約

LLM に求める出力:

```json
{
  "headline": "1 行の要約",
  "items": [
    {"finding_id": "...", "class": "action | confirm | info", "reason": "根拠付きの説明"}
  ],
  "incidents": [
    {"finding_ids": ["...", "..."], "summary": "同じ主体・同じ時間帯の finding をまとめた見立て"}
  ],
  "approve_suggestions": [
    {"finding_id": "...", "reason": "正当と思われる理由"}
  ]
}
```

- `class` は arata 設計書 9-1 の「要対処 / 確認依頼 / 情報」。**重大度は変えさせない**。表示する重大度は report.json の値を使う。
- `finding_id` が report.json に無いものは捨てる (LLM が作った ID を表示しない)。
- `approve_suggestions` は提案として表示するだけ。aratam は approve を実行しない。表示には `arata approve <id> --note "..."` の形を添える。
- 個人を特定できる値を書かないよう system で指示する。入力の report.json もその前提で作られている。
- 決定 (ADR 0037): 入力の値はログ由来で攻撃者が書ける。LLM が攻撃者の文に従っても次が残るよう、規則で検査する (プロンプトの指示は破られる前提)。
  - new / changed / recurred で `urgent_severity` 以上の finding は `info` にさせない (`confirm` に上げ、LLM の理由を捨てる)。切り詰めるときはこれらを先頭に回す。
  - `urgent_severity` 以上の finding への `approve_suggestions` は捨てる。
  - 自由文 (`headline`・`reason`・`incidents` の `summary`・blocks の `summary` と `next`・提案の書き起こし) に URL、`@channel` / `@here` / `@everyone`、BLOCK に強める記述があれば項目を捨てて規則の行に戻す。`headline` と blocks の `summary` なら形の不正 (再試行し、だめなら LLM の失敗と同じ扱い)。捨てたら `LLM_OUTPUT_REJECTED` の WARN (理由だけ。文の中身はログに写さない)。
  - LLM の文が載る通知は、既存の末尾の行に「要約と → は LLM による (ログの文字列に影響され得る)」を添える。`provider: none` と LLM の失敗では出さない。

### 3-1. プロバイダ

| provider | 呼び方 | 認証 |
|---|---|---|
| `bedrock` | `bedrockruntime` の Converse API。`model` (推論プロファイル ID) と `region` は設定で明示する | AWS SDK の標準認証チェーン (`profile` 指定可)。必要なのは `bedrock:InvokeModel` だけ |
| `claude-cli` | `claude -p --output-format json` を子プロセスで起動し、プロンプトを標準入力で渡す。ツールは使わせない設定にし、作業ディレクトリは空の一時ディレクトリにする。決定: `--setting-sources project` で設定は project だけを読む (空のディレクトリなので project 設定は無く、ユーザー設定の hooks・権限設定・プラグインを読ませない。`--bare` は OAuth のログイン状態を読まなくなるので使わない)。決定: system は引数でなく `--system-prompt-file` で渡す (引数は ps で見える)。作業ディレクトリは `/tmp` でなく利用者のキャッシュ (`~/.cache/aratam`) の下に作り、`CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` で親の CLAUDE.md を読ませない。子プロセスの環境変数は動くのに要るものだけを許可リストで渡す (AWS の認証情報やトークンは渡さない。claude を Bedrock で使う設定も渡らないので、Bedrock は `provider: bedrock` を使う) | `claude` 側のログイン状態 |
| `openai-api` (後続) | Chat Completions を `net/http` で呼ぶ | 環境変数の API キー |
| `none` | LLM を呼ばない | - |

- 共通: `timeout` (既定 120s)。失敗時の再試行は 1 回まで。
- インターフェースは `Summarize(ctx, system, reportJSON) (raw []byte, err error)` の 1 つ。JSON の検証と組み立ては共通部分で行い、プロバイダごとに書かない。

決定 (実装順 2〜3):
- 再試行: エラー・時間切れに加え、形が合わない出力も 1 回だけ再試行する (2 回目は契約どおりに返すことが多いため)。`timeout` は 1 回ごとにかける。
  再試行は `LLM_RETRY`、最終的な失敗は `LLM_FAILED` (標準エラー) で、原文を送って終了コード 3。
- 出力の検証: 前後の文やコードフェンスが付いていたら最初の `{` から最後の `}` までを取り出す。`headline` が空なら形が不正。
  report.json に無い `finding_id`、`class` が action / confirm / info 以外の item、同じ `finding_id` の 2 件目以降は捨てる
  (捨てた finding が new / changed / recurred なら「要約に含まれていなかった指摘 (規則で追加)」として末尾に足される)。
  incidents は知らない ID を除き、ID が残らなければ捨てる。approve_suggestions も知らない ID のものを捨てる。
  決定 (ADR 0041): LLM が任意に増やせる節で本文を埋めさせない。incidents は 10 件まで (1 件の中の同じ ID は 1 つにする)、
  approve_suggestions は finding 1 件につき 1 つ (2 件目以降は捨てる)。
  知っている ID なら still_open などを分類してもよい (表示は report.json の区分を添える)。
- 組み立て: 1 行目の名前と期間、件数の行、取れなかったソース (期間レポートは取れなかった run)、漏れた finding は report.json から規則で書き、
  LLM の文字列は headline・reason・incidents・approve の理由だけ。どれもエスケープし、改行は空白にする (書式を崩させない)。
  LLM の文字列は組み立て側でも上限で切る (reason・approve の理由は 200 字、incidents の summary は 240 字、末尾に …)。
  system でも reason は 1〜2 文 (120 字程度)、incidents は 200 字程度とし、重大度や `data.xxx=` の値を繰り返させない (aratam が別に表示するため)。
- 切り詰め: 3,800 文字に収まらなければ優先度で削る。情報の理由文 → 情報の行 (「*情報* N 件 (長いため省略)」だけ残す) → 確認依頼の理由文 の順。
  見出し・要対処・インシデント候補・承認の提案・漏れた finding・取れなかったものは削らない。
  決定 (ADR 0041。以前は「分類の部分を末尾から切り、インシデント候補と承認の提案は必ず残す」): それでも収まらなければ、
  漏れた finding のうち urgent 以上 → 取れなかったもの → 分類 (urgent 以上を要対処の先頭に。ADR 0037) → 残りの漏れた finding の順に並べ直して、
  後ろから行の境目で切る。インシデント候補と承認の提案は、合わせて 800 字までなら必ず残し、超えるなら最後に回して切る
  (LLM が増やせる節を長さに依らず残すと、緊急の finding の行が押し出され、本文も上限を超えた)。全文の案内と LLM の注記は必ず残す。
  どの入力でも 1 通は 3,800 文字を超えない (見出しと末尾だけで超えるときは全体を行の境目で切る)。
- 期間レポート: system の文書は足さない。`docs/ai/report.md` の「期間レポート」の節で足りるため (8 章の未決を閉じる)。
  必ず載せる finding は events の new / changed / recurred。
- system: 出力の契約 (3 章)、「追加の照会はできない。report.json だけで判断する」、続けて `docs/ai/report.md`、その run のチェックの対処手順 (3-3 章)、利用者の前提を埋め込む。
- `claude-cli`: `claude -p --output-format json --tools "" --strict-mcp-config --no-session-persistence --setting-sources project --system-prompt <system> [--model <model>]`。
  ツールも MCP サーバーも使わせず、セッションをディスクに残さない。作業ディレクトリは空の一時ディレクトリ (終わったら消す)。
  子プロセスの環境変数は aratam のものから Webhook の環境変数 (`slack.webhook_env` / `urgent_webhook_env`) を除いて渡す。
  `--output-format json` の `is_error` が真なら失敗。実行ファイルは `llm.command` (空なら PATH の `claude`。cron の PATH が狭い場合に絶対パスで書く)。
- `bedrock`: SDK の自動再試行は切る (RetryMaxAttempts 1。再試行は共通部分で 1 回までと決めているため重ねない)。maxTokens 4096。
  決定: `temperature` は送らない (モデルの既定に任せる)。以前は 0 を送っていたが、新しいモデル (例: Claude Haiku 5.5) は Converse の `temperature` を「廃止」として ValidationException で拒否し、要約が毎回失敗して原文の送信になった (2026-11-09、実際の Bedrock で確認)。aratam は判定を LLM に任せず、出力は規則で検証するので、ばらつきは通知の振り分けに影響しない
  stopReason が max_tokens なら失敗 (途中で切れた JSON を検証に回さない)。

### 3-2. WAF の改善提案 (proposals)

経緯は ADR 0024。

- 送り方: 本文とは別の 2 通目として、**常に通常用の Webhook** に送る (proposals だけでは緊急にしない。本文が緊急用でも提案は通常用)。
  `on_quiet: short` なら静かな 1 行の後に、`silent` なら 2 通目だけを送る。proposals が無い (waf_review が走らない) run では送らない。
  2 通目の送信に失敗したら終了コード 5。1 通目を送れていれば `.aratam-notified` は書く (本文を二重に送らない)。2 通目だけの run で失敗したら書かない
- 書式 (`internal/notify/proposals.go`):

  ```
  *WAF の改善提案* arata weekly (acme) <期間>
  提案 N 件 / 観察 M 件 (arata が規則で作った候補。適用するかは人が判断する。aratam は WAF の設定を変えない)

  • *[false_positive / まず COUNT で様子を見る]* <summary>
      根拠: count 250 · distinct_ips_max_per_day 60 · days 7 · matching_days 7
      何を: … / なぜ: … / 進め方: …   (LLM のときだけ)
      設定例: (コードブロック。LLM のときだけ)

  *観察* (提案はしないが気づいたこと)
  • [false_positive / excluded_by_config] <summary>

  *COUNT のルールの状況* (提案ではない。COUNT → BLOCK の切り替えは人が計画して決める)
  • <summary>
  ```

  - 提案 (kind が observation 以外) → observation → count_rule_status の順。observation は合わせて 10 行までで、残りは「ほか N 件は report.json」
  - 段階は `count_first` = 「まず COUNT で様子を見る」、`review` = 「見直す」。根拠の行は kind ごとの evidence の主なキー (対応表に無い kind は全キー)。リストは 3 個まで
  - 決定: **数字は規則の行に必ず出す**。種類・段階・概要・根拠は report.json の値で、エスケープする。LLM の文字列は何を・なぜ・進め方・設定例だけ
  - 3,800 文字を超えたら、設定例 → LLM の文 の順に削り、それでも収まらなければ末尾 (observation の側) から行の境目で切る
  - 決定 (ADR 0041): 設定例は複数行のまま載せるので、検査 (Block の action・コードフェンス) の前に目に見えない文字 (制御文字・向きの制御・ゼロ幅) を除く。
    改行とタブは残す。除かないと `"Bl<ゼロ幅>ock":` のような書き方が検査を通り、Slack と waf-proposals.md にそのまま出る
- LLM (`claude-cli` / `bedrock`): 要約とは別の 1 回の呼び出し (再試行は 1 回まで。`timeout` も同じ)。
  - 入力は提案の候補だけの JSON 配列 (id `p1`.. を振り、kind・stage・web_acl・scope・rule・rule_in_group・method・path・summary・evidence)。
    決定: **observation は LLM に渡さない** (規則の書式だけで出すので、提案への格上げが構造上起きない)。提案が 0 件なら呼ばない
  - system: 出力の契約 `{"proposals": [{"id", "what", "why", "how", "example"}]}`、縛り (候補に無い提案を作らない・BLOCK に強めない・設定例の action は Count か変更点だけ・
    数字を作らない・unused_rule は削除を勧めない)、`docs/ai/report.md` の「WAF の修正提案の候補」の節、`context_file` (あれば)
  - 検査: 前後の文・コードフェンスは要約と同じく取り除く。`proposals` が無ければ形が不正。知らない id・重複は捨てる (漏れた候補は規則の行だけ)。
    BLOCK に強める記述 (設定例の `"Block":` / CDK の `block:`、文中の「BLOCK に切り替える」など) を含む項目は捨てる。``` を含む設定例は例だけ捨てる。
    捨てたものは `LLM_PROPOSAL_REJECTED` の WARN。文字数は各文 200 字、設定例 800 字・20 行まで。文中の数字が evidence にあるかは検査しない
  - 縮退: 書き起こしだけが失敗したら、候補を規則の書式で載せて節の冒頭に「(提案の書き起こしに失敗したため、候補をそのまま載せます)」と書き、
    `LLM_PROPOSALS_FAILED` の WARN を出す。終了コードは変えない。本文の要約が失敗したら書き起こしは呼ばない (終了コード 3 のまま)
- 生の値: LLM にも Slack にも report.json の proposals の値だけを使う (ヘッダー・クエリ・Cookie は report.json にも無い)

### 3-3. 対処手順 (playbook)

経緯は ADR 0025 (「aratam の system への埋め込み」はその延長。新しい ADR は立てない)。目的は、LLM が決まった手順に沿って、利用者の事情 (`context_file`) を踏まえた具体的な助言を書けるようにすること。

- 何を入れるか: `docs/ai/playbooks/<check>.md` (`ai.Playbook(check)`) を、LLM の system に `<playbook check="...">` で区切って入れる。
  - 要約: その run の report.json の **new / changed / recurred** の finding のチェックだけ (LLM が分類・説明を書く finding と同じ範囲)。同じチェックは 1 回。
    決定: 解消・未対応 (still_open)・報告済み・情報だけのチェックは入れない (items に必ず入れるものではなく、助言を求めないため)。期間レポートも期間の new / changed / recurred。
  - 提案の書き起こし (2 回目の呼び出し。3-2 章): `waf_review` の playbook を同じ形で入れる。
  - `provider: none` は LLM を呼ばないので使わない。playbook の無いチェックは黙って飛ばす。
- 並びと上限: チェックごとの最大の重大度が高い順 (同じなら出現順)。**合計 24 KiB まで**。超えたら高い順に入れ、入らないものは落とす
  (後ろにもっと小さい playbook があれば入れる)。**1 つの playbook を途中で切らない** (途中で切った手順は誤解を招く)。
  落としたチェック名は WARN `PLAYBOOKS_OMITTED` (`omitted` にカンマ区切り)。要約は続ける。区切りや見出しの分は上限に数えない。
- 位置づけ (system に書く): 対処手順 (arata の汎用の手順) → 利用者の前提 (`context_file`) の順に参考にする。食い違うときは前提を優先して書き添える。
  重大度・分類・振り分け・規則より優先しない。「まず確かめること」は LLM には確かめられないので「人が確かめること」として書く。
  封じ込め・設定の変更・approve / ack / snooze / resolve は**人への提案にとどめ、LLM は実行しない**。
- system の並び: 出力の契約 → `docs/ai/report.md` → 対処手順 → 利用者の前提。
- 振り分け・重大度・finding 欠落の補完・LLM 失敗時の原文送信は、playbook の有無に関わらず規則のまま (2 章)。

### 3-4. Block Kit (slack.format: blocks)

経緯は ADR 0029。組み立ては `internal/notify/blocks.go`、型と上限は `message.go`。

- 構成:

  ```
  [メンション・注記・警告]                 (section。緊急用を通常用に送るとき・NAME_MISMATCH・LLM の失敗)
  🚨 arata daily — acme                    (header。絵文字は最大重大度: critical 🚨 / high 🔴 / medium 🟠 / low 🟡 / info ⚪)
  *期間* … | *新規* 🚨 critical 1 ・ 🟠 medium 2 | 変化 1 件 ・ 再発 1 件 | 解消 1 件 ・ 未対応 0 件 | 本日報告済み N 件 | 情報 N 件 (件数のみ)
                                           (fields。1 つの欄に 1 行で書き、ラベルと値を 2 段に分けない。0 件の変化・再発、報告済み、情報は出さない)
  要約 1〜2 文                             (LLM。none は規則)
  ⚠️ 取れていないもの                       (取れなかったソース・解釈率の警告・スキップ。期間レポートは取れなかった run)
  ── まず対応                               (new / changed / recurred のうち urgent_severity 以上。1 件ずつ)
  🚨 *<summary>* (再発)
  → <何をするか>
  ── 確認推奨                           (それ未満。同じチェックは 1 項目)
  🟠 *MFA の無いコンソールユーザー* 5 人
  `alice` `bob` …
  全文と対処手順: `arata review` ・ `arata help ai playbook <check>` | WAF の改善提案は別のメッセージ | <dir>/report.md   (context)
  ```

- 通知用の text (プッシュ通知・検索): `arata daily (acme): 新規 3 件、最大 critical`。メンションは blocks の先頭の section に書く
- まとめ方 (規則): (チェック、または チェック/key の種類 = key の最初の `|` より前) ごとの対応表 `groupRules`。
  見出し・単位・並べる値を決める (例: `credential_hygiene/no_mfa` = 「MFA の無いコンソールユーザー N 人」+ user、`credential_hygiene/unused_key` = 「使われていないアクセスキー N 本」+ user と days_unused、
  `new_principal`・`principal_new_source`・`secret_access`・`access_denied` = ARN の末尾 (外部アカウントは ID を添える)、`login_bruteforce`・`probe_paths` = IP と回数)。
  - 決定: 並べる値は IAM ユーザー名・ARN の末尾・IP・ルール名まで (個人を特定できる値を出さない)。10 個まで (ほか N)。期間レポートの events は data を持たないので key から取る
  - 決定: 対応表に無いチェック (guardduty_findings・iam_changes など、1 件ごとに中身が違うもの) と、1 件だけのグループは summary で 1 件ずつ。項目の並びは重大度の高い順
  - 変化・再発は名前や見出しの後に `(変化)` `(再発)` を付ける
  - `endpoint_abuse` (ADR 0030): 画面の集中 (key = 画面名) は「*画面への分散した集中* — `signup` 25 IP / 10 分」、「A のあと B」(key = `from>to`) は「*「A のあと B」の連鎖*」に分けてまとめる。
    summary が長いので 1 件でもこの形にし、確認推奨でも playbook どおりの「→ その時間幅の登録・送信をアプリの運営者が確認し、保留・承認待ちの運用へ回す (遮断はしない)」を添える
- 「→」(規則): playbook の「対処の選択肢」の先頭の項目を、太字・コマンドを含む括弧・末尾の補足の括弧を除き、最初の文まで (80 字まで)。
  決定: 条件の括弧 (「封じ込め (侵害の疑い)」) は残す (条件を落とすと過剰な対処を勧めることになる)。playbook が無ければ「`arata review` で詳細を確認する」
- 要約 (規則。provider: none と LLM の失敗時): 「まず対応 N 件 (最も重いのは「…」)、確認推奨 M 件。」/「確認推奨 M 件。high 以上の指摘はありません。」/「新規・変化・再発の指摘はありません。」
- LLM の契約 (blocks):

  ```json
  {"summary": "全体の要約 1〜2 文", "next": [{"finding_id": "「まず対応」の id", "action": "人が次にすること 1 文"}]}
  ```

  - system: 出力の契約、「まず対応」の finding (id・チェック・重大度・summary を規則で列挙)、縛り (重大度を変えない・実行しない・個人を特定できる値を書かない・report.json だけで判断する)、
    続けて `docs/ai/report.md`、対処手順 (3-3 章)、利用者の前提。入力は report.json だけ (text と同じ)
  - 検査: 前後の文・コードフェンスは取り除く。summary が空なら形が不正 (1 回だけ再試行)。知らない ID・「まず対応」以外の ID・重複・空の action は捨て、規則の「→」で補う。
    summary は 200 字、action は 80 字で切る。どれもエスケープし、改行は空白にする
  - 縮退: 失敗したら規則だけの Block Kit を送り、先頭に「要約に失敗したため規則で組み立てました」。終了コード 3。提案の書き起こしは呼ばない (2 章と同じ)
- 上限 (Slack): blocks 50 個、section の text 3,000 字、header 150 字、fields 10 個・各 2,000 字、context の要素 2,000 字。
  決定: 入らない項目は後ろから「ほか N 件は `arata review` で確認してください」に縮める (「まず対応」を優先して残す。件数は落とさない)。長い文字列は行の境目で切って … を付ける
- WAF の改善提案 (2 通目。`internal/notify/proposals_blocks.go`): 俯瞰できる短い形にし、全文は別のファイルに書き出す。

  ```
  🛡️ WAF の改善提案 — acme                                  (header)
  10/20 09:00 〜 10/21 09:00 (UTC) ・ 提案 5 件 ・ 観察 3 件 | arata の規則による候補…   (context)
  ──
  🛡️ *探索パスが WAF を通過* — 14 件 / 7 日・2 パス           (section 1 行目: 種類の日本語 + 主な数字)
  設定ファイルや管理画面を探す通信が WAF を素通りしている (7 日で 14 件)   (section 2 行目: なぜ困るか。規則の固定文 + 数字)
  → WebACL `prod-waf` に、`/.env`・`/.git/config` を URI で照合するルールを COUNT で追加し、1〜2 週間、正規の通信が一致しないかを見る
                                                              (section 3 行目: 次の一手。140 字まで)
  /.env 13・/.git/config 1                                    (context: 根拠 1 行)
  ──
  *観察* / *COUNT のルール*                                    (1 ルール 1 行。「`名前` 140 件・怪しい 100%・7/7 日」、一致なしは「一致なし: `a` `b`」の 1 行)
  設定例と詳しい説明: `<dir>/waf-proposals.md` | 対処手順: `arata help ai playbook waf_review`   (context)
  ```

  - 決定 (試験チャンネルで「文章が長く俯瞰しにくい」という意見を受けて): 規則の長い summary、LLM の何を・なぜ・進め方・設定例は Slack に出さない (report.json / report.md と waf-proposals.md にある)
  - 主な数字と根拠は種類ごとの規則 (`proposalNumbers`)。「→」は LLM の `next` (書き起こしの契約に足した 1 行。BLOCK に強める記述の検査は他の項目と同じで、捨てたら項目ごと規則に戻る)、
    無ければ規則 (`ruleNext`。種類ごとのテンプレートに WebACL 名・ルール名・上位のパス・limit などの evidence の値を埋め込む)
  - 決定 (試験チャンネルで「→ 探索パスのルールを COUNT で追加して様子を見る」は具体性がないという意見を受けて): 「→」には必ず
    どこに (WebACL 名・ルール名)・何を (対象のパス・条件の種類 (URI の照合・scope-down など))・どうする (COUNT で追加して何日・何を見る / 対象から外す など) を書く。
    上限は 140 字 (80 字では抜け落ちた)。LLM の system でも「様子を見る・検討する だけで終わる抽象的な言い回しを避け、具体的な対象と確認方法を書く」と求め、例を示す
  - なぜ困るか (`proposalWhy`): 種類ごとの固定文 + 数字 (例: challenge_on_app_path =「正規の画面で多くの人が Challenge を解かされている (解かれた 80%)」)。1 件は見出し / なぜ / → / 根拠 の 4 行まで
  - **`waf-proposals.md` の書き出し (notify の副作用)**: slack.format: blocks で提案があるとき、入力ディレクトリ (`--in`) に書く (一時ファイルから置き換え、0640)。
    提案ごとの種類・対象・概要・根拠・次の一手・何を・なぜ・進め方・設定例の全文と、観察・COUNT のルールの状況。`--dry-run` では書かない (パスは出す)。
    書けなければ WARN `PROPOSALS_FILE_FAILED` を出し、context は report.md を案内する (通知は続ける。終了コードは変えない)
  - 提案が入らなければ「ほか N 件の提案は waf-proposals.md」。観察・Challenge / CAPTCHA の状況・COUNT のルールは合わせて 10 行まで
  - ADR 0028 の種類: `challenge_on_app_path` = 「正規の画面に Challenge / CAPTCHA — `ルール` が GET /x で Challenge 160 件 / 7 日・解かれた 80%」、
    「→ このパスを `ルール` の対象から外す (scope-down) か条件を絞る」(BLOCK に変えることは勧めない)。
    `challenge_impact` (observation) は「*Challenge / CAPTCHA*」の節に 1 ルール 1 行 (「`ルール` Challenge 900 件・解かれた 5%・GET 以外 40」。割合は解釈しない)
- 静か (`on_quiet: short`): header `✅ arata <profile> — <name>` と 1 行。入力の問題: header `⚠️ arata の出力が無いか古い — <name>`、理由・code・入力のパス
- `--dry-run`: `--format text` (既定) は人が読む簡易表示 (`[通知] <text>`、header は `# `、divider は `---`、context は `(小) `、fields は ` | ` でつなぐ)。
  `--format json` は Webhook に送る payload そのもの。`--format` は `--dry-run` のときだけ指定できる

## 4. 設定

arata と同じく暗黙の既定を持たない。`aratam config init` で全項目を明示した雛形を出す。

```yaml
name: example                     # 通知に出す監査対象の名前 (report.json の name と違えば警告)
max_age: 26h                      # report.json がこれより古ければ「実行されていない」と通知する
urgent_severity: high             # この重大度以上は緊急用に送る
on_quiet: short                   # short | silent

llm:
  provider: bedrock               # bedrock | claude-cli | none (後続で openai-api)
  model: <推論プロファイル ID>
  region: us-east-1
  # profile: aratam-llm
  timeout: 120s
  # command: /usr/local/bin/claude   # claude-cli の実行ファイル (決定: 実装順 2 で追加。空なら PATH の claude)
  # context_file: aratam-context.md  # この監査対象の前提 (Markdown。ADR 0024)

slack:
  webhook_env: ARATAM_SLACK_WEBHOOK            # 通常用。URL は設定ファイルに書かず環境変数で渡す
  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK   # 省略時は通常用に送り、冒頭にメンションを付ける
  urgent_mention: "<!channel>"
  format: blocks                  # blocks (Block Kit) | text (mrkdwn の本文。v0.3.0 までの書式)
```

- Webhook の URL は秘密なので設定ファイルに書かせない (環境変数の名前だけを書く)。

決定 (実装順 1):
- 必須: `name`, `max_age`, `urgent_severity` (critical | high | medium | low), `on_quiet`, `llm.provider`, `slack.webhook_env`。
  `llm.timeout` は provider が `none` 以外なら必須、`bedrock` は `llm.model` と `llm.region` も必須。`claude-cli` の `model` は省略可 (claude 側の既定)。
  `slack.urgent_webhook_env` と `slack.urgent_mention` は省略可。未知のキーは誤記とみなして設定エラーにする (arata と同じ)。
- `slack.format` (ADR 0029): `blocks` | `text`。必須 (暗黙の既定を持たない)。v0.3.0 の設定には無いので、エラー文に「v0.4.0 から必須。従来どおりなら `slack.format: text`」と書く。
- `*_env` は環境変数の名前 (`[A-Za-z_][A-Za-z0-9_]*`) でなければ設定エラー。URL を貼った誤りを弾き、エラーには値を出さない。
- `urgent_webhook_env` を書いたのに環境変数が空なら、通常用に送り `urgent_mention` を付ける (`URGENT_WEBHOOK_UNSET` の警告を出す)。緊急の通知を落とさないため。
  緊急用の Webhook があるときはメンションを付けない (チャンネル自体が緊急用のため)。
- `llm.context_file` (ADR 0024): 利用者が書いた「この監査対象の前提」(決済画面はリクエストが多いのが仕様、監視の送信元、ログインのパスなど) の Markdown。
  利用者の環境 (監査の設定を置く非公開のリポジトリなど) に置き、arata のリポジトリには置かない (例は `examples/aratam-context.md`)。
  決定: セットアップの手順の 1 段にする (README の通知の手順、`examples/github-actions/README.md` の手順 6、`arata help ai runtime`)。任意の項目として仕様に書くだけでは使われずに終わる。
  同じレポートで有無を比べると、前提ありの要約は「前提のどれに合うか・何だけ確かめるか」を書き、前提と食い違う点 (未承認の主体など) は隠さず指摘した。
  下書きは LLM に任せてよいが、事実の確認とマージは人が行う (前提は承認の代わりにならない)。相対パスは設定ファイルのディレクトリ基準。空なら使わない。
  LLM を使うときだけ読み、要約と提案の書き起こしの両方の system に「この監査対象の前提」として (対処手順の後に。3-3 章) 区切って入れる。重大度・分類の基準・規則より優先しないと明記する
  (振り分けは規則なので変わらない)。provider: none では読まない。
  決定: 無い・読めない・UTF-8 でない・16 KiB を超えるときは設定エラーにせず、WARN (`CONTEXT_UNREADABLE` / `CONTEXT_TOO_LARGE`) を出して前提なしで続ける。
  超えたときは切り詰めずに使わない (途中で切った前提は誤解を招くため)。
- 雛形 (`config init`) の `llm.provider` は `none` にする。LLM の鍵を用意する前でも notify が動き、まず規則だけの通知で流れを確かめられるように。
  `max_age` などの書式は arata の設定と同じ (`time.ParseDuration` と `d` = 日)。

## 5. CLI

```
aratam config init [--out aratam.yaml] [--force]
aratam config check [-c aratam.yaml] # 設定の形をオフラインで検査 (Slack・LLM に繋がない。問題があれば終了コード 2)
aratam notify  --in <dir> [-c aratam.yaml] [--dry-run [--format text|json]] [--force]
               # --dry-run は送らずに標準出力へ。LLM は呼ぶ (--llm none で呼ばない)。--format json は送る payload そのもの
aratam doctor  [-c aratam.yaml]   # LLM に短い問い合わせを 1 回、Webhook の環境変数の有無を確認 (送信はしない)
aratam test-notify [-c aratam.yaml] # Slack に試験メッセージを 1 通送る
```

- 決定: 設定ファイルのパスには既定を持つ。`-c` > 環境変数 `ARATAM_CONFIG` > カレントディレクトリの `aratam.yaml` の順に探す。
  `config init` の書き出し先も既定は `./aratam.yaml` (既存ファイルは `--force` が無ければ上書きしない)。
  `--in` は既定を持たない (監査対象・プロファイルごとに違うデータの場所で、取り違えると別の report を送ってしまうため)。
- 決定 (arata の ADR 0042): `config check` は notify / doctor が起動時にする検証 (`notify.LoadConfig`) だけを行い、Slack にも LLM にも繋がない。PR の CI で使う。
  - Webhook の環境変数は見ない (警告も出さない)。PR の CI には秘密を渡さないのが正しい形で、そこで毎回「未設定」と出る警告は読まれなくなる。あるかどうかは `doctor` が見る
  - `llm.context_file` は書いてあれば読めるかを見る。リポジトリの中のファイルなのでオフラインで確かめられる。読めない・16 KiB を超えるは `warn`
    (notify が前提なしで続けるのと同じ扱い。ADR 0024)。`provider: none` では使わないので `skip`
  - 出力と終了コードは arata の `config check` と同じ形 (`ok` / `warn` / `ng` / `skip`、`ng` があれば 2)
- プロバイダ名は呼び方を表す (`claude-cli` / `openai-api`)。同じモデルを別の経路で呼ぶプロバイダを足しても名前が衝突しない。
- 終了コード: 0 = 送った (または on_quiet=silent / 通知済みで送らなかった)、2 = 設定エラー、
  3 = LLM が使えず report.md で送った、4 = 入力が無い・古い (その旨は送った)、5 = 送信に失敗した。
- 送信に失敗したら標準エラーに出して終了コード 5。cron 側の MAILTO などで拾える。
- 決定: CLI は arata と同じ標準 `flag` の上のコマンド層 (`internal/subcmd`) を共有する。ヘルプの書式・フラグのエラー文言・未知のコマンドで終了コード 2 も arata と同じ。
  標準エラーのログも arata と同じ JSON (`msg` と固定語彙の `code`)。
- 決定: `--dry-run` の出力は 1 通ごとに `--- route: <normal|urgent> → <送る Webhook> ---` の行を付けて本文を出す。
- 決定: `--llm` で `llm.provider` を上書きしたら、上書き後の設定で検証し直す (`--llm none` なら model などは要らない)。
- 決定 (`doctor`): config / webhook / llm を表 (STATUS ITEM DETAIL) で出す。Webhook は環境変数の有無だけで URL は表示しない。
  通常用が無ければ ng (`WEBHOOK_UNSET`)、緊急用の名前を書いたのに無ければ warn (`URGENT_WEBHOOK_UNSET`)。
  LLM は「疎通確認です。ok とだけ返してください。」を 1 回送り (report のデータは渡さない。再試行しない)、失敗や claude の実行ファイルが無ければ ng (`LLM_UNAVAILABLE`)。
  `llm.context_file` を書いたときは context の行を足す (読めなければ warn。provider: none なら skip)。
  ng が 1 つでもあれば終了コード 2、ng / warn の行は標準エラーにも code 付きで出す。
- 決定 (`test-notify`): 既定は通常用、`--urgent` で緊急用に送る (緊急用が無ければ notify と同じく通常用にメンション付き)。送信に失敗したら終了コード 5。

## 6. パッケージ構成

```
cmd/aratam/          # CLI
internal/notify/     # 設定、入力の検査、振り分け、組み立て、検証 (LLM とネットワークに依存しない。テストの中心)
internal/llm/        # Summarizer と各プロバイダ (bedrock / claudecli)
internal/slack/      # Incoming Webhook の送信 (net/http)
internal/subcmd/     # arata と共有する、標準 flag の上のコマンド層
internal/report/schema/  # arata と共有する report.json の型 (標準ライブラリだけに依存)
docs/ai/             # arata と共有。aratam は report.md を system として埋め込む
```

- テストは report.json のゴールデンと、LLM の応答の固定値 (正常・欠落あり・形が不正・時間切れ) で書く。実 LLM と実 Slack には接続しない。
- `internal/report` の型を import して report.json を読む (形のずれをコンパイル時に検出する)。
- 決定: report.json の型 (と JSON・Markdown・Parse) は、標準ライブラリだけに依存する `internal/report/schema` に置き、`internal/report` は型エイリアスで同じ名前を出す。
  `internal/report` は組み立てのために checks / store を import しており、aratam がそれを import すると SQLite と監査用の AWS SDK のサービスがバイナリに入るため。
- 決定: aratam が依存してよいパッケージを `cmd/aratam/deps_test.go` の許可リストで固定する (`go list -deps`)。SQLite・監査用の AWS SDK のサービス・
  `internal/{store,checks,collect,engine,config}` は名指しで禁止する。
- 決定: テストの report.json / report.md は arata のゴールデン (`internal/report/testdata`) をそのまま読む (コピーしない。arata の出力が変われば aratam のテストも落ちる)。

## 7. 実装順

1. `internal/notify` (入力の検査・振り分け・`none` での組み立て) と `internal/slack`、`notify --dry-run`、`config init`
2. `claude-cli` プロバイダと LLM 出力の検証・補完
3. `bedrock` プロバイダ、`doctor`、`test-notify`
4. リリースへの追加 (aratam のバイナリ 2 つ)、README

## 8. 未決事項

- ~~Slack の書式を Block Kit にするか mrkdwn の本文だけにするか~~ (決定: Block Kit。`slack.format: text` で本文も選べる。3-4 章、ADR 0029)
- ~~期間レポート用の system 文書を `docs/ai` に足すか、report.md の節で足りるか~~ (決定: report.md の節で足りる。3-1 章)
- 同じ run の hourly と daily で通知をまとめるか (まずは別々に送る)

# ファズテスト

信用できない入力 (ログ由来の値・LLM の出力・利用者のファイル・外部の API の応答) を解釈する箇所を、Go 標準のファズテスト (`testing.F`) で確かめる。
目的は、パニック・無限ループと、規則で固定した守り (ADR 0037) の破れが無いことを機械で確かめること。判断は ADR 0041。

## 動かし方

```sh
go test ./...                              # seed (f.Add) と testdata/fuzz の入力だけを走らせる。ふだんの回帰テスト
tools/fuzz.sh                              # 全部の対象を 30 秒ずつ探索する (make fuzz も同じ)
tools/fuzz.sh 2m internal/notify           # 時間とパッケージを指定する
go test ./internal/notify -run '^$' -fuzz '^FuzzParseSummary$' -fuzztime 5m   # 1 つだけ長く回す
```

CI は `.github/workflows/fuzz.yml` が週 1 回と手動 (`workflow_dispatch`。時間を指定できる) で `tools/fuzz.sh` を回す。PR では回さない (必須チェックではない)。
テストは実 AWS・実 LLM・実 Slack に接続しない (偽の API と固定値だけ)。

## 失敗したとき

1. `go test -fuzz` は失敗した入力を、そのパッケージの `testdata/fuzz/<対象>/<ハッシュ>` に書く (CI では成果物 `fuzz-failures` に残る)。
   その入力に顧客の情報が無いことを確かめる (seed は架空の値だけなので、ふつうは入らない)
2. `go test ./<パッケージ> -run '<対象>/<ハッシュ>'` で再現する。本体の問題か、テストの性質が厳しすぎるのかを見分ける
3. 本体の問題なら、入力を `testdata/fuzz/` に残すか、意味の分かる seed (`f.Add`) に書き直してコミットし、本体を直す (TDD)。
   判断を変えたら `docs/design.md` / `docs/aratam.md` の「決定:」か ADR に残す
4. 性質の方が誤りなら、テストを直して入力は捨てる

## 対象と性質

| パッケージ | 対象 | 入力 | 確かめる性質 |
|---|---|---|---|
| `internal/notify` | `FuzzParseSummary` | LLM の出力 (text の要約) | 検査を通った文だけが残る。重大度の床・approve の提案の制限。欠落の補完。本文は 3,800 字以内で、緊急の finding の行と LLM の注記が残る。URL・メンション・`<` `>`・目に見えない文字が無い |
| | `FuzzParseBlockNotes` | LLM の出力 (blocks の要約と「→」) | 「まず対応」の id だけ・1 行・上限以内。Block Kit の上限。「まず対応」の finding が全部載る |
| | `FuzzLLMInput` | report.json (LLM に渡す前) | 読める JSON は読める JSON のまま。silenced と、finding の配列の各要素の triage が残らない。finding の数と id は変わらない |
| | `FuzzParseWriteups` | LLM の出力 (WAF の提案の書き起こし) | BLOCK に強める記述・Block の action・コードフェンスが残らない (目に見えない文字を挟んでも)。規則の行が残る。waf-proposals.md の見出しを増やせない |
| | `FuzzRunWithReport` | report.json | 通知の流れ全体 (provider: none、text と blocks、timezone は UTC と夏時間のあるゾーン) がパニックしない。Slack の上限。`<` `>` のエスケープ |
| | `FuzzLogValuesStayInert` | ログ由来の値 (summary・key・data・path) | どの書式でも行を増やせない。目に見えない文字と `<` `>` が残らない (run と期間レポート) |
| | `FuzzOneLineAndEscape` | 任意の文字列 | `oneLine` と `Escape` の性質 (冪等、元に戻せる)、切り詰めの上限 |
| | `FuzzParseDuration` | 設定の長さ | 正の値。日数が桁あふれで別の長さにならない |
| | `FuzzZone` | 設定の timezone、ログ由来の時刻 | `Local` (実行環境のゾーン) にならない。時刻でない値は 1 文字も変えない。直した時刻は同じ瞬間を指す RFC 3339 で、数字と `T : - + . Z` だけ。書いたオフセットはそのゾーンのその瞬間のオフセットか UTC だけ (秒の端数のあるオフセットを丸めない)。文中の時刻の置き換えは時刻の形の外に触れない |
| | `FuzzSlackConfig` | aratam.yaml の slack 節 | 送り方は 1 つだけ (Webhook と bot が混ざらない)。通った値は環境変数の名前・チャンネル ID の形。エラーに値を写さない |
| `internal/slack` | `FuzzParseResponse` | Slack の Web API の応答の本文 | 成功は JSON のオブジェクトで `ok` が `true` のときだけ。error コードは `[a-z0-9_]` で 64 字まで、ID は `[A-Z0-9]`。エラーの文は固定 |
| | `FuzzRetryAfter` `FuzzParseScopes` | `Retry-After`、`X-OAuth-Scopes` | 待ち時間は 0 以上 24 時間以下の秒。scope は決まった字だけ・100 個まで・重複なし |
| | `FuzzPostMessageResponse` | 状態コード・本文・`Retry-After` (偽の API) | 成功は 2xx で `ok: true` のときだけ。エラーの文は 1 行で、トークンも本文も含まない。呼び出しは 3 回まで |
| `internal/collect/cwlogs` | `FuzzNormalizePath` `FuzzMaskSample` `FuzzHistPercentiles` | パス、ログの行、レートの度数 (Insights の結果) | クエリ・フラグメントとメールアドレスの形が残らない。冪等。サンプル行は伏せてから切り、制御文字を残さない。分位数は p50 ≤ p99 ≤ max で、どれも度数の値 |
| `internal/checks` (waf_review) | `FuzzLabelMatches` | WAF の設定のラベル・ルール名・LabelMatchStatement の鍵 | 前の名前空間を省いた鍵は、マネージドのグループのラベルにも WebACL の外のラベルにも一致しない (ADR 0070) |
| | `FuzzQueryLiterals` | 設定の glob・接頭辞・正規表現 | Insights の `/.../` と `"..."` を抜け出さない。Go の regexp でも同じ意味 |
| | `FuzzParseValues` | Insights の結果の値 | 時刻・日・件数 (有限で負でない)・IP の範囲 |
| | `FuzzListedQueries` | 怪しい IP の一覧の IP (ストアから読む値。count_rule_status の listed。ADR 0069) | 文は 10,000 文字以内で、IP の並びの外は固定の部品と同じ。並びの要素はすべて `"<正規の形の IP>"`。数えた IP の数と要素の数が同じ |
| | `FuzzCollectHTTPRows` `FuzzCollectWAFRows` `FuzzMismatchSamples` | Insights の結果の行 (偽の API) | 収集の全体がパニックしない。record を JSON にできる。メールアドレスと User-Agent の原文が残らない |
| | `FuzzPrefixCaptures` | 設定の `request.id`・`request.lines` の正規表現 (`request_lines`。ADR 0051) | キャプチャを `rl_` の名前に付け替えても RE2 で読め、数と順番が同じで、同じ文字列の同じ位置に一致する (エスケープ・文字クラスの中を書き換えない)。`/` が残らない |
| | `FuzzRequestRows` `FuzzCollectRequestRows` | `request_lines` の Insights の結果の行 | 件数は有限で負でない。最初の行のある数 ≤ request_id の数、使い回しの数 ≤ 最初の行のある数。数えるリクエストの数は最初の行のあるリクエストの数より減らない。鍵の数が最初の行の数の半分未満なら必ず止める。`FORMAT_MISMATCH` なら record を出さない |
| | `FuzzRequestCollect` | ログの行 (リクエストごとの request_id の割り当て。偽の Insights が 2 段の `stats` を解釈する) | 同じ request_id を何度使っても、数えた件数は request_id の付いた最初の行の数とちょうど同じ。通らないときは `FORMAT_MISMATCH` で record を 1 つも出さない。最初の角括弧を鍵にする設定は必ず止まる |
| | `FuzzUserValues` | アプリのログから取り出した値 (種類・ID・auth の結果・手段・理由。ADR 0052) | Go の判定は、クエリの中で突き合わせる正規表現と同じものを受ける。形に合った種類と ID は `:`・`\|`・`@`・空白を含まない (主体の key を一意に分けられる) |
| | `FuzzUserRows` | 解釈率のクエリの結果の、ユーザー ID と auth の列 | 形に合わない値は集計の key にも結果にも現れず、捨てた数に入る。ID の付いた数 ≤ 数えたリクエストの数、by の数 ≤ ID の付いた数、種類・手段・理由ごとの和が合計と合う。key は 32 個 + `other` まで |
| | `FuzzUserCollect` | ログの行 (種類・ID・auth の結果が任意の文字列。設定の正規表現は緩い。偽の Insights) | 形に合った種類と ID のリクエストだけが ID つきに、合わないものは捨てた数に、ちょうど入る。合わない値は record に残らない。段 0 の数は変わらない。ID が 0 件なら `http_user` は「取れない」になる |
| | `FuzzHygieneQuery` `FuzzNotPrecededBy` | 設定の項目名・`stream_prefix` (log_hygiene。ADR 0050) | どんな値でもクエリの段の数と並び (`fields` と `stats`) が変わらない。`/.../` を抜け出さない。一時フィールドの名前は全部異なり決まった字だけ。正規表現は Go の regexp でも読め、`=>` と `:`・空白の有無の 4 つの書き方に一致し、`[FILTERED]`・空の値・別の鍵に一致しない。検査を通らない項目名はクエリに入らない。「直前が〜でない」の表現が素直な判定と同じ意味 |
| | `FuzzHygieneRows` | Insights の結果の行 (偽の API。log_hygiene) | 受け取るのは有限で負でない整数だけ (別の方法で読んだ値と一致)。それ以外は収集の失敗で、0 件にしない・何も出さない。record とエラーの文に結果の文字列が残らない |
| `internal/pathids` | `FuzzQueryMatchesNormalize` `FuzzTemplateAny` | ログ由来のパス (path_ids。ADR 0071・0087) | Insights の中の組み立て (偽の Insights) と Go の正規化が同じ型・同じ対象 ID になる。型は印・伏せた区間・置いてよい区間だけで、`:id` の数と対象 ID の数が同じ。`:any` の位置の値は型にも対象 ID にも現れない。拡張子は一覧のものだけを最後の区間の末尾から外し、`/` を足さない・消さない |
| | `FuzzSanitize` | Insights の結果の型 | 置いてよい形 (印・`:x`・32 バイト以下で個人に結び付かない区間) にしかならない。区間の数は `max_segments` まで。`/` で始まらない値は空 |
| | `FuzzCompile` | 設定の `segments`・`templates`・`formats` | 検証を通れば、組み立てた文の段の数は規則の数だけで決まり (`/.../` と `"..."` を抜け出さない)、Go の正規化と同じ結果になる |
| `internal/collect/cloudtrail` | `FuzzNormalizeEvent` `FuzzRoleARNFromSession` `FuzzReadTrailFile` | イベントの本文 (JSON)、ARN、trail の S3 のファイル (gzip の JSON) | 取り出す値の型と上限。セッション名を主体に残さない。キーのハッシュは決まった記録 (発行の 3 種類と AssumedRole の記録) にだけ付き、キーそのものは残さない (ADR 0076・0081)。ファイルの誤りは中身の誤りだけで、解いた大きさの上限を超えて読まず、管理イベント以外を管理イベントにしない |
| | `FuzzPublicStatements` | バケットポリシー、CIDR | 公開の判定が見逃す側に倒れない (条件を外す・公開のステートメントを足す・広い CIDR・否定の演算子) |
| `internal/record` `internal/report` | `FuzzMask` `FuzzFindingMasksIdentity` | 任意の文字列の間に置いたメールアドレス・セッション名 | レポートに元の形で残らない。冪等 |
| `internal/report/schema` | `FuzzParse` `FuzzMarkdownLogValues` | report.json、ログ由来の値 | 読めたものは書き直しても同じ。report.md の行を増やせない (run と期間レポート) |
| `internal/allowlist` | `FuzzParse` `FuzzMatchPattern` | allowlist.yaml、glob | 主体の指定は 1 つ・arn_pattern はアカウントを固定。書いていないアカウントの主体を承認しない。行き先 (`assume_destinations`) のアカウントは 12 桁の数字だけ・note 必須で、呼び出し元の承認と行き先の既知が互いに効かない |
| | `FuzzAppendDestination` | `approve --destination` が書く行き先 (アカウントは finding の data、ロールと note は人の入力) | 書けたなら読め、行き先がちょうど 1 件増え、ほかの節と元の行は変わらない。12 桁の数字でないアカウント・空の note は書かない |
| | `FuzzCheck` | allowlist.yaml (`config check`) | エラーの有無が `Parse` と一致する (check が通したものは run でも読める)。エラーは 1 件まで、警告は重複した主体・重なる行き先・期限切れの行き先の数と一致。行番号がファイルの行数を超えない |
| `internal/checks` | `FuzzKnownDestination` | 呼び出し元・ロールの ARN、受け取ったアカウント、MFA の値 (ログ由来) | 行き先が既知になるのは、外向きで、ロールの ARN のアカウントが既知リストに書いた 12 桁と文字どおり同じときだけ。finding の data からの判定は、それに加えて `mfa` が文字どおり `true` のときだけ |
| | `FuzzOriginTrace` | 保存済みの発行 (AssumeRole*) の種類・キーのハッシュ・時刻の任意の組 | 必ず止まる。たどれたら段数は 1〜4、根は AssumeRoleWithWebIdentity で、1 段目までの時刻の差は寿命の和 (12 時間 + 1 時間 × 段数 - 1) を超えない。たどれなければ 1 段目の値を返さない (ADR 0081) |
| | `FuzzALBsWithoutWAF` | posture_item の `without_waf` (ストアから戻した JSON。ALB の名前は利用者が決める) | 返す名前は空でなく、finding の key の区切り (`\|`) を含まない |
| | `FuzzLogHygieneSnapshot` | log_hygiene のスナップショットの項目 (ストアから戻した値) | key は設定のソース id と種類、重大度は種類で決まる。行数は 1 以上の整数、`retention` は決まった 3 つ、`fields` は設定の項目名だけ。項目の中の文字列が finding に残らない |
| `internal/config` | `FuzzLogHygieneParamField` | `checks.log_hygiene.param_fields` の項目名 | 検査を通った名前は 1〜64 字の英数字・`_`・`-` だけ |
| `internal/engine` | `FuzzBuildRoleParams` | 設定の `log_group` の並び | 出す `AllowedLogGroupNames` は読み取り専用ロールの AllowedPattern に合い (空・`*` にならない)、4,096 バイト以内。カンマで分けると重複を除いた設定の順に戻る。受け付けない名前があれば値を出さない (ADR 0062) |
| `internal/engine` | `FuzzValidateTriageInput` | 片付けの `--by` と `--reason` (ワークフローの入力・実行した人を含む) | 受け付けた `--by` は空でなく 64 バイト以内の ASCII で、`@`・空白・改行を含まない。受け付けた `--reason` は正しい UTF-8・300 文字以内で、制御文字 (Cc)・書式の文字 (Cf)・行と段落の区切りを含まない (ADR 0068) |
| `internal/engine` | `FuzzParseFindingIDs` | ack / snooze / resolve の ID の並び (ワークフローの入力をそのまま渡すこともある) | 受け付けた並びは 1〜100 件で、どれも 12 桁の小文字の 16 進・重複なし・入力に現れた順。書き直して読み直しても同じ。止めたときの文は 1 行で、上限の長さ以内 (ADR 0080) |
| `internal/report/schema` | `FuzzSilencedReasonStaysInCode` | 「黙らせているもの」の節に出す片付けの理由 | report.md で理由は 1 つのコードの中に収まり (バッククォートで閉じさせない)、改行で行を増やさない (ADR 0068) |
| `internal/iplist` | `FuzzBuild` | 日の値の key (ログ由来の IP。怪しい IP の一覧。ADR 0069) | 一覧の行の IP はすべて正規の形 (`netip.Addr.String()` で読み直した値と同じ) で、既知の送信元を含まない。理由は 3 つのどれか、件数は正、日とソースは渡したもの (後で Logs Insights の問い合わせの文に入れる値) |
| `internal/config` | `FuzzParseDuration` `FuzzParseStore` `FuzzLoad` | 設定の値、arata.yaml | 受け入れた値は書いたとおりの意味。source の id と profile 名にパスの区切りが無い。`path_ids` を受け入れたソースは検証した規則を持ち、組み立てた文が長さの上限に収まる |
| | `FuzzRequestValidate` | 設定の `request:` (`request_lines`。LLM が書く) | 受け付けた設定は、鍵のキャプチャが `request_id` だけ、行のキャプチャが決まった名前だけで、どれも RE2 で読め、ip と path が同じ行にあり、同じ項目を 2 つの行が取り出さず、`set` は 100〜599 の status だけ |
| | `FuzzRequestUserValidate` | 設定の `request.user_id`・`request.auth` の正規表現 (ADR 0052) | 受け付けた正規表現は RE2 で読め、決まった名前のキャプチャだけを持ち (必須のものがある。by は 2 つとも)、どの入力に対しても一致が入力の終わりで終わる (行の途中の同じ並びを読まない) |
| `internal/collect/account` | `FuzzParseCredentialReport` | 認証情報レポートの CSV | 行の形 (日時は RFC 3339 の UTC か空、キーは 2 本まで) |
| | `FuzzWAFStatementBasis` | WAF のルールの文 (And・Or・Not の木。利用者が決める) | 前提の葉 (国・IP セット・Host 名) を含む木だけが前提か前提の一部になる。パスの葉だけの木はパス。Not を 2 つ重ねても変わらない (ADR 0084) |
| `internal/repoinit` | `FuzzFiles` | `arata repo init` の引数 (YAML・HCL・シェル・Markdown に入る。チャンネル ID の引数を含む) | 形を通らない引数では 1 つも書かない。形を通れば、ワークフローは YAML として読め、参照する秘密は決まった 3 つだけで、値は決まった場所にだけ入る。チャンネル ID が足りなければ、空で書き出さずに足りない引数を返す (ADR 0059・0060) |
| | `FuzzLineDiff` | 今ある一式のファイル (利用者のもの) | 行の差分に、制御文字と不正な UTF-8 が残らない |
| | `FuzzWorkflowSecrets` | ワークフローの YAML (利用者のリポジトリ) | 返す秘密の名前は、形の合うものだけ・重複なし・名前の順で、入力に現れるものだけ (ADR 0060) |
| | `FuzzAratamSlack` | aratam.yaml の slack 節 (利用者が育てるファイル) | 送り方は bot か webhook のどちらか (aratam と同じ判別)。エラーに中身を写さない |
| | `FuzzGitHubSecretList` | GitHub の API の応答 (秘密の名前の一覧。偽の API) | 出力とコマンドに運ぶ名前は、秘密の名前の形だけ。出すコマンドは `gh secret set` / `gh secret delete` の決まった形だけ。読めない一覧を「足りない秘密」にしない。応答の本文と鍵を出さない |

新しく信用できない入力を解釈する関数を足したら、ここにファズテストも足す。性質は「パニックしない」だけにせず、その関数が守る規則を書く。

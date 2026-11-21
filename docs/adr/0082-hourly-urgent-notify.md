# 0082. 取得の回に `hourly` のプロファイルを重大度の下限 (`min_severity: high`) 付きで判定し、high 以上だけを通知する (`arata repo init --flash`)。下限より下の観測は記録せず daily に残す

- 日付: 2026-11-21
- 状態: 採用 (2026-11-21、開発リードのレビュー。実装はまだ)
- 関係する判断: ADR 0078 (取得だけのワークフロー。4 節の「秘密は認証の 2 つだけ」を、この引数を付けたときに限り置き換える)、0072 (`ecs_exec` の重大度)、
  0066 (量の急変の速報。`flash: true` のプロファイル)、0038 (報告済みの印は出力の準備の後)、0005 (event 型と state 型)、0014 (暗黙の既定を持たない)、
  0054 (機械が読む出力)、0060・0061 (bot トークン、知らせのチャンネル)、0018 (arata と aratam は出力だけで連携)

## 背景

利用者の要望 (オーナーの判断、2026-11-21):

- 1 時間ごとの取得のときに、緊急度の高いものがあれば通知までしたい
- 作り方は `arata repo init` の雛形に入れる (各リポジトリで手で直さない)
- ECS Exec は、未知の主体の場合だけ 1 時間ごとに通知したい。既知の主体 (medium) は、今までどおり daily で知らせればよい

### 今の事実 (2026-11-21 の main)

- `arata repo init --collect-every <間隔>` が `arata-collect.yml` を書き出す (ADR 0078)。中身は `arata collect --incremental` だけで、判定・通知はしない。秘密は認証の 2 つだけを渡す
- 設定の雛形 (`config init`) に `hourly` のプロファイルがある (`root_usage`・`ecs_exec`・`unknown_assume_role`・`oidc_assume_role`、window 1h)。
  `daily` にも同じ 4 つが入っている (hourly を回さない運用でも拾うため)。`repo init` のワークフローは daily と weekly だけを回し、hourly を回さない
- 4 つのチェックはどれも event 型 (ADR 0005)。重大度:
  - `root_usage`: critical
  - `ecs_exec`: 知らない主体 high、既知の主体 medium、すべて失敗した試行は 1 段下げる (知らない主体 medium、既知の主体 low)。Key に UTC の日付が入る (ADR 0072)
  - `unknown_assume_role`: high
  - `oidc_assume_role`: 既知のロールに知らない入り口から high、知らないロール medium、既知の入り口の回数が平常帯超え low / medium
- 差分判定 (`internal/checks/diff.go`) は、観測を findings の表と突き合わせて**必ず書く** (upsert)。報告済みの印 (`reported_at`) は出力の準備の後に付ける (ADR 0038)。
  一度も報告していない open の finding は、次の run でも new に戻る
- daily は、窓の中で初めて見た (first_seen が窓の始点より後) かつ報告済みの still_open を `already_reported` (「本日報告済み」) に回す。新規としては出さない
- aratam は `on_quiet` (aratam.yaml) で静かな回の送り方を決め、`coverage.sources_failed` があれば緊急用に送る。aratam.yaml はアカウントごとに利用者が育てるファイルで、`repo init` は書き直さない
- ADR 0066 の速報 (`access_denied_spike`・`sign_in_failure_spike`、`flash: true` のプロファイル) は**まだ実装していない** (roadmap の「大きなアカウントの収集」の後段)

### 守る性質 (要の点)

1 時間ごとの run が指摘を記録 (報告済みに) したのに通知しなければ、daily では「本日報告済み」の件数に回るだけで、新規として知らされない。
**1 時間ごとの run は、通知しない指摘を記録しない。daily に新規として残す。** aratam の側の下限で落とす形は、この性質を壊すので使わない
(arata が報告済みにした後で aratam が捨てることになる)。

## 決定

### 1. プロファイルに重大度の下限 `min_severity` を足す (arata)

```yaml
profiles:
  hourly:
    window: 1h
    min_severity: high          # この重大度より下の観測は、この run では記録も報告もしない (次の daily が新規として報告する)
    checks: [root_usage, ecs_exec, unknown_assume_role, oidc_assume_role]
```

- 値は `critical | high | medium | low`。書かなければ今と同じ (下限なし)。暗黙の既定は持たない (ADR 0014)
- **下限より下の観測は、差分判定 (`checks.Diff`) に渡す前に捨てる**。findings の表に書かず (first_seen も reported_at も付かない)、報告にも出さない。
  次の daily (下限なし) が同じ観測を新規として報告する。チェックの計算 (重大度・Key・Fingerprint) は変えない
- **`min_severity` を書いたプロファイルには、event 型のチェックだけを入れられる** (`config check` と `run` の設定の検査で止める。`CONFIG_INVALID`)。
  state 型は「観測されなかった open は resolved」なので、観測を捨てると既存の finding を解消してしまう。info の重大度も下限より下として捨てる
- 捨てた観測は記録しないが、数だけを報告に出す: report.json のトップレベルに `min_severity` (文字列。書いたときだけ)、`summary.deferred` (下限より下で次に回した観測の数。書いたときだけ) を足す。
  report.md には「下限 (high) より下の N 件は、次の下限なしの run で報告する」の 1 行。中身 (主体・Key) は出さない
- スキーマ: `schemas/report.schema.json` と `profiles.schema.json` に項目が増える。足すだけなので互換で、`schema_version` は 1 のまま (ADR 0054)

この形で決まること (今の差分判定の規則のまま):

| hourly で見た観測 | hourly の run | 次の daily |
|---|---|---|
| 下限以上 (例: 知らない主体の ECS Exec、high) | new として記録・報告し、報告済みにする | 同じ Key は `already_reported` (「本日報告済み」)。Fingerprint が変われば changed として出し直す |
| 下限より下 (例: 既知の主体の ECS Exec、medium) | 記録しない (`summary.deferred` に数だけ) | new として報告する (今の daily と同じ) |
| 下限より下で、同じ日の同じ Key が後で下限以上になった | 後の回で new (high) | `already_reported` |
| ack / snooze 中の Key が下限以上に上がった | changed として再報告 (ADR 0022 のまま) | 今と同じ |
| ack / snooze 中の Key の下限より下の観測 | 捨てる (状態を触らない) | 今と同じ |

- 決定: 下限は**プロファイルに書く** (チェックのパラメータにしない)。「1 時間ごとに知らせるのは high 以上」は回し方の決まりで、チェックごとの意味ではない。
  4 つのチェックすべてに同じ形で効き、今後 hourly に入れるチェックにも、パラメータを足さずに効く

### 2. 雛形の `hourly` のプロファイル

- `config init` の雛形の `hourly` に **`min_severity: high`** を書く。チェックは今の 4 つのまま (`root_usage`・`ecs_exec`・`unknown_assume_role`・`oidc_assume_role`)。
  新しい既定値なので `config init --diff` で見える (`missing_key profiles.hourly.min_severity` の形。実装で今の差分の出し方に合わせる)
- 結果として 1 時間ごとに知らせるもの: ルートの利用 (critical)、知らない主体の ECS Exec の成功 (high)、allowlist に無い呼び出し元の AssumeRole (high)、
  既知の OIDC のロールへの知らない入り口からの引き受け (high)。medium 以下 (既知の主体の ECS Exec、知らない OIDC のロールなど) は daily
- `daily` は変えない (4 つのチェックを入れたまま。下限なし)
- **ADR 0066 の速報 (`access_denied_spike`・`sign_in_failure_spike`) は入れない**。まだ実装が無く、また ADR 0066 は速報を `flash: true` の専用のプロファイルで回し、
  ほかのチェックと混ぜない (LLM を通さない) と決めている。実装したときは、同じ step の並び (4 節) に `run --profile flash` を足す形を、その実装の PR で決める

### 3. 知らない主体の、すべて失敗した ECS Exec (今は medium) は 1 時間ごとに入れない

- 決定 (提案): **入れない**。重大度 (ADR 0072 の 3 節) は変えず、medium のまま daily で知らせる
- 理由
  - すべて失敗した試行は、本番のコンテナにシェルが開いていない (壁が効いた)。成功 (high) と違い、今すぐ止める操作が無い
  - 知らない主体が権限の無い操作を試していることの兆候は、ほかに `unknown_assume_role` (high、1 時間ごと)、`access_denied` (daily)、
    のちに `access_denied_spike` (ADR 0066、速報) が受け持つ。ECS Exec の 1 回の失敗だけを毎時に上げる理由が弱い
  - 失敗には `TargetNotConnectedException` (エージェントが動いていない) のような作業の失敗も混ざる。新しいロールを作った直後 (まだ既知でない) の作業の失敗で、夜中に鳴らしたくない
  - 同じ日に成功が混ざれば、同じ Key で high になり、その回で 1 時間ごとに知らせる (ADR 0072 の「上がる余地」)
- 却下した案
  - **知らない主体の失敗を high にする** (ADR 0072 の表を変える): daily でも high になり、緊急用のチャンネルに送られる。作業の失敗まで緊急にする。
    重大度を変えると攻撃の対応表 (ADR 0058) と playbook も直すことになり、この要望の範囲を越える
  - **`ecs_exec` に「知らない主体の失敗も下限を越えさせる」パラメータ**: 1 節の「下限はプロファイルの決まり」を、チェックごとの例外で崩す。要るとわかれば、別の ADR で足す (足すのは互換)

### 4. ワークフローの形: `arata-collect.yml` の 1 つのジョブの中で、判定・通知・取得を続ける

`--flash` を付けたとき、`arata-collect.yml` のジョブの step を次の順にする (準備の step は今と同じ):

1. 準備 (checkout・取得と照合・秘密の確認・OIDC・監査ロールのプロファイル)。秘密の確認は認証の 2 つのまま (Slack のトークンの未登録は、aratam が `CONFIG_INVALID` で止まる。監査と同じ)
2. **`arata run --profile hourly --out <一時のディレクトリ>`** (時間切れ 15 分)
3. **`aratam notify --in <同じディレクトリ>`** (時間切れ 5 分)。2 が終了コード 0 か 3 のときだけ動かす
4. `arata collect --incremental` (今の step。時間切れ 35 分)。2・3 の成否に関係なく動かす
5. 知らせ (`--alert-channel` を付けたときだけ。6 節)

- 決定: **別のファイル (`arata-flash.yml`) にしない**。理由
  - 課金は 1 回ごとに分へ切り上げる (ADR 0078 の 7 節)。ジョブを分けると、準備の数十秒と切り上げが毎時 2 回になり、`1h` なら 1 アカウントで 1 か月に少なくとも 720 分増える。
    同じジョブなら、増えるのは判定の数十秒だけ (7 節)
  - 2 つのファイルにすると、同じ group (`arata-audit-<アカウント>`) で毎時 2 つが順に待ち、その後ろで daily も待つ。待ちの数が倍になる
  - 「取得の間隔で回すもの」を 1 つのファイルにまとめる (`--collect-every` が cron を決め、`--flash` が中身を足す)
- 決定: **判定を取得より先にする**。取得が追いつきで長引いても、知らせが遅れない。`run --profile hourly` は自分の要るソース (CloudTrail) を、ソースの位置から続きだけ集める (ADR 0064)。
  ふだんは前の回からの 1 時間分で、すぐ終わる。後の取得は、`collect: hourly` の cloudwatch-logs と、判定が読まなかった残りを集める
- 決定: hourly の判定は**取得と同じ間隔で回す** (`--collect-every 6h --flash` なら 6 時間ごと。窓は前の回の終わりから追いつく。`max_catchup`)。勧めるのは `1h`。
  間隔を別に選ぶ引数は持たない (cron が 2 本になり、group の待ちも増える)
- cron・concurrency (監査と同じ group、`queue: max`)・`workflow_dispatch` は ADR 0078 のまま。手で流したとき (`workflow_dispatch`) も判定と通知をする (止まった後の追いつきで、溜まった high を知らせるため)

#### 定時の遅れ・飛びと追いつき

- GitHub の定時は遅れ、まれに飛ぶ (2026-11-21 の実測で 3〜19 分の遅れ)。hourly の判定の窓は、今の規則 (設計書 3 章) のまま **From = min(now − window, 前回の window_to)** で、
  前の回の終わりから続ける。遅れても飛んでも、間の出来事は次の回の窓に入り、取りこぼさない。窓の境目の出来事を 2 回評価もしない
- **`max_catchup` を超えた遅れ** (既定 7d。GitHub の定時が長く止まったときなど): 超えた分の hourly の評価は諦め、`RUN_MISSED` (`truncated: true`) を出す (今の規則のまま)。
  超えた分の出来事は、hourly が記録していないので、daily (自分の窓で追いつく) が新規として報告する。hourly の判定が早く届かなくなるだけで、知らされないことは無い
- 実装の PR で、テストで固定する: 定時が 3〜19 分遅れた回・1 回飛んだ回で、窓が前の回の window_to から始まり、境目の high の出来事がちょうど 1 回報告されること。
  `max_catchup` を超えたときに `RUN_MISSED` が出て、超えた分の出来事が hourly で記録されず、次の daily で新規になること

#### Slack の秘密がワークフローに渡ること (ADR 0078 の 4 節との関係)

- ADR 0078 の 4 節は「取得は Slack に送らない。秘密は認証の 2 つだけ」とした。理由は 2 つ: 取得の回に通知の step を持たない (毎時の一時的な失敗で鳴らさない)、要らない秘密を渡さない
- この ADR は、**`--flash` を付けたときに限り**、`ARATAM_SLACK_BOT_TOKEN` を `arata-collect.yml` に渡す。付けなければ今の出力と 1 バイトも変わらない (テストで固定する)
- 渡し方は監査と同じ: **aratam の step (と 5 の知らせの step) の `env` にだけ**書き、ジョブの `env` には書かない。`arata run`・`arata collect` の step には渡らない。
  environment (`audit`) とデプロイできるブランチの制限は今のまま (ADR 0057)
- 毎時の一時的な失敗で鳴らさない、という 0078 の理由は保つ: 取得・判定の失敗では Slack に送らない (6 節)。送るのは high 以上の指摘があったときと、それが届かなかったときだけ
- `repo check` の `workflow_secrets` は、`arata-collect.yml` が参照する秘密が決まった 3 つの部分集合であることを今のまま確かめる (項目は足さない)

### 5. 引数 `--flash`

- `arata repo init` と `arata repo check` に `--flash` を足す。**`--collect-every` と一緒にだけ使える** (無しで渡すとエラー)。付けなければ今と同じ
- 名前: 「取得の回に、daily を待たずに知らせる (速報する)」の意味で `--flash` にする。ADR 0066 の速報 (`flash` のプロファイル) を実装したら、同じ引数でそれも回す (2 節)。
  今は `hourly` のプロファイルだけを回す
- README のコマンドと `arata-check.yml` の `repo check` の引数に載る (生成物を決める引数なので。ADR 0078 の 1 節と同じ)
- **`repo check --flash` は、各アカウントの `aws/<アカウント>/arata.yaml` に `profiles.hourly` があり、`min_severity` を書いていることを確かめる** (オフライン。PR の検査で落とす)。
  書いていない (古い雛形から作った) 設定のまま流すと、hourly が medium も記録して毎時に知らせる。
  落ちたときの案内には、足す行をそのまま出す (`profiles.hourly` の下に `min_severity: high`。`config init --diff` でも見える)。
  値 (high か critical か) は利用者が選べる。event 型だけであることは `config check` が確かめる (1 節)

### 6. 失敗の扱い

| 起きたこと | ジョブ | Slack | 指摘はどうなるか |
|---|---|---|---|
| 判定 (`arata run`) が 0・3 のほかで失敗 | 赤 | 送らない (aratam を呼ばない) | 確定していない (S3 のストアは Commit しない。ADR 0034・0038) ので、次の hourly か daily が新規として報告する |
| 判定が 3 (一部のソースが取れない) | 成功 (`::warning::`) | 取れた分の指摘だけを送る。取れなかったことでは送らない (7 節) | 取れなかったソースの分は次の回か daily が読む |
| 通知 (aratam) が 2・5 で失敗 | 赤 | 知らせのチャンネルへ 1 行 (`--alert-channel` があり、かつ report.json の new・changed・recurred の数が 1 以上のとき) | **報告済みになっている**。daily では「本日報告済み」に回る。だから知らせを出す |
| 取得 (`arata collect`) の失敗 | 赤 (3 は警告で成功。ADR 0078) | 送らない | ADR 0078 の 5 節のまま (daily が追いつく) |

- 決定: **判定・通知の失敗で、取得を止めない・失敗扱いにしない**。3 つは別の process で、それぞれ自分の分を確定する。取得の step は `always()` で動かし、自分の終了コードで成否を出す。
  ジョブの色は 1 つなので、どれかが失敗すれば赤になる
- 決定: 判定が失敗したときに aratam を呼ばない。呼ぶと report.json が無いので「arata の出力が無いか古い」(終了コード 4) を毎時に緊急用へ送る。
  判定の失敗で失うものは無く (確定していない)、原因が daily と共通なら daily の知らせが届く (ADR 0078 の 5 節と同じ考え)
- 知らせの step の条件は、監査の `alert` (ADR 0060) に「この回に送るべき指摘があった」を足す。数は report.json を `jq` で数として読む (`summary.new + summary.changed + summary.recurred`。機械が読む値。ADR 0054)。
  静かな回の aratam の失敗 (設定の誤りなど) では毎時に鳴らさない。設定の誤りは daily の知らせが届く
- 引き受けること: 通知が失敗し、知らせのチャンネルも無い (または届かない) と、その high は daily の「本日報告済み」の件数と一覧にしか出ない。
  arata は Slack に届いたかを知らない (ADR 0018) ので、報告済みの印を取り消す道は作らない

### 7. aratam: 下限付きの報告の送り方

report.json に `min_severity` があるとき (1 節)、aratam は**送り方だけ**を変える (判定はしない。ADR 0018):

- **静かな回は送らない** (`on_quiet` に依らない)。毎時の「新規なし」を送らない。aratam.yaml を hourly のために分けずに済む (aratam.yaml は利用者が育てるファイルで、`repo init` は書き直さない)
- **`coverage.sources_failed` だけでは送らず、緊急用にもしない**。送り先は指摘の重大度だけで決める (`urgent_severity` 以上なら緊急用)。取れなかったことは daily が今の規則で知らせる (ADR 0066 の速報と同じ扱い)
- 文面: 見出しは今の形 (`arata hourly — <name>`)。本文の先頭に規則の 1 行「この回は high 以上だけを見ています。medium 以下は次の daily で知らせます」(値は report.json の `min_severity`)。
  指摘の行・LLM の要約・「→ 何をするか」は今と同じ。`summary.deferred` は文面に出さない (中身の無い件数で毎回の通知を作らない)
- **LLM は送る回だけ呼ぶ** (今の順のまま: 静かなら 2 の振り分けで終わり、3 の LLM に進まない)。high 以上は月に数回の想定で、費用はわずか。
  知らない主体の ECS Exec のような場面こそ playbook の「→ 何をするか」が要るので、LLM を通す。LLM が使えなければ今と同じく原文で送る (終了コード 3)
- `max_age`・`.aratam-notified` は今と同じ (入力のディレクトリは毎回の一時のもの)
- 版: ワークフローは arata と aratam を同じ Release から取る (`ARATA_VERSION`) ので、`min_severity` を知らない古い aratam と組むことは無い。
  手元の cron で組む利用者向けに、Release の本文に「`min_severity` を使うなら aratam も同じ版以上」と書く (古い aratam は、静かな回に `on_quiet` のとおり送る)

### 8. daily との重なり

- hourly が報告した Key を、daily は新規として再び報告しない。**それでよい** (今の雛形の決定のまま。`internal/scaffold/scaffold.go` の Profiles の注記)
- daily の通知では「本日報告済み N 件」の 1 行に出て、LLM には `already_reported` として渡る (一覧の扱いは今のまま)。daily の report.md には「本日報告済み」の節に 1 件ずつ出る
- 同じ日の同じ Key (`ecs_exec` は日付が Key に入る) に後から新しい記録が加わり Fingerprint が変われば、daily は changed として出し直す (ADR 0072 の 4 節のまま)
- 下限より下の観測は記録しないので、daily にとっては hourly が無いときと同じ (1 節の表)

### 9. GitHub Actions の時間

- 増えるのは、1 回あたり `arata run --profile hourly` の 1 回 (ストアの取り出しと確定、CloudTrail の続き、4 つの判定) と、aratam の 1 回 (静かな回は設定と入力を読むだけ)。
  準備 (バイナリの取得・OIDC) は取得と共有する
- 見積もり: 1 回あたり数十秒が増える。取得だけの回が 1 分に収まっていれば、多くの回は 1 分のまま、越えれば 2 分になる (切り上げ)。
  `1h` で 1 アカウントあたり 30 日で最大 720 分の増加 (すべての回が 1 分を越えた場合)。実際の増え方は、ストアの大きさで決まる (ストアの取り出しと確定が 2 回になる)
- 別のファイルにした場合 (4 節で却下) は、これに準備と切り上げが毎回足され、少なくとも 720 分 / 30 日 / アカウントが増える
- 説明書に書く: 実測の見方 (`gh run list -w arata-collect.yml` の時間)、抑えたい利用者は `--flash` を外す (取得だけに戻す) か、間隔を長くする

### 10. 直すもの (実装の PR)

- arata: `config` に `min_severity` と検査 (event 型だけ・値の形)、engine で差分判定の前に捨てる、report.json の `min_severity`・`summary.deferred`、report.md の 1 行、スキーマの作り直し (`-update`)、
  雛形の `hourly` (ゴールデン)、`config init --diff`。設定は利用者のファイルなので、今の設定の検査のファズ (あれば) に `min_severity` を足す
- aratam: 7 節の送り方 (静かなら送らない・`sources_failed` で緊急にしない・先頭の 1 行)。aratam の依存は増やさない (`cmd/aratam/deps_test.go`)
- `repo init` / `repo check`: `--flash` (`--collect-every` と組)、雛形の `arata-collect.yml` の分岐 (付けないときは今と 1 バイトも変わらない)、`repo check --flash` の `arata.yaml` の検査、
  生成する README のコマンドと説明
- `examples/audit-repo`: 見本の引数に `--flash` を足して作り直す (`TestExampleIsTheOutput -update`)。actionlint・zizmor・actionsgate が読む
- `examples/github-actions` のテスト (偽の `arata`・`aratam` で `run:` を動かす):
  - Slack のトークンが aratam と知らせの step の `env` にだけあり、ジョブの `env`・`arata run`・`arata collect` の step に無いこと
  - 判定 → 通知 → 取得の順。判定が 2 のとき aratam が呼ばれず、取得は動くこと。判定が 3 で警告・成功、aratam が呼ばれること
  - aratam が 5 で、report.json の new が 1 以上なら知らせが動き、0 なら動かないこと
  - `--flash` 無しの出力が今と同じであること、`--collect-every` 無しの `--flash` がエラーになること
- 説明書 (`examples/github-actions/README.md`): 「取得の回に high 以上を知らせる」の節 (有効にする手順 `--schedule --collect-every 1h --flash --force` の PR、`arata.yaml` の `min_severity`、知らせる範囲、daily との関係、失敗の扱い、時間)。
  知らない主体の、すべて失敗した ECS Exec (medium) は 1 時間ごとには届かず、daily で届くことも 1 行書く (3 節)
- `docs/design.md` (プロファイルの項目と「決定:」)、`docs/aratam.md` (2 章の振り分けに 7 節)、`arata help ai` (`config`・`runtime`・`report` の該当箇所。ゴールデンも変わる)
- 攻撃の対応表 (ADR 0058): チェックと重大度を変えないので直さない (3 節で重大度を変えない案を採るため)

## 検討した選択肢

- **aratam の側で重大度の下限を持ち、high 未満を送らない**: arata は既に報告済みにしているので、daily では「本日報告済み」に回り、medium が誰にも新規として知らされない。要の性質を壊すので却下 (依頼の時点で除外)
- **チェックのパラメータで出し分ける (`ecs_exec` の既知の主体を出さない、など)**: hourly のプロファイルの `overrides` で書けるが、チェックごとに「出さない」の意味のパラメータが要り、
  `oidc_assume_role` の medium・low など 4 つすべてに別々の書き方が増える。今後 hourly に足すチェックにも毎回要る。下限 1 つで足りるので却下
- **記録はするが報告済みの印を付けない** (ADR 0038 の「一度も報告していない open は new のまま」を使う): daily は新規として報告できるが、hourly の report.json に medium が new として載り、
  aratam で落とすことになる (却下した 1 つ目と同じ形)。報告に載せない別の区分と、印を付ける条件が 2 か所に分かれる。記録しない方が単純で、表を見ても hourly が無いときと同じになる
- **hourly のプロファイルからチェックを外す (`ecs_exec` を外し、`root_usage` などだけにする)**: 知らない主体の ECS Exec (high) が 1 時間ごとに来なくなり、要望に合わない
- **別のファイル (`arata-flash.yml`)・別のジョブにする**: 4 節。時間と待ちが倍になる。秘密を分けられる利点は、step の `env` に限ることでほぼ同じに得られる
- **取得の後に判定する** (collect → run): 取得が追いつきで長引くと、知らせが遅れ、資格情報の 1 時間の中に判定が収まらないことがある
- **hourly のために aratam.yaml を別に持つ (`aratam-hourly.yaml`、`on_quiet: silent`)**: 利用者が各アカウントで 1 つずつファイルを足すことになり、「手で直さない」に合わない。
  `sources_failed` で緊急用に送る規則も設定では変えられない。report.json の `min_severity` を見て送り方を変える方が、arata の判断 (下限) と送り方が 1 か所でそろう
- **aratam に `--on-quiet silent` の引数を足す**: 静かな回は抑えられるが、`sources_failed` の扱いは残る。7 節の形で足りる
- **判定の失敗も毎回知らせる**: ADR 0078 の 5 節と同じ理由で却下 (毎時の一時的な失敗で鳴る。失うものが無い)
- **hourly の判定に ADR 0066 の速報を入れる**: 2 節。未実装で、`flash: true` の決まり (ほかと混ぜない・LLM を通さない) と合わない
- **daily の `ecs_exec` などを外す (hourly に任せる)**: hourly を回さない利用者・hourly が失敗した回に拾えなくなる。下限より下は daily だけが報告するので外せない

## 結果

- 良い点
  - ルートの利用・知らない主体の ECS Exec・知らない呼び出し元の AssumeRole などが、次の朝を待たずに 1 時間ほどで届く
  - 1 時間ごとの run が、通知しない指摘を報告済みにしない。medium 以下は今までどおり daily が新規として報告する (hourly が無いときと同じ)
  - 引数 1 つ (`--flash`) で有効・無効を切り替えられ、aratam.yaml は直さなくてよい
- 引き受けるコスト
  - GitHub Actions の時間が増える (9 節)
  - Slack のトークンが取得のワークフローにも渡る (`--flash` のときだけ、aratam の step だけ。4 節)
  - 通知が失敗した high は報告済みのまま残る (6 節。知らせのチャンネルで補う)
  - daily の後ろで待つと、知らせが最大で daily の時間 (実測 23 分) ほど遅れる (ADR 0078 の 3 節のまま)
  - 古い雛形の `arata.yaml` は `min_severity` を足すまで `repo check --flash` で落ちる (5 節。黙って medium を毎時に送るより、PR で止める)
- **確かめていないこと**: 実際の GitHub と Slack では確かめていない (開発では実環境に接続しない)。リリースの前に、開発リードが試しのリポジトリで、
  毎時の回が静かなら何も送らないこと、high の偽の指摘 (試験環境の知らない主体の ECS Exec など) が 1 時間以内に届き、次の daily で「本日報告済み」に回ること、
  既知の主体の ECS Exec が毎時には届かず daily で新規として届くことを確かめる
- 次の段 (この ADR では決めない): ADR 0066 の速報を実装したら、`--flash` の step に `run --profile flash` を足す。`min_severity` を daily 以外のプロファイル (event 型だけのもの) で使う形は、要望が出てから

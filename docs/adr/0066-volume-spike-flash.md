# 0066. 量の急変を、時間帯ごとの平常帯と比べて速報する (`access_denied_spike`・`sign_in_failure_spike`。LLM を通さない短い通知)

- 日付: 2026-11-15
- 状態: 採用

## 背景

ADR 0064 (続きだけの収集) と ADR 0065 (Logs Insights の時ごとの小計) で、ストアに時ごとの値が貯まる。読み方の刻みが細かくなれば、
「急激な変化があったときに、とりあえず連絡だけする」通知が作れる (オーナーの提案。2026-11-15 に決定とすることになった)。

今の通知との違い:

- hourly のチェック (`root_usage`・`unknown_assume_role`・`oidc_assume_role`・`guardduty_findings` の High) は**起きたこと自体が異常**な事象で、1 件で鳴る。平常帯は要らない
- daily の平常帯の比較 (`access_denied`・`login_bruteforce`・`waf_block_trend` など) は日の単位で、知らせるのは翌朝になる
- 速報は**量の急変**を時の単位で見る。平常帯と比べる必要があり、日の平常帯ではなく時間帯ごとの平常帯が要る
  (日の平常帯は昼と夜の差を均すので、夜の急増を見落とし、昼のふだんの山で鳴る)

## 決定

### 1. 最初の対象は 2 つ

| チェック | 系列 (key) | 時ごとの値 | 材料 | 使える時期 |
|---|---|---|---|---|
| `access_denied_spike` | 主体の ARN | その時に拒否された呼び出しの件数 (`access_denied` と同じ `error_codes`・`expected_denied` の除外・サービス主体の除外) | events の表 (拒否は注目イベントとして時刻付きで既に残っている。`internal/collect/cloudtrail` の `NotableWith`) | ADR 0064 の後 |
| `sign_in_failure_spike` | `cloudwatch-logs` のソースの ID | その時の sign-in の失敗の件数 (`login_bruteforce` と同じ `paths`・`methods`・`failure_statuses`。IP をまたいだ和) | ADR 0065 の部分の行 (下) | ADR 0065 の後 |

- 周期は hourly。モードは event (ADR 0005)
- 決定: 対象は「**壁を越えたもの**」の急変に絞る。拒否の急増は、入り込んだ後に権限を探る兆候。ログインの失敗の急増は、WAF を越えてアプリまで届いた総当たり。
  どちらも人がすぐに動く理由になる。WAF が止めた量 (BLOCK) は対象にしない (「検討した選択肢」)
- `sign_in_failure_spike` の系列は IP ごとではなくソースごとにする。分散した総当たり (多数の IP から少しずつ) は IP ごとの系列では鳴らない。IP ごとの集中は日次の `login_bruteforce` が受け持つ。
  速報の `data.top` に、その時の上位の送信元 IP を入れる
- 他の候補 (秘匿値の一括読み出し・使わないリージョンへの書き込みの量・WAF で特定の画面への CHALLENGE / BLOCK の急増) は、この 2 つを実データで動かしてから別の ADR で足す

#### ログインの失敗の時ごとの値をどこから得るか (ADR 0065 との関係)

- `sign_in_failures` は http_access のクエリ 2 (`sign_in_failures` + `probe_hits`。`(時, ip, method, status, パスの印)` で数える。ADR 0031・0065) から作る。
  ADR 0065 でこのクエリが `bin(1h)` になり、部分の行 (`metric_parts`) として時ごとに残る。速報はその時の部分の行のうち、`collectHTTP` と同じ条件
  (method・sign-in のパスの印・失敗の status) に合う行の件数を足して時の値にする。新しいクエリは足さない (Insights の読み取りは増えない)
- 平常帯 (14 日) は時ごとの値の系列が要るが、部分の行は確定した日から 3 日で消す (ADR 0065 の `retention.metric_parts`)。そこで、**時ごとの sign-in の失敗の和を `metrics_hourly`
  (ADR 0064 の時ごとの表) に `sign_in_failures_hourly` (key 空) として残す**。日の値を作るときに一緒に書く。1 ソース 1 時間 1 行なので軽い
- 時ごとの値が取れるのは、`collect: hourly` (ADR 0065) を書いた `cloudwatch-logs` のソースだけ。書いていないソース・`request_lines` のソース (ADR 0065 の対象外) では、
  このチェックは skip し、`coverage.checks_skipped` に理由を出す
- 決定: 拒否は events から直接数える (時刻付きで残っているので、時ごとの表に別に残さない。events の保持期間の既定 90 日で足りる)

### 2. 基準

ある系列の、ある時 `h` (UTC の 1 時間) の値 `v` について、次を**すべて**満たしたら急変とする。

1. `v ≥ min_count` (絶対の下限。少ない件数の 2 倍・3 倍で鳴らさない)
2. `v ≥ band_factor × max(B(h), 1)`。`B(h)` は**同じ UTC の時の、直近 `baseline_days` 日の値の最大** (値の無い日は 0)
3. `v ≥ recent_factor × max(R(h), 1)`。`R(h)` は**直前 6 時間の値の中央値**

- 決定: 平常帯は中央値ではなく**最大**で取る。14 日 × 1 時間で 1 つの時に 14 点しかなく、中央値とばらつきは荒い。最大との比なら「この 2 週間のこの時間帯で一度も無かった量」という説明になり、
  速報として誤りが少ない (見落としの向きに倒す。見落とした分は日次の比較が拾う)
- 3 は、ゆっくり増えるもの (キャンペーン・リリースの後) と、急変が続いた後の時を鳴らさないため
- 重大度: 既定は medium。`v ≥ escalate_factor × max(B(h), 1)` かつ `v ≥ escalate_factor × min_count` なら high
- 評価する時は、**ソースの位置 (ADR 0064) が時の終わり + `ingest_delay` を越えた時**だけ (途中の時の値で鳴らさない)。1 回の評価で、前回の評価の後に揃った時をすべて見る

既定のパラメータ (`config init` の雛形に書く。暫定の値で、試験環境と利用者のアカウントで 2 週間動かした後に見直す):

| | `access_denied_spike` | `sign_in_failure_spike` |
|---|---|---|
| `baseline_days` | 14 | 14 |
| `min_baseline_days` | 7 | 7 |
| `min_count` | 50 | 100 |
| `band_factor` | 3 | 3 |
| `recent_factor` | 3 | 3 |
| `escalate_factor` | 10 | 10 |

#### 平常帯が貯まるまで

- 決定: **時ごとの値が `min_baseline_days` 日分そろうまで、その系列の速報は出さない。** レポートの `coverage.notes` に「速報は平常帯の蓄積待ち (あと N 日)」を出す
- 決定: `min_baseline_days` は既定 7。そろうまでは、`B(h)` を揃った日だけで取る (7 日目からは 7〜14 日の最大)
- 絶対値の下限だけで出す案は採らない (下の「検討した選択肢」)。新しい監査対象の最初の 1 週間は、日次の `access_denied`・`login_bruteforce` が受け持つ
- `access_denied_spike` は events に時刻があるので、`init` のベースライン (既定 7 日。ADR 0011) で取ったイベントからそのまま平常帯ができ、init の直後から出せる。
  `sign_in_failure_spike` は ADR 0065 の時ごとの読み方を始めた日から貯まる (init で過去の時ごとの値を作るかは ADR 0065 の実装で決める。作ると Insights の読み取りが増える)
- 主体が新しい (平常帯の期間に一度も現れていない) 系列は、`B(h)` が 0 で 2 は `v ≥ band_factor` になる。1 の `min_count` が効くので、新しい主体の少ない拒否では鳴らない。
  新しい主体そのものは `new_principal` が受け持つ

### 3. 雑音の抑え方

- **finding の key に日を入れる**: `<系列>|<UTC の日>` (例 `arn:aws:iam::123456789012:role/app|2026-11-15`)。同じ系列の急変は、1 日に 1 つの finding になる
- **続けて送らない間隔**: 同じ系列は、前の速報から `cooldown` (既定 6h) の間は、重大度が上がったとき (medium → high) だけ再報告する (ADR 0022 の上げ方と同じ)。
  日をまたいでも `cooldown` は効く (23 時台と 0 時台の同じ急変を 2 度送らない)
- **1 日の上限**: 速報のプロファイルが 1 日 (UTC) に送る finding の数は `max_per_day` (既定 5) まで。超えた分は速報では送らない。
  報告済みの印 (ADR 0038) を付けないので、日次の報告で new として出る
- **日次の報告への引き継ぎ**: 2 つのチェックは daily のプロファイルにも入れる (雛形でそうする)。daily は窓の全部の時を評価し、
  速報で送ったものは同じ key なので `already_reported` に回る (今の hourly と daily の関係と同じ。設計書 3 章)。上限で送らなかったものは new として、LLM の要約つきで日次に載る

### 4. 速報の形

#### プロファイルと report.json

- 速報は**専用のプロファイル**で回す (雛形の名前は `flash`)。プロファイルの設定に `flash: true` を書く
  ```yaml
  profiles:
    flash: { window: 1h, flash: true, checks: [access_denied_spike, sign_in_failure_spike] }
  ```
- `flash: true` のプロファイルに入れられるのは、速報のチェック (この ADR の 2 つと、今後足すもの) だけ (`config check` で止める)。速報は LLM を通さないので、規則の文だけで伝わるチェックに限る
- 決定: **report.json は今の run の報告のまま (新しい `kind` を作らない)**。トップレベルに `flash: true` (速報のプロファイルの報告にだけ付く。`omitempty`) を足す
  - 理由: aratam は知らない `kind` を「arata が失敗した」とみなして緊急用に送る (`docs/aratam.md` 2 章)。新しい `kind` にすると、aratam を上げ忘れた利用者に毎時「失敗した」が届く。
    項目を足すだけなら、古い aratam は通常の報告として送るだけで (LLM を通すので重いが) 壊れない
  - スキーマ: `schemas/report.schema.json` に `flash` (boolean) が増える。項目を足すだけなので互換で、`schema_version` は 1 のまま (ADR 0054)。
    型 (`internal/report/schema`) に足し、`-update` で作り直す。プロファイルの一覧 (`profiles.schema.json`) にも `flash` を足す
- finding の `summary` は arata が規則で作る 1 行。`data` に根拠の数字を入れる

  ```
  拒否の急増: arn:aws:iam::123456789012:role/app が 14:00〜15:00 UTC に 1,240 件 (この時間帯の過去 14 日の最大 30 件、直前 6 時間の中央値 12 件)
  ログインの失敗の急増: prod-nginx-access が 14:00〜15:00 UTC に 3,400 件 (この時間帯の過去 14 日の最大 60 件、直前 6 時間の中央値 25 件。送信元 IP 820 個)
  ```

  `data` の項目: `hour` (RFC 3339)・`count`・`band_max`・`band_days`・`recent_median`・`top` (拒否は上位の API と送信元、ログインの失敗は上位の送信元 IP。各 5 件まで)。ログインの失敗は `ips` (その時の異なり IP の数) も入れる。
  個人を特定する値は入れない (主体は ARN、送信元は IP)

#### aratam

- `flash: true` の報告は **LLM を通さない**。規則で組み立てる: 見出し「速報」・finding ごとに `summary` の 1 行・末尾に「詳しくは次の日次の報告」
  (Block Kit の形は、LLM が使えなかったときの規則の組み立てと同じ部品を使う。`docs/aratam.md` 3-4 章)
- 送り先は今の規則のまま重大度で決める (`urgent_severity` 以上なら緊急用。既定では medium は通常用、high は緊急用)
- 新規・変化・再発が 0 件なら**送らない** (`on_quiet` に依らない。毎時の「新規なし」を送らない)
- `coverage.sources_failed` があっても、速報では緊急用に送らない (毎時の失敗の通知を作らない)。取れなかったことは hourly・daily の報告が今の規則で知らせる
- `max_age` と `.aratam-notified` の扱いは今と同じ

#### 役割の分け方 (ADR 0018)

- 急変かどうか、重大度、送るかどうかの上限 (`max_per_day`・`cooldown`)、文の中身は **arata** が規則で決め、report.json に書く
- aratam は `flash` を見て「LLM を通さない・静かなら送らない・取れなかったことで緊急用にしない」という**送り方**だけを変える。判定はしない

### 5. 順番

1. ADR 0064 の実装 (続きだけの収集、ソースの位置の共有)。hourly が CloudTrail の位置を進めるので、拒否の時ごとの値はこの時点で events から作れる
2. `access_denied_spike` と速報のプロファイル・`flash` の型・aratam の送り方
3. ADR 0065 の実装 (Logs Insights の時ごとの部分の行と、`sign_in_failures_hourly`)
4. `sign_in_failure_spike`

決定: **0064 の実装で、時ごとの値を貯め始める** (主体の活動の `metrics_hourly`。ログインの失敗の時ごとの値は 0065 から同じ表に貯まる。拒否は events から作るので、0064 で新たに貯めるものは無いが、events の保持期間が
`baseline_days` (14 日) より短くないことを `config check` で確かめる。既定の `retention.events` は 90 日で足りる)。

## 互換

- 新しいチェック・新しいプロファイルの項目 (`flash`)・report.json の新しい項目 (`flash`) で、どれも足すだけ。既存の設定・報告は変わらない
- 書かなければ動かない (ADR 0014)。`config init` の雛形に `flash` のプロファイルとチェックの既定のパラメータを書き、`config init --diff` で `unused_check` として見える
- aratam を上げずに `flash` のプロファイルを回すと、古い aratam は LLM を通して毎時の通常の報告として送る (`on_quiet` が `short` なら毎時「新規なし」が届く)。
  Release の本文に「`flash` を使うときは aratam も同じ版以上に上げる」と書く
- `examples/audit-repo` (repo init の出力) のワークフローに毎時の `flash` を足すかは、雛形の版で決める (Actions の実行時間と S3 ストアの確定の回数が増える)

## 検討した選択肢

- **WAF の BLOCK の急増を速報する (`waf_block_spike`)**: 採らない (オーナーの判断。2026-11-15)。オーナーの言葉: 「WAF は基本的にブロックされまくって無差別にリクエストが送られている。これを一々通知するのか悩ましい」。
  BLOCK は WAF が止めた記録で、人がすぐに動く場面が少ない。無差別のスキャンで量の波が大きく、速報が雑音になる。傾向は日次の `waf_block_trend` で足りる。
  速報に向くのは壁を越えたものの急変 (1 節)
  - 次の候補: 「WAF で、ログインなど特定の画面への CHALLENGE・BLOCK が急増した」(量の全体ではなく、狙われている画面が分かる場合)。`waf_block_path` の時ごとの値
    (ADR 0065 の部分の行) を、設定した画面のパス (`login_bruteforce.paths` など) に絞って数える形になる。この 2 つを動かした後に別の ADR で決める
- **平常帯が貯まるまで、絶対値の下限だけで出す**: 採らない。拒否は CI の権限の確かめや監視の道具で毎時ある程度出るアカウントがあり、下限だけでは最初の 1 週間に鳴り続けて
  速報を見なくなる。下限を高くすれば本当の急変も鳴らない。最初の 1 週間は日次の比較で受け、`access_denied_spike` は init のベースラインで直後から出せる
- **日の平常帯 (14 日の中央値 × 係数) と比べる**: 採らない。時間帯の差を均すので、夜の急増を見落とし、昼の山で鳴る
- **中央値とばらつき (MAD) で比べる**: 採らない (今は)。1 つの時に 14 点では荒い。2 週間の実データで最大との比と比べて、良ければ後で置き換える
- **report.json に新しい `kind` (`flash`) を作る**: 採らない。上の 4 節の理由 (古い aratam が毎時「失敗した」を送る)
- **hourly のプロファイルに速報のチェックを混ぜる**: 採らない。hourly の報告は LLM の要約つきで送るので、速報だけを LLM なしで送る区別が報告の中に要る。プロファイルで分ける方が単純
- **aratam が急変を判定する (report.json の数字を読んで)**: 採らない。ADR 0018 (判定は arata)。aratam は LLM と通知だけを持ち、ストアを持たない (`cmd/aratam/deps_test.go`)

## 結果

- 良い点: 量の急変を最短で 1 時間 + 遅れで知らせられる。LLM を待たないので速く、LLM の失敗の影響を受けない
- 良い点: 上限で送らなかったものも日次に必ず載る (取りこぼさない)
- 引き受けるコスト: 毎時の run が増える (Actions の実行時間・S3 ストアの確定の回数)。通知が増え、基準が合わないと速報を見なくなる危険がある。既定のパラメータは暫定で、実データで見直す
- 引き受けるコスト: 最初の 1 週間 (WAF は時ごとの読み方を始めてから 1 週間) は速報が出ない

## 手間の見積もり

- `access_denied_spike` (時ごとの集計・基準・cooldown・上限・日次の引き継ぎ) とテスト: 2 日
- `flash` のプロファイル・`config check`・`config init` の雛形・report の型とスキーマ・`help ai` の文書とゴールデン: 1 日
- aratam の送り方 (LLM を通さない組み立て・静かなら送らない・取れなかったことで緊急用にしない) とテスト: 1.5 日
- playbook (`docs/ai/playbooks/<check>.md`) と攻撃の事例の対応表 (`docs/threats.md`。ADR 0058) を 2 つ分: 0.5 日
- `sign_in_failure_spike` と `sign_in_failures_hourly` (ADR 0065 の後): 1 日
- 合計 約 6 日 (0064・0065 を含まない)

## 未確認の点

- 既定のパラメータ (`min_count`・各係数) が実データで妥当か。2 週間の時ごとの値で、過去にあった急変 (試験環境で作る) が鳴り、ふだんの山が鳴らないかを確かめる
- aratam の Block Kit の規則の組み立てを、速報の 1 行だけの形で Slack の表示の上限に収める方法 (件数が `max_per_day` までなので小さい見込み)

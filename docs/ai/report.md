# report.json の読み方と要約の手順

## report.json の構造

```json
{
  "profile": "daily", "window": {"from": "...", "to": "..."}, "name": "acme", "run_id": "...",
  "summary": {"new": 3, "changed": 1, "recurred": 0, "resolved": 2, "still_open": 7, "max_severity": "high", "collect_errors": []},
  "findings": {"new": [], "changed": [], "recurred": [], "resolved": [], "still_open": []},
  "already_reported": [],
  "info": [],
  "coverage": {"sources_ok": [], "sources_failed": [], "checks_run": [], "checks_skipped": [], "formats": []},
  "proposals": []
}
```

- finding 1 件: `id`, `check`, `key`, `severity`, `summary`, `status`, `first_seen`, `last_seen`, `data` (根拠。件数・IP・日付など)
- `summary.max_severity`: new / changed / recurred の最大。still_open は含まない
- `already_reported`: 別の周期 (hourly など) で報告済みの事象。二重に騒がない
- `info`: 重大度 info (既知デプロイ主体の IAM 変更など)。記録のみ
- `coverage.sources_failed`: 取れなかったソースと `code`、不足した `action`。`covered_from` / `covered_until` は取れた期間。`partial: true` は一部の項目だけ取れなかった (取れた項目で評価済み。取れなかった項目は前回の状態のまま)
- `coverage.checks_skipped`: 走らなかったチェックと理由 (必要なソースが無い / 失敗)
- `coverage.formats`: アプリログの解釈率 (`match_rate`、`code` が FORMAT_MISMATCH / FORMAT_DRIFT のこともある)。`truncated` は結果の行の上限に当たった集計 (件数は少なめ)
- `proposals` (weekly の waf_review が走ったときだけ): WAF の修正提案の候補と observation。下の「WAF の修正提案の候補」
- `dry_run: true` (試しの実行 `arata run --dry-run` の報告だけ): ストアに何も書いていない報告。**通知ではない** (aratam は送らない)。指摘は報告済みになっておらず、次の定時の実行でもう一度出る。分類はストアの今の状態に対するもの。新規の指摘の `id` はストアに無く、`arata review` / `approve` / `ack` に使えない
- `coverage.notes` (試しの実行で、見た範囲が定時の実行より狭いときだけ): 入っていない期間と、日次集計を使うチェックが評価しなかった UTC の日。必ず伝え、その期間・その日を「何も無かった」と書かない (見ていない)。`window` は実際に見た範囲

## 読む順序

1. `summary` で件数と最大重大度を掴む
2. `coverage` で取れていなかったものを確認する。失敗したソースやスキップしたチェックがあれば「静かだから平和」とは書かない
3. `findings.new` → `changed` → `recurred` → `resolved` → `still_open` の順に読む

## 要約の手順

要約は日本語で、次の順に書く。

1. **新規**: 何が・どこから・どの主体で起きたか。重大度の高い順
2. **変化**: 前回から何が変わったか (送信元 IP の増加など)
3. **再発**: しばらく途切れていた事象が再び起きた
4. **解消**: 解消した指摘
5. **未対応**: still_open の件数と、長く残っているもの
6. **取れなかったもの**: coverage の失敗・スキップ・解釈率の問題。対処方法 (`arata help ai` の code 表) を添える

要対処・確認依頼の finding には、チェックごとの対処手順 (`arata help ai playbook` にチェック名を付ける。例 `arata help ai playbook access_denied`) に沿って、
まず確かめること・判断の分かれ目・対処の選択肢を添える。手順は汎用なので、利用者の事情 (組み込み側が渡す文書) があれば踏まえる。
封じ込め (認証情報の無効化など) は提案までで、実行は人が判断する。

## 相関付け

個々の finding を横断して読み、同じ主体・同じ IP・近い時刻のものをまとめる。

- 新規主体 + 国外 IP + 秘匿値取得が同じ主体なら、1 件のインシデント候補として書く
- unknown_assume_role の呼び出し元と new_principal が同じなら 1 つの話としてまとめる。向き (外向き / 内向き / 内部) と MFA は見出しの括弧と data の `direction`・`mfa` のとおりに書く。外向き (自アカウントの主体が外部アカウントのロールを引き受けた) を、外部からの侵入と逆に書かない。`mfa: unknown` を「なし」と書かない
- login_bruteforce / probe_paths / waf_block_trend の IP が重なれば、同じ攻撃元の可能性として書く
- access_denied (拒否された API 呼び出しの急増) は権限の列挙の兆候。同じ主体の new_principal・unknown_assume_role・iam_changes (拒否) と合わせて 1 つの話として書く。
  data の `apis` (拒否された API と件数)・`threshold` (`breadth` = 種類が多い、`volume` = 同じ API の件数が多い)・`allowlist_status` を根拠にする。
  `breadth` は乗っ取りや侵害の疑い、`volume` だけなら設定ミスのアプリの可能性が高い
- access_denied は allowlist で承認済みの主体 (`allowlist_status: approved`) でも出る。承認は「その主体が居ること」を認めるもので、権限を探ってよいという意味ではない。
  承認済みの主体の列挙は乗っ取り・SaaS 側の侵害の疑いとして扱う
- access_denied の data の `expected_denied_excluded` は、allowlist の `expected_denied` (想定済みの拒否) に一致して数えなかった件数。
  数に含まれていない分があることを書き添える。想定内の拒否が多い主体なら `expected_denied` を提案する (`arata help ai approve`)
- defense_evasion (監査・検知を止める・弱める操作) は侵入者が最初にやることの 1 つ。同じ主体の access_denied・iam_changes・unknown_assume_role と近い時刻なら、
  侵害が進んでいる疑いとして最初に書く。`known_deploy_principal: true` で 1 段下がっていても、監査の無効化そのものは見逃さない
- public_exposure (外部に開く設定変更) は deploy タグの主体でも重大度を下げていない (`known_deploy_principal` は事実として添える)。
  `exposure` (開いた中身) と `target` を根拠にし、weekly の access_analyzer・posture の同じ資源の指摘とまとめる
- principal_new_source (既知の主体の初めての送信元・リージョン) はアクセスキー・セッションの漏洩の典型。`new_sources` の `ips` と `new_regions` を根拠にし、
  同じ主体の access_denied・secret_access・iam_changes とまとめる (high は拒否の急増と同時)。送信元の国・事業者は arata が判定していないので、断定せず人への確認事項にする
- secret_access (秘匿値の読み取りの異常) の `bulk: true` は持ち出しの兆候。読まれた秘匿値は漏洩したものとして扱う前提で書く。
  data にあるのは名前 / ARN だけ (値は CloudTrail にも arata にも無い)。調べるために値を読みに行くことを勧めない
- endpoint_abuse (画面への分散した集中・「A のあと B」の連鎖) は事実として書く: 画面の名前・時間幅 (UTC)・件数・異なり IP・ふだんの上限 (`baseline_p99_*`)・同じ UA の IP 数。
  遮断 (IP の拒否・登録の停止) を勧めず、その時間幅に登録・送信されたものを運営が確認・保留することにつなぐ。`baseline_used: false` は導入直後 (絶対の閾値だけ) と書き添える。
  UA はハッシュしか無いので原文を推測しない
- unused_region_activity (ふだん使わないリージョンでの書き込み) は漏洩した認証情報の悪用 (採掘など) の典型。`region`・`apis`・`compute_apis` を根拠に、同じ主体の principal_new_source・
  access_denied・iam_changes と cost_anomaly の同じリージョンの根本原因とまとめ、今も動いている資源の確認を最初に勧める。正規なら `cloudtrail-lookup` の `regions` に足すことを提案する
- cost_anomaly (費用の異常) は予想額・実際の額・増加の割合 (`impact_ratio`)・影響額を並べて伝え、金額だけで重大さを書かない。`root_causes` のリージョン・使用タイプを根拠に
  unused_region_activity などの操作の指摘とつなぐ。費用の削減の提案 (Savings Plans・サイズの見直しなど) はしない
- data に `escalated_from_suppressed: true` がある changed は、人が ack / snooze していた finding の重大度が上がったもの
  (`suppressed_status` は acked / snoozed、`suppressed_severity` はそのときの重大度)。「確認済みだった」ことより、悪化したことを優先して書く
- allowlist のメモ、前回レポート、時間帯 (デプロイ時刻、メンテナンス時間) を踏まえる

## 分類の基準

各 finding を次の 3 つに分け、理由を根拠 (data のどの値か) 付きで書く。

- **要対処 (今動く)**: critical / high で正当な説明が付かないもの。root の利用、既知外主体の AssumeRole、
  設定不備のうち公開につながるもの。侵害の兆候が複数重なるもの
- **確認依頼 (人が判断する)**: 新規の主体や送信元で、業務上の理由があり得るもの。承認するかを人に聞く
- **情報 (記録のみ)**: info、既知の傾向の範囲の low、解消した指摘

`summary.max_severity` が high 以上のときは、LLM の分類に関係なく組み込み側が緊急通知する規則になっている。
LLM は critical / high を「情報」に格下げして沈黙させない。

## 書いてはいけないこと

- 個人特定値 (氏名・メールアドレス) を書かない。主体は ARN、外部アカウントは「外部アカウント NNN」と書く。data に `caller_identity` / `principal_identity: account_only` (または `external_account`) がある finding の主体 `arn:aws:iam::NNN:root` を「NNN の root」「ルートユーザー」と書かない (アカウント NNN のどの主体かは記録に無い。正規の CI や SaaS のロールも同じ形。ルートユーザーの利用は root_usage だけが報告する)
- エンジンのログのサンプル行 (FORMAT_MISMATCH の samples) を要約に転記しない
- 推測を事実として書かない。裏取りしていないことは「可能性」と書く

## 追加の裏取り (任意)

high 以上の finding は、同じ読み取りロールで追加照会して根拠を足してよい (例: その主体の直近の CloudTrail イベント)。
追加照会は読み取りのみ。書き込み・設定変更はしない。

## WAF の修正提案の候補 (proposals)

arata が決まった規則で作った、WAF の設定を変える候補。finding ではない (毎週その時点の候補が出る)。適用するかは人が判断する。

- 1 件: `kind`、`stage`、`web_acl` / `scope` / `region`、`rule` (WebACL のルール名)、`rule_in_group` (ルールグループの中のルール名)、`method` / `path` (正規化したパス。数字・UUID は `:id`)、
  `summary`、`evidence` (根拠の数字と提案する値)、`finding_key` (low の finding にもした候補)
- **提案** (`kind` が observation 以外): `false_positive` (誤検知の疑い)、`challenge_on_app_path` (正規の画面に Challenge / CAPTCHA。人が解いている = 正規の利用者が巻き込まれている疑い。stage は review)、
  `probe_allowed` (すり抜けている探索)、
  `rate_limit_missing` (レート制限の不足)、`rate_limit_loose` / `rate_limit_tight` (レート制限の値の見直し)、`unused_rule` (使われていないルール。削除は勧めない)
- `stage`: `count_first` = まず COUNT で様子を見てから確定する、`review` = 人が見直す (変更を勧めるものではない)。
  **COUNT → BLOCK の切り替えは arata は勧めない** (運用で計画して行う作業)
- **observation** (`kind: observation`、`stage: none`): 規則が提案に至らなかったが、WAF の設定の観点で不審な観測。`about` は関わる候補の種類、`reason` は提案しなかった理由:
  `below_threshold` (閾値未満)、`undetermined` (設定と突き合わせられない・scope-down を解釈できないなど、判断できない)、`excluded_by_config` (除外設定に一致。決済のパスなど)、
  `excluded_by_rule` (決まった除外に一致。レートベースのルール・IP 評判のグループ・sign-in のパス)、`position_limit` (ログの配列の位置の上限を超え、数え漏れの可能性)
- **COUNT のルールの状況** (`kind: observation`、`about: count_rule_status`、`reason: informational`): COUNT で動いているルールごとに毎回 1 件。提案ではなく、COUNT → BLOCK を計画するときの材料。
  `matches` (一致件数)、`suspect_ratio` (怪しい通信の割合 = 探索パスか、レート制限・既定の action・sign-in のパス以外で BLOCK された IP からの一致)、`matching_days` / `days` (一致した日数 / 集計の日数)
- **Challenge / CAPTCHA の状況** (`kind: observation`、`about: challenge_impact`、`reason: informational`): 出した数の多いルールごとに毎回 1 件。`issued` (出した件数)、
  `solve_ratio` (解かれた割合 = 解いた IP / 出した IP。日ごとの値を期間で足した比)、`issued_non_get` (GET 以外。構造上解けない)、`paths` (主なパスと割合)。
  割合が低いのは「ボットを止めている」とも「解けない通信が止まっている」とも読めるので、解釈せず数字だけを書く
- 根拠の読み方: `distinct_ips_max_per_day` は日ごとの異なり IP 数の最大で、期間全体の IP 数の**下限**。`count` などは期間 (`days` 日) の合計。
  レートの値 (`p99_per_5min`、`proposed_limit`、`current_limit_per_5min`) は 1 IP あたり 5 分間の件数

書き起こし方:

- 提案ごとに「何を・なぜ (evidence の数字)・段階 (まず COUNT で様子を見る / 見直す)」を書く。**候補に無い提案を足さない**。数字を作らない
- challenge_on_app_path は「対象から外す (scope-down)・条件を絞る」方向だけを書く。Challenge / CAPTCHA を BLOCK に変えることは勧めない
- count_rule_status は事実 (一致件数・割合・日数) だけを書く。「BLOCK に上げるべき」とは書かない (割合が高くても、切り替えは人が計画して決める)
- observation は「提案はしないが気づいたこと」として、理由 (`reason`) と一緒に事実だけを書く。observation を提案に格上げしない
- 攻撃そのもの (同じ IP の探索・総当たり) は findings (waf_block_trend・probe_paths・login_bruteforce) の方に出る。proposals と同じ IP・パスなら関連付けてよい
- ヘッダー・クエリ文字列・Cookie などの生の値は report.json に無い。推測で補わない

## 期間レポート (report --month / --from --to)

`"kind": "period"` の report.json は収集せずストアから作る月次・任意期間の集計。顧客向けの報告や棚卸しに使う。

- `notes`: 「YYYY-MM-DD 以前は状態遷移の履歴なし」など。期間の一部の件数が数えられていないことを要約の冒頭に書く
- `summary`: 期間内の new / changed / recurred / resolved の件数、`by_severity` (新規・再発した指摘の重大度別)、`open` (今の未対応)
- `events`: 状態遷移の一覧。`profile` が空の resolved は人の resolve / approve か allowlist の編集による解消
- `new_principals` / `open` / `metrics` (アプリ層の日次推移、UTC) / `runs_missing` (partial / failed / RUN_MISSED)
- 要約は「期間の概況 → 重大なもの → 解消したもの → 残っているもの → 取れなかった run」の順。`runs_missing` があれば監視の穴として書く

## approve について

新規の主体のうち正当と思われるものは「approve してよいか」を人に提案する。**LLM 自身は approve しない** (ADR 0001)。
提案には finding の `id`、承認の対象 (`arata review --format json` の `approve`)、理由、期限を付けるべきかを書く。
判断基準は `arata help ai approve`。

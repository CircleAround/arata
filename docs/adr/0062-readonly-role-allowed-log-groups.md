# 0062. 読み取り専用ロールに、読ませるロググループの名前を受けるパラメータを足し、ログの中身を読む Allow をそのロググループだけに絞る

- 日付: 2026-11-15
- 状態: 採用

## 背景

配布用の読み取り専用ロール (`deploy/iam/readonly-role.yaml`) は、Logs Insights の action (`logs:StartQuery`・`logs:GetQueryResults` など) を
`Resource: '*'` で許している。読ませたくないロググループは、ADR 0053 の `DeniedLogGroupNames` (読ませないものを並べる形) で止める。

ある利用者の環境で、読ませないものを並べる形では足りないことが分かった。

- アプリのコンテナが、nginx のアクセスの行と、アプリ (Rails) の行を、**同じロググループの同じストリーム**に出している。
  アプリの行には利用者の操作のログ (リクエストのパラメータ。氏名・メールアドレス・本文) が混ざる
- IAM では、ロググループの中の一部のストリームや一部の行だけを読めるように絞れない (下の「action とリソースの型」。リソースの型は
  ロググループとログストリームまで)。このロググループは「読む」「読まない」のどちらかしか選べない
- 読ませないものを並べる形では、**アプリが後から利用者の値をログに混ぜたとき、黙って読める状態になる**。新しいロググループも、作った時点で読める。
  どちらも、利用者が Deny に足し忘れたことに気付く手段が無い
- 「監査のロールは個人情報を読まない」を守るには、読めるものを明示する形 (許可リスト) が要る。ADR 0053 では
  「ソースを足すたびにロールの更新が要る」として許可リストを採らなかったが、上の事情で、その手間を引き受ける利用者がいる

オーナーが、許可リストの形を足すことを決めた (2026-11-15)。この ADR はその形を決める。
2 の既定・一覧の外の Deny・doctor の探りの検査は、提案の段階で判断を仰ぎ、オーナーの答え (2026-11-15) で決めた。
「仕組みを足しすぎない。次の版では、スタックの更新と設定の書き換えを必須にする」という方針で、仕組みは軽くした。ADR 0053 (Deny) は置き換えず、併用する。

## 決定

### 1. パラメータの形

**パラメータ `AllowedLogGroupNames` を足す。ロググループの名前を完全一致・カンマ区切りで書く。文字の規則は `DeniedLogGroupNames` と同じ**
(`AllowedPattern` で英数字と `_ - / . #` のカンマ区切りだけを通す。空白・`?`・コロン・ARN・空の要素は弾く) **に、`*` 1 文字だけの値を足す** (2 を参照)。

- ARN は、ADR 0053 と同じく名前ごとに 2 つを組み立てる: `arn:*:logs:*:*:log-group:<名前>` と `arn:*:logs:*:*:log-group:<名前>:*`
  (後者はその下のログストリーム、および `StartQuery` が `logGroupName` で渡されたときに評価される形。ADR 0053 のポリシーシミュレーターの結果では
  `<名前>:*` の形で評価された)。組み立ては ADR 0053 と同じ `!Split` / `!Join` (素の CloudFormation。Transform は使わない)
- リージョン・アカウント・パーティションは `*`。理由は ADR 0053 と同じ (ロールはリージョンを持たない。`!Join` の区切りに `AWS::AccountId` を書けない)。
  Allow の側でアカウントが `*` でも、このロールが読めるのは、このアカウントのロググループと、リソースポリシーなどで別に許されたものだけで、
  許す範囲が名前の一致より広がることは無い (未確認: アカウントをまたぐ Logs Insights (CloudWatch のクロスアカウントの監視) で、
  このロールの Allow がどう効くか。arata はそれを使わない)
- **Deny と併用できる。両方に書いた名前は読めない (Deny が勝つ)**。IAM の評価の規則による:
  「An explicit deny in either of these policies overrides the allow.」([Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html))、
  「If the enforcement code finds even one explicit deny that applies, the enforcement code returns a final decision of **Deny**.」
  ([Determining whether a request is allowed or denied within an account](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html))
- 一覧に無いロググループは、Allow が無いので読めない (暗黙の拒否)。「By default, all requests are implicitly denied」
  「If there are no identity-based policies or no statements in identity-based policies that allow the requested action, then the request is implicitly denied」(同じ文書)。
  ただし暗黙の拒否なので、**ほかのポリシー (管理ポリシーなど) がこのロールに付けば読める**。一覧の外を明示の Deny で止める仕組みは入れない (「検討した選択肢」)

### 2. 既定の扱い: 既定を持たない (必須のパラメータにし、全部を読ませるなら `*` と書く)

**`AllowedLogGroupNames` に `Default` を書かない。全部のロググループを読ませる (今と同じ) には、`AllowedLogGroupNames=*` と明示する。**

- `*` は「全部」の意味の予約語で、`*` 1 文字だけのときに限る。`prod-*` や `a,*` のような部分的なワイルドカードは今までどおり弾く
  (`AllowedPattern: '^\*$|^[A-Za-z0-9_./#-]+(,[A-Za-z0-9_./#-]+)*$'`)。`*` のときは、Allow の `Resource` を今と同じ `'*'` にする (Condition で分ける)
- 空は通さない (`AllowedPattern` で弾く)。「空 = 全部」と「空 = 何も読めない」のどちらも、空のときの意味を読み手に推測させるため
- 既にあるスタックを更新するとき、値を渡さなければ **更新そのものが失敗する** (新しいパラメータに既定が無いため)。
  黙って全部が読めなくなる事故 (空 = 何も読めない) も、黙って全部が読めるまま残る (空 = 全部) も起きない。利用者は、更新のときに 1 度だけ `*` か一覧かを選ぶ
  - 未確認: `aws cloudformation deploy` で、既定の無い新しいパラメータを渡さずに既にあるスタックを更新したときの、エラーの文言と、
    変更セットを作る前に止まるか。実装の PR で確かめ、README に書く
- **次の版に上げるときは、スタックの更新と設定の書き換えを必須の手順にする。** 読み取り専用ロールのスタックを `AllowedLogGroupNames` を付けて更新し、
  arata の設定 (`sources`) をその一覧と合わせる。移し方 (一覧の作り方、`*` を選ぶ場合、順番) を Release の本文と README に書く

比べた案 (C に決めた):

| 案 | 新しいスタック | 既にあるスタックの更新 | ADR 0014 (暗黙の既定を持たない) |
|---|---|---|---|
| A. 空 = 全部 (今と同じ) | 何も書かないと全部読める | 変わらない | 外れる |
| B. 空 = 何も読めない | 何も書かないと監査が全部 `ACCESS_DENIED` | **更新で全部が読めなくなる** (次の run で気付く) | 合う。ただし事故の形が悪い |
| **C. 既定なし、全部は `*`** | 値が要る (書かないと作れない) | 値が要る (書かないと更新が止まる) | 合う。選んだ値がスタックのパラメータに残る |

A を採らない理由: 許可リストを足す目的は「黙って読める状態」を無くすことで、何も書かない利用者がその状態のまま残る。
C は 1 度だけ手間が増えるが、決めた値がスタックのパラメータ (`*` か一覧か) として誰からも見える。
`*` を選んだかどうかを arata の側で検査する仕組みは入れない (「検討した選択肢」の doctor の探り)。

### 3. 絞る action

**今 Allow にある Logs の action のうち、`logs:StartQuery` と `logs:GetQueryResults` を、`AllowedLogGroupNames` の ARN だけに絞る。
`logs:DescribeLogGroups` と `logs:StopQuery` は `'*'` のまま (文を分ける)。** ほかの action は足さない (Allow に無いものは暗黙の拒否のまま)。

action ごとのリソースの型は、AWS の Service Authorization Reference の CloudWatch Logs の表で確かめた。HTML の表
([Actions, resources, and condition keys for Amazon CloudWatch Logs](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatchlogs.html))
はスクリプトで描かれていて取り出せなかったので、同じ内容を機械で読める形で配る AWS の Service Reference
(`https://servicereference.us-east-1.amazonaws.com/v1/logs/logs.json`、`Version: v1.5`、2026-11-15 に取得) を読んだ。

| action | リソースの型 | 中身を返すか | このロールでの扱い |
|---|---|---|---|
| `StartQuery` | log-group | 返す (結果は GetQueryResults で取る) | Allow を一覧に絞る |
| `GetQueryResults` | log-group | 返す | Allow を一覧に絞る |
| `StopQuery` | なし (`*` だけ) | 返さない | `'*'` のまま (絞れない) |
| `DescribeLogGroups` | なし (`*` だけ。List) | 返さない (名前・保持期間などの属性) | `'*'` のまま (絞れない。doctor の `log_group` の名前の一致に使う) |
| `FilterLogEvents`・`GetLogGroupFields`・`GetLogRecord`・`StartLiveTail`・`Unmask` | log-group | 返す | Allow に無い (暗黙の拒否)。足さない |
| `GetLogEvents` | log-stream | 返す | Allow に無い。足さない |
| `GetLogFields`・`StopLiveTail`・`TestMetricFilter` | なし | `GetLogFields` は未確認 (項目の名前を返すと思われる) | Allow に無い。足さない |
| `DescribeQueries` | なし (List) | 返さない (クエリの文字列と ID) | Allow に無い。足さない |

リソースの単位で絞れない action で漏れが無い理由:

- `DescribeLogGroups` は List で、ロググループの名前と属性を返し、ログの行は返さない。名前そのものが個人情報になる運用はこの ADR の範囲外
- `StopQuery` はクエリを止めるだけで、結果を返さない
- 中身を返す action は、どれもリソースの型が log-group か log-stream で、**Allow に無いか、一覧に絞る**。`*` にしか書けない action で中身を返すものは、
  今 Allow にある中には無い (`GetLogFields` の返すものは未確認だが、Allow に無い)

`GetQueryResults` について (未確認の点):

- リクエストは `queryId` だけで、ロググループを受けない。リソースの型は log-group だが、**どのロググループの ARN で評価されるか** (そのクエリが問い合わせた
  ロググループか) は、AWS の文書に書かれていない (上の表・[CloudWatch Logs permissions reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/permissions-reference-cwl.html) を読んだ)
- Service Reference の `Operations` では、`GetQueryResults` の操作が `FilterLogEvents`・`GetQueryResults`・`Unmask` の action で認可されうる、
  `StartQuery` の操作が `DescribeLogGroups`・`DescribeQueryDefinitions`・`FilterLogEvents`・`iam:PassRole`・`StartQuery`・`Unmask` で認可されうる、とある。
  今のロールはこのうち `FilterLogEvents` と `Unmask` を持たずに動いているので、それらは特定の使い方 (マスクを外す、など) のときだけと読んでいる (未確認)
- 実装の PR で、**最初に**、`GetQueryResults` を一覧に絞った形で arata の run が通ることを開発用のアカウントで確かめる。通らなければ、`GetQueryResults` だけ `'*'` に戻し、
  理由 (クエリ ID を知らなければ結果を取れない。このロールは `DescribeQueries` を持たないので、ほかの主体のクエリ ID を一覧できない) を ADR に追記する

`StartQuery` で 1 回に複数のロググループを渡すと、1 つでも一覧に無ければ全体が拒否されると見込む (Allow は要求したすべてのリソースに要る)。
arata は 1 回に 1 つしか渡さない。クエリ文字列の `SOURCE` コマンドなど、`logGroupNames` を渡さずに対象を選ぶ書き方の認可は未確認で、arata は使わない。

### 4. arata の設定とロールのパラメータの食い違いに気付く手段

一覧の正は arata の設定 (`sources` の `log_group`) とし、ロールのパラメータは設定から作る。食い違いに気付く手段は、次の 2 つだけにする。

- **読めないソースは `ACCESS_DENIED` として通知と coverage に出る** (今の仕組みのまま。run はそのソースだけを失敗にして続ける)。
  `arata doctor` は、ロググループの `StartQuery` が拒否されたら `permission` の 1 行にまとめている (ADR 0053)。その案内に
  「`AllowedLogGroupNames` に無い (→ `arata config role-params` の値でスタックを更新する)」を足す。action が無いのか、Deny か、Allow の一覧に無いのかは、
  AWS のエラーの文言でしか分からないので、arata は判定しない (ADR 0053 と同じ)
- **`arata config role-params` を足す** (名前は実装の PR で決める)。設定を読み、`readonly-role.yaml` に渡すパラメータを出す。
  `--format json` は `{"schema_version": 1, "parameters": {"AllowedLogGroupNames": "prod-nginx-access,prod-api"}, "log_groups": ["prod-nginx-access", "prod-api"]}`
  の形にし、スキーマ (`schemas/`) とテストで固定する (ADR 0054)。人向けの出力 (`text`) は、そのまま打てる `--parameter-overrides AllowedLogGroupNames=…` を出す
  - 名前は `Config.AuditLogGroups` (cloudwatch-logs のソースの `log_group`。重複を除き、設定の順) を使う
  - 名前が `AllowedPattern` に合わない (使えない文字がある) ときは、出さずに error にする (スタックの更新で弾かれる前に分かる)
  - 名前の並びが CloudFormation のパラメータの値の上限 (4,096 バイト) や、ロールのインラインポリシーの大きさの上限を超えるおそれがあるときは warn。
    名前 1 つにつき、Allow と Deny を合わせて名前の長さの 2 倍 + 60 文字ほどを使う (ADR 0053)。上限の値は実装の PR で公式文書から確かめて書く

`arata repo check` (GitHub を読むだけ。ADR 0060) は AWS を読まないので、この食い違いは見ない。

### 5. 導入の手順 (onboarding) への反映

実装の PR で、次を直す。

- `deploy/iam/readonly-role.yaml` の頭の説明と例。例は `AllowedLogGroupNames=prod-nginx-access` の形と、`*` の形の 2 つ
- `README.md` の読み取り専用ロールの節、`examples/github-actions/README.md` の手順 2
- `internal/repoinit/templates/README.md` の手順 1 (`examples/audit-repo` は `-update` で作り直す)。設定 (`aws/<アカウント>/arata.yaml`) を書いた後に
  `arata config role-params --format json | jq -r '.parameters.AllowedLogGroupNames'` の値を渡す順にする。設定を書く前にロールを作る順なら、最初は `*` で作り、
  設定の後に一覧で更新する、と書く
- `docs/ai/index.md`・`docs/ai/logs.md` の `ACCESS_DENIED` の案内 (Allow の一覧に無い場合を足す)、`docs/design.md` の該当の「決定:」
- **ソースを足す手順に、ロールの更新を足す** (`sources` に書いたら、`arata config role-params` の値でスタックを更新する。しないと、そのソースだけが `ACCESS_DENIED`)
- **一覧に入れる前に、そのロググループの中身の種類を確かめる**、と書く。同じロググループに利用者の操作のログ (個人情報) が混ざっていないかは、
  arata では判断できない (arata は中身の良し悪しを見ない)。混ざっているなら、一覧に入れず、アプリかログの送り方の側で分ける

## 検討した選択肢

- **既定を空 = 全部にする (2 の A)**: 既にあるスタックが何も変わらず、いちばん穏やか。しかし何も書かない利用者が「黙って読める」状態のまま残り、
  この ADR の目的 (読めるものを明示する) が既定で外れる。ADR 0014 にも合わない。採らなかった
- **既定を空 = 何も読めないにする (2 の B)**: 安全側だが、既にあるスタックを別の目的 (action の追加など) で更新しただけで、全部のロググループが読めなくなる。
  次の run の `ACCESS_DENIED` まで気付かない。採らなかった
- **一覧の外を明示の Deny (`NotResource`) で止める**: Allow を絞るだけだと、ほかのポリシーがこのロールに付けば読める。`Effect: Deny`・`NotResource: <一覧の ARN>` なら、
  ほかのポリシーが付いても一覧の外は読めない。しかし `NotResource` の Deny は当たる範囲を読み違えやすく (ADR 0053 のテストは Deny の文に `Not*` を使わないことを固定している)、
  リソースの型を持たない action を入れると全部を止める。このロールはテンプレートが作り、ほかのポリシーを付ける前提が無い。
  仕組みの重さに見合わないので、入れなかった (オーナーの判断、2026-11-15)
- **doctor で「絞っていない (`*`)」を warn にする探り**: 存在しないロググループの名前 (固定の接頭辞付き) に `StartQuery` を投げ、
  `AccessDeniedException` なら絞っている、`ResourceNotFoundException` なら `*`、と見分ける案。入れなかった (オーナーの判断、2026-11-15)。
  - 仕組みの重さに見合わない。探りの拒否が CloudTrail に残るので、arata 自身の `access_denied` がそれを数えないよう、
    接頭辞で除く規則と、collector が拒否された `StartQuery` のロググループの名前を残す変更まで要る
  - その見分けが成り立たないおそれがある。拒否された呼び出しの CloudTrail の記録で `requestParameters` が null だった例がある
    (ADR 0055 の、拒否された `AssumeRoleWithWebIdentity`)。`StartQuery` でも同じなら、接頭辞で見分けられない
  - 認可が存在の確認より先に行われることも未確認だった
- **ARN をそのまま受ける (`AllowedLogGroupArns`)**: ADR 0053 と同じ理由 (`:*` の付け忘れで当たらない) で採らなかった
- **接頭辞で許す (`prod-nginx-*`)**: 新しいロググループが、名前が合うだけで読める状態になる。この ADR が無くしたい状態そのもの。採らなかった
- **タグで許す (`aws:ResourceTag/...`)**: ロググループの側で宣言できるが、タグを付けられる主体が読める範囲を広げられる。action ごとに条件の評価を確かめる必要もある。採らなかった
- **ストリーム単位で絞る**: `StartQuery`・`GetQueryResults` のリソースの型は log-group だけで、ストリームでは絞れない (3 の表)。
  同じストリームに混ざる行を分けるのはアプリかログの送り方の側 (別のロググループに出す、データ保護ポリシーでマスクする) の仕事で、arata のロールではできない。
  文書に、その対処の方向だけを書く
- **arata の側で一覧を持つ (ロールのパラメータを arata が書き換える)**: arata は読み取り専用で、AWS の書き込み系を呼ばない (設計書 8 章)。採らなかった

## 結果 (良い点・引き受けるコスト)

- 利用者は「このロググループだけを読ませる」を宣言できる。新しいロググループ・後から個人情報が混ざったロググループのうち、一覧に無いものは読めない
- 一覧にあるロググループに個人情報が混ざることは防げない (IAM はロググループより細かく絞れない)。それは文書で伝え、アプリの側の対処を勧める
- **互換を壊す**: 既にあるスタックの更新に、`AllowedLogGroupNames` の値 (`*` か一覧) が要る。Release の本文と README に書く。
  arata のバイナリや出力の互換は変わらない (`config role-params` は新しい出力で、スキーマを足す)
- ソースを足すたびにロールの更新が要る (ADR 0053 で避けた手間を、一覧を選んだ利用者は引き受ける)。`arata config role-params` と doctor の案内で手間を減らす
- `*` を選んだまま (絞っていない) かどうかを、arata は検査しない。スタックのパラメータに残る値が、利用者の選んだ印になる
- arata の読み取り専用の性質・必要な action の一覧は変わらない (Allow の範囲を狭めるだけ)。`readonly_role_test.go` の action の突き合わせは、絞った形でもそのまま通る
- Allow の絞り込みはこのロールの中だけに効く。ほかのポリシーが付けば読める (一覧の外の明示の Deny は入れない)

### 確かめ方 (実装の PR)

- `internal/engine/readonly_role_test.go`: `AllowedLogGroupNames` が `*`・1 つ・複数のときの Allow の `Resource` の並び (ADR 0053 のテストの形)、
  `StartQuery`・`GetQueryResults` の文と `DescribeLogGroups`・`StopQuery` の文が分かれていること、どの形でも collector の action が揃うこと、
  `AllowedPattern` が `*` だけ・名前の並びを通し、空・`prod-*`・`a,*`・空白・コロンなどを弾くこと、`Default` が無いこと
- `deploy/sandbox`: CfnInclude に値を渡し、`pnpm test` / `pnpm typecheck` / `pnpm synth` (deploy はしない)
- `arata config role-params`: 型・スキーマ・`schematest` のテスト、名前が規則に合わないときの error
- 最初に、開発用のアカウントで、`GetQueryResults` を一覧に絞った形で arata の run が通るかを確かめる (3)
- IAM の評価 (一覧の内外、Deny との併用、`GetQueryResults` の評価) は、リポジトリのテストでは固定できない。
  ADR 0053 と同じく、IAM Access Analyzer の `validate-policy` とポリシーシミュレーター (`simulate-custom-policy`。架空のアカウント ID と名前) で確かめた結果を PR に書く。
  `GetQueryResults` はシミュレーターでは確かめられない (実際の API の挙動) ので、上の開発用のアカウントでの確認による

## 追記 (2026-11-15、実装の PR)

- **予約語 `none` を足した** (開発リードの判断)。`AllowedLogGroupNames=none` は、どのロググループの中身も読ませない (`StartQuery`・`GetQueryResults` の文を出さない)。
  cloudwatch-logs のソースが無い設定 (`arata repo init` が書き出す設定は、ロググループのソースがコメントだけ) では、渡せる値が `*` か存在しない名前しか無かったため。
  arata の「無し」の書き方 (`audit_account: none` など) にそろえた。`*` と `none` は、値の全体がその 1 語のときだけ予約語。`none` という名前のロググループは読ませられない。
  `arata config role-params` は、ソースが無ければ `none` を出す (error にしない)
- **`GetQueryResults` の評価を確かめた** (3 の未確認の点)。そのクエリが問い合わせたロググループの ARN で評価される。開発用のアカウントで、
  読み取り専用ロールを、`StartQuery`・`GetQueryResults` を 1 つのロググループの ARN に絞るセッションポリシー付きで引き受けて確かめた (資源は変えていない)。
  絞っていない資格情報で別のロググループのクエリを始め、その ID を絞った資格情報で `GetQueryResults` に渡すと、
  `AccessDeniedException` (`not authorized to perform GetQueryResults on resources <そのロググループ>`) になった。一覧に絞った形で `arata doctor` のクエリは通った。
  したがって `GetQueryResults` も一覧に絞ったまま (クエリの ID を知っていても、一覧の外のロググループの結果は取れない)

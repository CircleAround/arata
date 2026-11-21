# 0079. `secrets_access` の主体を、CloudFormation が付ける末尾の乱数だけを除いた形 (`principal_pattern`) でも書けるようにする

- 日付: 2026-11-21
- 状態: 採用

## 背景

allowlist の `secrets_access` の項目の主体 (`principal`) は ARN の完全一致だけである (ADR 0027・0073。`SecretExpected`・`SecretBulkExempt`)。
一方、`principals` には `arn_pattern` (glob。12 桁のアカウントが必須) がある。

CDK (CloudFormation) でロールの名前を指定しないと、名前は `<スタック名>-<論理 ID>-<乱数>` の形になる
(例: `example-app-prod-AppTaskDefExecutionRole1A2B3C4D-AbcDef123Ghi`)。論理 ID (末尾の 8 桁はコンストラクトのパスのハッシュ) は同じ定義なら変わらないが、
**スタックを作り直すと末尾の乱数が変わる**。CDK の既定の書き方で普通に起きる。

そのたびに次が起きる。

- `bulk: exempt` (ADR 0073) の項目が新しいロールに一致しなくなり、起動時の秘匿値の読み取りが一括読み出しの high になる (high は ack できない。ADR 0068)
- `bulk: exempt` の無い `secrets_access` の項目も一致しなくなり、新しいロールは「初めての読み手」の medium になる
- 利用者は allowlist の ARN を書き直す PR を、作り直しのたびに出すことになる。書き直すまでの run は high を resolve するしかない

ADR 0076 で、`bulk: exempt` で外すのは「`ecs-tasks.amazonaws.com` の `AssumeRole` で発行され、`bulk_exempt_within` の内に使われた認証情報」の読み取りだけになった。
主体を glob で書けても、外れるのは「ECS が発行した直後の読み取り」だけである。この ADR は、その前提の上で、主体の書き方だけを広げてよいかと、その形を決める。

### 確かめたこと・まだ確かめていないこと

公式文書 (2026-11-21 に読んだ):

1. CloudFormation の `AWS::IAM::Role` の `RoleName`
   <https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html>
   - 「If you don't specify a name, CloudFormation generates a unique physical ID and uses that ID for the role name.」。名前は 64 文字まで。`RoleName` の変更は「Update requires: Replacement」
   - 生成する名前の形の規則は書かれていない。例として `role/MyRole-AJJHDSKSDF` がある
2. CloudFormation の「resource custom naming」
   <https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-name.html>
   - 「By default, CloudFormation generates a unique physical ID to name a resource. For example, ... `MyStack-MyBucket-abcdefghijk1`」。形 (スタック名・論理 ID・乱数) は例が示すだけで、規則としては書かれていない
   - 「You can't perform an update that causes a custom-named resource to be replaced.」
3. CDK の開発者ガイド「Resources」の物理名の節
   <https://docs.aws.amazon.com/cdk/v2/guide/resources.html>
   - 生成された名前の例: 論理 ID `Stack2MyBucket4DD88B4F` に対し `stack2MyBucket4dd88b4f-iuv1rbv9z3to`
   - 「Assigning physical names to resources has some disadvantages ... any changes to deployed resources that require a resource replacement ... will fail if a resource has a physical name assigned.」

**公式文書に無かったこと**: 生成する名前の形と、乱数の部分の文字の種類・長さの規則。例は英大文字の乱数 (IAM) と英小文字・数字の乱数 (S3) の両方がある。
下の 2 節の規則 (`*` が一致するのは英数字だけ、直前は `-`) はこの例の形を前提にするので、実際の記録で確かめた (次)。

実際の記録 (2026-11-21 に開発リードが読んだ形。CDK のスタックのロール名を、作り直しの前後を含めて 6 つ。名前の値は書かない):

4. 末尾の乱数は、どれも **12 文字**で、英大文字・英小文字・数字が混ざる (形の例: `UldlUdUUUlUU`。U は英大文字、l は英小文字、d は数字)。英大文字だけではない
5. 作り直しの前後で変わったのは、末尾の乱数だけ。その前の部分 (スタック名・論理 ID) は同じだった
6. **名前が 64 文字を超えるときは、論理 ID が途中で切られる** (公式文書には無い。記録で確かめた事実)。切られても、`-` と 12 文字の乱数は末尾に残る。
   形の例: `<スタック名>-WorkerTaskDefinitionExecutionRoleC-<乱数 12 文字>` はちょうど 64 文字で、論理 ID の末尾の 8 桁のハッシュが消え、語の途中で切れている。
   `<スタック名>-WorkerTaskDefinitionTaskRoleA1B2C3-<乱数 12 文字>` は、ハッシュが 6 桁だけ残っている

決定: 乱数の長さは 12 文字に固定しない (公式文書に規則が無いため)。`*` は英数字の 1 文字以上のままにする。記録では 12 文字だった

## 決定

### 1. `secrets_access` の項目に `principal_pattern` を足す。`principal` と排他

```yaml
secrets_access:
  - principal_pattern: arn:aws:iam::123456789012:role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-*
    secrets: ["/example-app/prod/secrets/*"]
    bulk: exempt
    note: タスクの起動のたびに ECS がタスク定義の secrets を読む。CDK でスタックを作り直すと末尾の乱数が変わる
```

- 1 つの項目に `principal` か `principal_pattern` の**どちらか 1 つ**。両方・どちらも無いのは読み込みエラー (principals の「arn / account / arn_pattern のどれか 1 つ」と同じ形)
- 名前は `arn_pattern` にしない。2 節のとおり規則が `principals` の `arn_pattern` より狭く、同じ名前で別の規則にすると、片方の書き方をもう片方に写したときに迷う。
  節の中の主体の項目は `principal` なので、`principal_pattern` とする
- `bulk: exempt` の有無によらず書ける (初出だけを止める項目にも使える)。規則 (2 節) も両方で同じにする。作り直しで一致しなくなるのは、どちらの項目も同じため
- `arata approve` は書かない (今の `secrets_access` と同じ。人が書く)

### 2. 書ける glob は「末尾の乱数だけを `*` にした」形だけ (`principals` の `arn_pattern` より狭い)

読み込みの時に次をすべて求める。外れたら読み込みエラー (警告にしない。ADR 0073 の 3 節と同じ理由: 効き目は静かに finding を消すこと)。

- (a) `arn:<パーティション>:iam::<12 桁>:role/` で始まる (IAM のロール。アカウントは 12 桁の数字。`principals` の `arn_pattern` と同じくアカウントは必須)
- (b) ワイルドカードは**末尾の `*` の 1 つだけ**。`?` と、途中の `*` は書けない
- (c) `*` の直前は `-` (CloudFormation の名前の、論理 ID と乱数の区切り)
- (d) `:role/` の後から末尾の `-*` の前まで (固定の部分) の、最後の `/` より後ろ (ロールの名前の部分) が、`-` で区切った空でない部分を 2 つ以上持つ
  (スタック名と論理 ID。`role/app-*` は不可、`role/example-app-prod-AppTaskDefExecutionRole1A2B3C4D-*` は可)
- (e) 照合の時に、`*` が一致する部分は**英数字 (`[A-Za-z0-9]`) の 1 文字以上**に限る。`/`・`:`・`-` を含む値には一致しない

(e) が要の規則である。`*` が `-` を越えないので、固定の部分に論理 ID を (名前に残っている分を) 全部書かないと一致しない。
例えば `role/example-app-prod-*` は、同じスタックのタスクのロール (`example-app-prod-AppTaskDefTaskRole...-<乱数>`) にも実行用のロールにも一致しない
(どちらも乱数の前に `-` を含む)。`/` を越えないので、パス付きのロール (`role/example-app-prod-X-evil/anything`) にも一致しない。

ただし、名前が 64 文字で切られたとき (背景の 6) は、論理 ID のハッシュが消えるか短くなるので、「同じ論理 ID のロールだけに一致する」は成り立たない。
前の部分が同じに切られる別のコンストラクトのロールにも一致しうる (例: 論理 ID が `...ExecutionRoleC...` と `...ExecutionRoleCustom...` のロールが、同じ形に切られる)。
規則では防げない (切られた名前は、切られていない別のロールの名前の前の部分と区別できない) ので、4 節の data と playbook の案内 (5 節) で見る。

`principals` の `arn_pattern` (`*` は `/` や `:` も含む任意の文字列) は変えない。あちらは主体の承認 (new_principal など) で、`github-actions-*` のように役割ごとに名前を変えて増える主体を受ける。
`secrets_access` は秘匿値の読み取りの finding を消すので、作り直しの乱数の分だけを許す。

### 3. 照合は、一致した主体の ARN ごとに、今の規則をそのまま当てる

- `SecretExpected` / `SecretBulkExempt` は、項目が `principal` なら完全一致、`principal_pattern` なら 2 節の照合で主体を選ぶ。秘匿値の側の比べ方は変えない
- ADR 0073 の 4 節 (サービスに引き受けられたロールか) と、ADR 0076 の 1 節 (発行の突き合わせ) は、**読み取りの実際の主体の ARN**で行う。
  突き合わせる `AssumeRole` の `roleArn` は、読み取りの主体と同じ ARN でなければならない (「pattern に一致する別のロールの発行」とは組ませない)
- 平常帯 (日ごとの数) も、Key (`bulk-exempt:<主体の ARN>`・`bulk-exempt-unmatched:<主体の ARN>`) も、実際の主体の ARN ごとのまま。
  作り直した後のロールは別の主体として数え、別の Key で出る (作り直しの前の Key は出なくなるだけ)
- 1 つの主体に `principal` の項目と `principal_pattern` の項目が両方一致するときは、両方の秘匿値の glob を和で使う (今の「同じ主体の複数の項目」と同じ)

### 4. 一致した glob を finding と info の data に出す

secret_access の finding (初出の low / medium・一括読み出しの high・`bulk-exempt-unmatched:` の medium) と info の行 (`bulk-exempt:`) の data に、次を足す。

- `secrets_access_principal_patterns`: その主体に一致した `principal_pattern` の値 (allowlist に書いたままの値。ログ由来ではない)。一致した項目が `principal` だけなら書かない
- `principal_pattern_principals`: 上の pattern のどれかに一致した、窓の中の秘匿値を読んだ主体の数 (自分を含む)。1 なら書かない

`principal_pattern_principals` が 2 以上になるのは、(1) その日にスタックを作り直して、前後のロールの両方が読んだ、か (2) glob が別のロールにも一致している、のどちらかである。
(2) には、名前が 64 文字で切られて、別の論理 ID のロールが同じ形になった場合 (2 節の終わり) も入る。
playbook に、前者なら何もしなくてよく、後者なら glob を狭めるか `principal` に戻すと書く。重大度は変えない (作り直しの日に鳴らさないため)。

- Fingerprint には入れない (作り直しのたびに changed にしない)
- 足すのは項目だけなので互換 (ADR 0054。finding の `data` は型を決めていない)。スキーマは変えない

### 5. 検査・説明書

- `arata config check`: 1・2 節は Parse の規則なので、今の形のとおり項目の行番号を添えてエラーにする (PR の時点で止まる。ADR 0042)。警告は足さない
  (オフラインでは「glob が別のロールにも一致するか」は分からない。分かるのは run の時で、4 節の `principal_pattern_principals` で見る)
- `docs/ai/index.md` (allowlist の例)・`docs/ai/onboarding.md` (起動時の読み取りの注)・playbook `secret_access.md` (起動時の読み取りの節・data の項目・確かめること)・
  設計書の allowlist の節の決定を直す。help ai はバイナリに埋め込まれるので、ゴールデンも変わる
- 説明書での案内: playbook に次の順で書く。
  1. 名前を固定できるロール (自分で `roleName` を付けている・作り直さない) は `principal` (完全一致) が最も狭い
  2. CDK の既定の名前で、作り直すと乱数が変わるロールは `principal_pattern` で、乱数の前までを全部書く。
     ロール名の固定の部分 (`-*` の前) が 51 文字 (64 − `-` の 1 文字 − 記録で見た乱数の 12 文字) に届いていたら、名前が切られている。
     その場合は、同じスタックに、前の部分が同じに切られる似た名前のロールが無いかを確かめる (あれば、そのロールの読み取りも外れる)
  3. 作り直した後のロールは new_principal でも新しい主体になる。そちらは今ある `principals` の `arn_pattern` で受ける (この ADR は変えない)
- `docs/threats.md` の対応表は変えない (チェックの重大度・条件は変えず、allowlist の書き方を広げるだけ)

### 6. ファズテスト (ADR 0041)

`principal_pattern` は利用者のファイルの値で、照合の相手はログ由来の主体の ARN なので、`FuzzParse` に seed を足し、照合の関数のファズを足して次の規則を固定する。

- 読み込みを通った `principal_pattern` は、必ず 2 節の (a)〜(d) を満たす (末尾が `-*`、ほかにワイルドカードが無い、`:role/` と 12 桁のアカウントがある)
- 一致したなら、ARN は固定の部分で始まり、残りは英数字の 1 文字以上だけ (`/`・`:`・`-` を含まない)。アカウントの違う ARN には一致しない
- 不正な UTF-8 はエラー (今の `globToRegexp` と同じ)

## 検討した選択肢

- **CDK 側で `roleName` を固定するよう案内するだけにする**: arata は変えずに済み、完全一致が最も狭い。
  ただ、物理名を固定したリソースは、置き換えの要る変更が失敗するようになる (背景の公式文書の 2・3。CDK の文書は不利な点として挙げている)。
  監査のために利用者のインフラの書き方を変えさせるのは、arata の役割 (読み取りだけ・利用者の運用に合わせる) に合わない。
  案内としては残す (5 節の 1)。これだけにするのは却下
- **`principals` の `arn_pattern` と同じ規則にする (`*` は `/`・`:` を含む任意の文字列、どこにでも書ける)**: `role/example-app-prod-*` で同じスタックのタスクのロールまで一致し、
  ADR 0076 の「タスクのロールには書かない」(コンテナの中の攻撃者が、認証情報の更新の直後に読めば外れる) を、書き方で破れる。
  パス付きのロールを作れる者には、`/` を越える `*` で任意の名前を一致させられる。却下
- **`bulk: exempt` の項目だけ規則を厳しくし、初出だけを止める項目は `arn_pattern` と同じにする**: 初出の medium / low を消す範囲も、同じスタックの別のロールに広がる。
  作り直しで困る形はどちらも同じなので、規則を 1 つにした方が分かりやすい。却下 (レビューで決定)
- **`principals` の項目を参照する (`secrets_access` に `principal_ref` を書き、`arn_pattern` を流用する)**: 主体の承認の広さ (役割ごとの glob) が、秘匿値の読み取りの除外にそのまま入る。却下
- **正規表現を書けるようにする**: 書き方の自由が増えるだけで、必要なのは「末尾の乱数」だけ。検査で広さを数えにくい。却下
- **CloudFormation が付けるタグ (`aws:cloudformation:logical-id` など) やスタックとの対応で主体を選ぶ**: `aws:` で始まるタグは利用者が付けられないので、名前より強い印になりうる。
  ただ、ロールのタグを読む API の呼び出し・状態の保存が増え、IAM のロールにそのタグが付くかも確かめていない。今回は入れない
- **作り直しを自動で追う (CloudFormation が作った新しいロールを、前のロールと同じものとみなす)**: 「同じ」の判定に CloudFormation の操作の記録の突き合わせが要り、
  攻撃者がデプロイの権限を持てば同じ形を作れる。却下

## 危険の評価 (引き受ける見逃し)

### 名前が合うロールを攻撃者が作れた場合

攻撃者が、glob に一致する名前で、信頼ポリシーが `ecs-tasks.amazonaws.com` のロールを作り、秘匿値を読む権限を付け、それを実行用のロールにしたタスクを起動すると、
起動時の読み取り (ECS が発行した直後の、組の秘匿値の読み取り) は外れ、info の行 (`bulk-exempt:`) と初出の無い形になる。秘匿値の値はそのタスクのコンテナに渡る。

- 要る権限: `iam:CreateRole`・ポリシーを付ける権限・`iam:PassRole`・`ecs:RegisterTaskDefinition`・`ecs:RunTask` (か `UpdateService`)
- **今 (完全一致) でも、ほぼ同じ形はある**: 同じ権限の一部 (`iam:PassRole` で今の実行用のロールを渡し、自分のイメージのタスク定義を登録して起動) があれば、
  今の実行用のロールの起動時の読み取りとして外れる (ADR 0076 は、誰がタスクを起動したかを区別しない)。glob で増える穴は「今のロールは渡せないが、新しいロールは作って渡せる」形だけで、
  ロールを作って渡せる権限は、ふつう今のロールを渡す権限より強い
- 残る手がかり:
  - iam_changes の `CreateRole` (medium。`tags: [deploy]` の主体なら info。ADR 0008・0056。デプロイの主体を奪われた形では info に下がる)
  - new_principal (新しいロールの ARN。ただし作り直しのために `principals` にも同じ形の `arn_pattern` を書いていれば出ない)
  - 4 節の `principal_pattern_principals` (今のロールも同じ日に読んでいれば 2 以上)
  - 組の外の秘匿値を読めば、今どおり初出・一括読み出し
- `principals` の `arn_pattern` の方が広い (`*` がどこにでも書ける) ので、名前の glob で承認が緩む度合いは、この ADR より `principals` の側が大きい。この ADR はそちらを変えない

### ADR 0076 の発行の照合があっても残る穴

主体の書き方を広げるだけで、0076 の評価はそのまま残る (実際の主体の ARN ごとに同じ規則を当てるため)。

- 発行から `bulk_exempt_within` (既定 2 分) の内に、エージェントに発行された認証情報を盗んで外で使われる形
- タスクのロールに書いた場合の、コンテナの中からの利用 (2 節の (e) で、glob を書き間違えてもタスクのロールには一致しにくくした。`principal` でタスクのロールを書けば今と同じ)

### 名前が 64 文字で切られた場合

切られた名前では、glob が別の論理 ID のロールにも一致しうる (2 節の終わり)。そのロールが ECS の実行用のロールで、同じ組の秘匿値を読めるなら、その起動時の読み取りも外れる。
そのロールがタスクのロールなら、上の「タスクのロールに書いた場合」の穴が、書いた人の意図に反して開く。
手がかりは、窓の中で両方のロールが読めば 4 節の `principal_pattern_principals` が 2 以上になることと、playbook の「51 文字に届いていたら似た名前のロールを確かめる」案内である。
片方のロールしか読まない窓では手がかりが無い。切られた名前で似た名前のロールがあるなら、`principal` (完全一致) を勧める
- ECS の基盤そのものを乗っ取られた形 (AWS の責任の範囲)
- 上の「名前が合うロールを作れた場合」

## 結果 (良い点・引き受けるコスト)

- CDK でスタックを作り直しても、allowlist を書き直さずに起動時の読み取りが外れたまま、初出も止まったままになる (作り直しの日の high・medium と、その resolve が無くなる)
- 外れる範囲は「同じ論理 ID で、末尾の乱数だけが違うロール」に限られ (名前が 64 文字で切られたときは、前の部分が同じに切られるロールまで)、ADR 0076 の発行の照合はそのまま効く
- 引き受けるコスト:
  - allowlist の `secrets_access` に項目が 1 つ増え、規則 (2 節) と、その照合・ファズが増える。主体の書き方が節によって 2 通りになる (`arn_pattern` と `principal_pattern`)
  - 乱数の形 (英数字) を前提にする (記録で確かめた。長さは固定しない)。違う形の環境では一致しない (鳴る側。今と同じ)
  - 名前が 64 文字で切られた環境では、似た名前のロールにも一致しうる (上の評価)。規則では防がず、data と playbook で見る
  - 名前を作れる攻撃者に対する見逃しが少し増える (上の評価)。iam_changes の `CreateRole` が、デプロイの主体なら info に下がることも引き受ける
- 実装: `internal/allowlist` (項目・規則・照合・ファズ)・`internal/checks/secret_access.go` (data の 2 項目)・文書 (5 節)。
  テストは、規則の可否 (2 節の各例)・作り直しの前後のロールの両方が外れる・64 文字で切られた名前の形・タスクのロールと別の論理 ID・パス付きのロール・別のアカウントには一致しない・
  0076 の突き合わせは実際の ARN で行う (pattern に一致する別のロールの発行とは組まない)・data の項目、を固定する

## 4 節への追記 (2026-11-21。実装のレビューで分かったこと)

- 事実: 差分判定 (`internal/checks/diff.go` の Diff。全チェック共通) は、その run で new・changed・recurred・suppressed (ack / snooze 中) になった行にだけ data を書く。
  still_open (重大度と Fingerprint が前と同じで、前の run から続いて観測された) の行は、前に書いた data のまま (ADR 0068 の 5 節への追記と同じ前提)。
  `bulk-exempt:` の info の行は Fingerprint が固定なので、前の run から続く行に 4 節の 2 項目は後から付かない
- 実際の記録で起きた形: 作り直しの日に、前のロールの行 (今朝の run で既に出ていた Key) には `principal_pattern_principals` が無く、新しいロールの行 (new) にだけ `2` が付いた
- 決定: 4 節の 2 項目は「その run で data を書いた行に付く」とする。Fingerprint には入れないまま、Diff も変えない
  - 作り直しの日は、新しいロールの Key が必ず new になるので、その行に出る。glob が別のロールにも一致する場合も、後から現れたロールの最初の行 (new) に出る
  - 窓が続いていれば、2 つの主体が初めて同じ窓に並んだ run では、少なくとも片方の行が new か recurred になる
    (両方が still_open になるには、両方が前の run にも出ている、つまり前の run で既に並んでいる必要がある)。そのため、どちらかの行には出る
  - **出ない・合わない場合**:
    - 前の run から続く行には付かない。片方の行に無くても、同じ pattern に一致する主体が 1 つだけとは言えない
    - 2 つのロールが続いた run に別々に現れ、同じ窓で初めて並んだ場合は、前から続く方の行には付かない。もう片方は recurred か new になり、そちらに付く
    - 一度付いた行は、still_open のあいだ値が残る (もう片方が読まなくなっても `2` のまま)
  - そのため playbook では、この項目を「同じ pattern の行を並べて見るきっかけ」とし、数そのものは `arata review` で同じ pattern の行を並べて確かめるよう書く
- 却下: (1) Fingerprint に「2 以上か」を入れる。作り直しの日に、info でない行 (初出の low・`bulk-exempt-unmatched:` の medium) が changed として通知に出直し、
  次の日に 1 に戻るとまた changed になる。4 節の「作り直しの日に鳴らさない」に反する。
  (2) still_open でも data を書き直す (全チェック)。全チェックの report.json の still_open の data の意味が変わり、ADR 0068 の追記と設計書の前提を変える。
  この ADR の範囲を超える (要るなら別の ADR で)
- テスト: 前の run で既に出ている Key に、新しく現れたロールが同じ pattern で並んだとき、新しい方の行にだけ付き、前の行は still_open で前の data のまま、を固定する

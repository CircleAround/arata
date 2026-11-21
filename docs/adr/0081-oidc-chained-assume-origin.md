# 0081. OIDC で入ったセッションから先の引き受けと操作の finding に、1 段目の GitHub の実行の手がかりを、発行されたキーのハッシュの突き合わせで付ける

- 日付: 2026-11-21
- 状態: 採用

## 背景

GitHub Actions の OIDC で引き受けたロール (1 段目、`AssumeRoleWithWebIdentity`) から、さらに別のロールを `AssumeRole` する (2 段目) ことがある。
例は CDK の deploy-role (`cdk deploy` が、ワークフローの認証情報で deploy-role・file-publishing-role などを引き受ける)。

- 2 段目の `AssumeRole` は、呼び出し元 (1 段目のロール) が `principals` で承認済みでなければ `unknown_assume_role` の high になる。
  2 段目のセッションの IAM の操作は `iam_changes` に出る
- **今の finding には、どの GitHub の実行から来たかが出ない。** 1 段目の記録には `oidcDetail` (ADR 0055) が `oidc_repo`・`oidc_ref`・`oidc_environment`・`gha_run_id` などを残すが、
  2 段目以降の記録には何も付かない。利用者は毎回、人が CloudTrail と GitHub を見比べて片付けている
- 0055 の「見えないもの」は、承認済みのロールからの乗り移りを次の候補として残した。この ADR はその手前の、「乗り移りがどの実行から来たか」を見えるようにする
- `roleSessionName` は残さない (ADR 0055・0076・設計書 6 章)。この決まりは変えない

ADR 0076 は、ECS の `AssumeRole` の `responseElements.credentials.accessKeyId` を `issued_key_hash`、秘匿値の読み取りの `userIdentity.accessKeyId` を
`session_key_hash` (どちらも `record.SessionKeyHash`。SHA-256 の先頭 32 桁。キーそのものは残さない) として残し、発行と使用を AWS が発行した値で結んだ。同じ形を 2 段目に広げる。

### 記録の形 (公式文書で確かめたこと。2026-11-21 に読んだ)

1. `AssumeRole`・`AssumeRoleWithSAML`・`AssumeRoleWithWebIdentity` の記録は、`secretAccessKey` を除いた `responseElements` を全部含む。
   `AssumeRoleWithWebIdentity` の例の `responseElements.credentials` に `accessKeyId` (`ASIA…`) がある (IAM ユーザーガイド「Logging IAM and AWS STS API calls with AWS CloudTrail」:
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html>)
2. 一時的な認証情報で呼んだ記録の `userIdentity.accessKeyId` は、その一時的な認証情報のアクセスキー ID。役割の連鎖の例 (`AssumeRole` を `type: AssumedRole` が呼ぶ) にも入っている
   (同上。CloudTrail ユーザーガイドの userIdentity の節: <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>。
   「セキュリティの理由で、無いことや空文字のことがある」とも書かれている)
3. 役割の連鎖 (ロールのセッションで別のロールを引き受ける) のセッションは最大 1 時間。ロールの最大のセッションの長さの設定によらない
   (<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html>)。
   `AssumeRoleWithWebIdentity` のセッションは既定 1 時間、最大 12 時間 (`DurationSeconds` の範囲は 900〜43200。
   <https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html>)
4. 1 段目の記録の `userIdentity` (`WebIdentityUser`) には `accessKeyId` が無い。1 段目と 2 段目を結べる値は、1 段目の**応答**の `accessKeyId` と、2 段目の**呼び出し側**の `accessKeyId` だけ

### 実際の記録で確かめたこと (2026-11-21)

出典: 本番の環境の CloudTrail (LookupEvents、2026-11-20〜21) を、2026-11-21 に開発リードが読んだ形。アカウント・ロール・リポジトリの名前と値は書かない。

1. GitHub の OIDC の 1 段目 (`AssumeRoleWithWebIdentity`) は 4 件。全件に `responseElements.credentials.accessKeyId` があった
2. GitHub の OIDC のロールのセッションが呼んだ 2 段目の `AssumeRole` (呼び出し側が `AssumedRole`) は 11 件。全件で `userIdentity.accessKeyId` が空でなく、
   1 段目の発行のどれかと一致した (合わなかったものは 0 件)
3. 1 段目の発行から 2 段目の呼び出しまでは 36 秒〜23 分 (2 節の範囲の内)
4. 2 段目の行き先は、CDK の deploy-role と file-publishing-role だった

## 決定

### 1. 残す値: `issued_key_hash` を一般化し、`session_key_hash` を注目イベントの全部に広げる

cloudtrail collector (`normalizeRaw`。LookupEvents と trail の S3 の共通) で、次の値を残す。値はどれも `record.SessionKeyHash` (キーが `ASIA` + 英大文字・数字 16 桁の形のときだけ。
形に合わなければ何も残さない)。

| 記録 | 項目 | 元の値 | 0076 との違い |
|---|---|---|---|
| 成功した `sts:AssumeRole` で、呼び出し側が `AWSService` の `ecs-tasks.amazonaws.com` | `issued_key_hash` | `responseElements.credentials.accessKeyId` | 同じ |
| 成功した `sts:AssumeRole` で、呼び出し側の `userIdentity.type` が `AssumedRole` (役割の連鎖) | `issued_key_hash` | 同上 | 新しい |
| 成功した `sts:AssumeRoleWithWebIdentity` (プロバイダを問わない) | `issued_key_hash` | 同上 | 新しい |
| 注目イベント (events に残す記録) で、`userIdentity.type` が `AssumedRole` | `session_key_hash` | `userIdentity.accessKeyId` | 0076 は秘匿値の読み取りだけ |

- **名前は分けない (`issued_key_hash` を一般化する)**。意味は「この記録が発行した認証情報のキーのハッシュ」で同じ。どの発行かは、記録の名前・主体の種類・`invoked_by`・`oidc_*` で既に分かる。
  使う側が発行の種類で絞る。secret_access は今も、主体が `ecs-tasks.amazonaws.com` の `AssumeRole` だけを引いている (`ecsIssuances`)。一般化してもその絞りで挙動は変わらない (テストで固定する)
- 2 段目の `AssumeRole` の記録には、`session_key_hash` (呼び出し側。1 段目が発行したキー) と `issued_key_hash` (2 段目が発行したキー) の両方が付く。これで 3 段目以降もたどれる (4 節)
- `session_key_hash` を秘匿値の読み取りに限らないのは、突き合わせを使う finding (5 節) の記録 (IAM の操作・監査の無効化・公開設定の変更・`AssumeRole`) に要るため。
  注目イベントの全部にしたのは、チェックごとの操作の一覧を collector に持ち込まない (一覧のずれで黙って付かない) ため。足すのは 1 記録あたり 32 桁の 1 項目で、注目イベント以外 (集計だけの記録) には残さない
- IAM ユーザー・root・SSO (`AssumeRoleWithSAML`) が呼ぶ `AssumeRole` の発行は残さない (GitHub の OIDC からの鎖の途中に現れない。残す値を増やさない)。
  ただし SSO のセッションが呼ぶ `AssumeRole` は「`AssumedRole` が呼ぶ」に当たるので残る (鎖をたどった先が OIDC でなければ 4 節で `not_oidc` になるだけ)
- `roleSessionName`・`userIdentity.arn` の後ろ (セッション名)・セッショントークン・キーそのものは残さない (0055・0076 のまま)。ハッシュは report・通知・info の data に出さない
- 保存の形・rebuild・権限は 0076 の 4 節と同じ (`events.data` の項目が増えるだけ。API の呼び出しと権限は増えない)

### 2. 突き合わせ: 同じストアの保存済みの注目イベントから、run の窓によらず引く

- 引くのは保存済みの注目イベントの `AssumeRole`・`AssumeRoleWithWebIdentity` (どちらも全部が注目イベント)。run の窓 (hourly なら 1 時間) に限らない。
  1 段目が前の時間・前の日にあっても、ストアにあれば突き合わせられる
- 時刻の範囲は、発行の種類ごとの認証情報の最長の寿命で決める。キーを使った記録の時刻を `t`、発行の時刻を `i` として:
  - 発行が `AssumeRoleWithWebIdentity`: `t - 12 時間 - 5 秒 <= i <= t + 5 秒`
  - 発行が役割の連鎖の `AssumeRole`: `t - 1 時間 - 5 秒 <= i <= t + 5 秒`
  - 5 秒は 0076 の `bulkExemptSkew` と同じ理由 (記録の時刻は秒の単位で、STS とほかのサービスの記録の時刻は別に付く)
  - キーは発行の都度 AWS が決める値なので、一致すれば発行は 1 つに決まる。範囲は誤った組を防ぐためではなく、引く量を限るためと、寿命を過ぎた (ありえない) 組を拾わないため
- 1 つの finding の窓 `[from, to)` に対して引く範囲は `[from - (12 時間 + 1 時間 × (最大の段数 - 1)) - 5 秒, to + 5 秒)` (最大の段数は 4 節)。
  引くのは、5 節の finding に `session_key_hash` のある記録が 1 つ以上あるときだけ。ECS が発行した分 (主体がサービス) は引かない
- **ストアに無い発行はたどれない**: 収集を始める前・保持の期間の外・収集していないリージョンの STS (リージョンのエンドポイントを使う呼び出しは、そのリージョンに記録される)・取りこぼし。
  遅れて届いた発行 (2 段目の記録の run の時点で 1 段目がまだ無い) も、その run ではたどれない。再走査 (ADR 0013 の `ingest_delay`) で両方が同じ run に入るのがふつう
- たどれなかった finding に、後で届いた発行で値を付け直すことはしない。3 節の値は Key と Fingerprint に入れないので、付いたか・付かなかったかで finding は new / changed にならない
  (後の run で同じ Key が recurred / changed になったときは、その時点で引き直した値が載る)

### 3. 付ける値と、信用しないこと

5 節の finding の data に、突き合わせた 1 段目 (`AssumeRoleWithWebIdentity`) の記録の値を付ける。

```json
"oidc_origins": [
  {"provider": "token.actions.githubusercontent.com", "repo": "example-org/example-repo", "sub_kind": "environment", "environment": "production",
   "run_id": "1234567", "assumed_at": "2026-11-21T01:02:03Z", "role_arn": "arn:aws:iam::123456789012:role/gha-deploy", "chain_depth": 1}
],
"oidc_origins_total": 1
```

- 1 つの要素は、1 段目の記録の `oidc_provider`・`oidc_repo`・`oidc_sub_kind`・`oidc_ref`・`oidc_environment`・`gha_run_id` (あるものだけ)、
  1 段目の引き受けの時刻 `assumed_at` (RFC 3339、UTC、秒まで) と引き受けたロール `role_arn`、`chain_depth` (4 節)。
  時刻とロールを入れるのは、9 節の次の段で、GitHub の実行の記録とそのまま突き合わせられるようにするため (1 段目の記録を探し直さずに済む)
  `oidc_owner_id`・`oidc_repo_id` は付けない (調べる手がかりには名前と実行の ID で足り、1 段目の finding で見られる)
- 1 つの finding (Key) は複数の記録をまとめるので、異なる要素の集合にし、並べ替えて上限 10 個 (`assumed_at` が要素に入るので、要素は 1 段目の引き受けの 1 回ごと)。`oidc_origins_total` は上限を超えても全部の数
- 付ける値は、付けるときにもう一度形を確かめる (`record.ParseGitHubSub` の各部分の形・`gha_run_id` は数字だけ・長さの上限)。ストアには以前の版や手で直した raw から作った値も入りうるため。
  形に合わない値はその項目だけ落とす
- **付ける値は信用できない入力として扱い、重大度・Key・Fingerprint・既知リストの判定・見出しのどれにも使わない。** 手がかりとして data に出すだけにする。
  - `run_id` は `userAgent` 由来で、呼ぶ側が自由に書ける (ADR 0055)。攻撃者は無関係な実行の ID を書ける
  - `repo`・`ref`・`environment` は GitHub が署名したトークンの `sub` から読んだ値で、`run_id` より強い。それでも、既知のリポジトリの既定のブランチの既存のワークフローを書き換える手口
    (0055 の「見えないもの」) では正規の値のまま来る。「既知のリポジトリから来たので下げる・承認する」は、この手口をそのまま通すので行わない
  - 結び付き (どの 1 段目から来たか) は AWS が発行したキーの一致で決まり、呼ぶ側は書けない。信用しないのは、結び付いた先の 1 段目の記録に書かれた値の方である
  - 見出し (`summary`) に入れないのは、通知の文面にログ由来の値を増やさないため (ADR 0037)。aratam は data を信用しない前提のまま (変えない)
- playbook には「`oidc_origins` は、GitHub の実行 (`https://github.com/<repo>/actions/runs/<run_id>`) を開いて人が確かめる手がかり。証拠ではない。`run_id` は呼ぶ側が書ける」と書く
- 個人を特定できる値は増えない (`sub` に actor は無い。セッション名は残さない)

### 4. 3 段目以降もたどる (最大 4 段まで)

- 鎖は「キーを使った記録の `session_key_hash` → それを `issued_key_hash` に持つ発行 → その発行の記録の `session_key_hash` → …」とたどり、
  `AssumeRoleWithWebIdentity` の発行に着いたら止める
- `chain_depth` は、1 段目のセッションから数えた `AssumeRole` の数。1 段目のセッションが直接呼んだ記録 (2 段目の `AssumeRole`・1 段目のロールの IAM の操作) は 0 段ではなく、
  「1 段目のセッションで呼んだ」を 1 とする: 2 段目の `AssumeRole` の記録 = 1、2 段目のセッションの IAM の操作・3 段目の `AssumeRole` = 2
- 最大は 4 (定数)。CDK の形 (1 段目 → deploy-role → その操作) は 2 で、4 はその倍の余裕。超えたらたどるのを止め、`too_deep` (6 節) にする
- 発行の時刻は使った時刻より前 (+5 秒まで) に限るので鎖は輪にならないが、念のため同じハッシュを 2 度たどらない
- たどる理由: 3 段目以降を見ないと、攻撃者が 2 段目のロールからもう 1 段乗り移るだけで手がかりが消える。たどる量は鎖の長さだけで、引く範囲 (2 節) が 1 時間ずつ延びるだけ
- CloudFormation が引き受ける実行のロール (`cfn-exec-role` など) の操作は、`AWSService` の `cloudformation.amazonaws.com` の `AssumeRole` で発行されたキーで呼ばれ、
  キーでは deploy-role に戻れない (発行を残さないので `no_issuance`)。CDK の IAM の変更の多くはこの形で、**この ADR ではたどれない** (7 節)

### 5. 付ける finding

| チェック | 付ける記録 | 理由 |
|---|---|---|
| `unknown_assume_role` | finding のまとめた `AssumeRole` の記録 (呼び出し側のセッション) | 依頼の主な対象。2 段目・3 段目の引き受けがどの実行から来たか |
| `iam_changes` | finding のまとめた IAM の操作の記録 | 0055・0056 の手口 (CI のロールから長期のキーを作る・信頼ポリシーを広げる)。CI から来たかで片付け方が変わる |
| `defense_evasion` | 監査・検知を弱める操作の記録 | 同じ手口の段 (乗り移った先で CloudTrail を止める)。high で、来た道が要る |
| `public_exposure` | 公開設定の変更の記録 | 同上。デプロイによる正規の変更と、それ以外の区別の手がかり |

- どれも注目イベントの記録を Key ごとにまとめる event 型で、1 節の `session_key_hash` が記録にあり、付け方が同じ (1 つの共通の関数)
- 付けないもの:
  - `oidc_assume_role`: 1 段目そのもので、値は既に data にある
  - `secret_access`: 0076 の突き合わせを持ち、data が既に多い。手がかりの要る形 (CI の秘匿値の読み取り) は、実際の記録で困っている例を見てから足す
  - `access_denied`: 主体 × 種類の数を平常帯と比べ、拒否の記録が多い。引く量に見合うかを確かめてから
  - `new_principal`・`principal_new_source`: 日次の集計から作り、記録が無い
  - `ecs_exec`: GitHub の実行からの `ExecuteCommand` の形を見ていない
  
  どれも同じ関数で後から足せる (足すときは設計書の「決定:」で足りる。重大度は変えないため)

### 6. たどれなかったことも data に出す (ただし、OIDC に関わる finding だけ)

- 項目: `oidc_origin_unmatched` (理由ごとの記録の数。0 の理由は書かない)
  - `no_key`: 記録に `session_key_hash` が無い (呼び出し側が `AssumedRole` でない・キーが空や形の外・以前の版で集めた記録)
  - `no_issuance`: 2 節の範囲に、そのハッシュの発行がストアに無い
  - `not_oidc`: たどった先の発行が ECS の `AssumeRole` (サービスが発行した。鎖の根が OIDC でない)
  - `too_deep`: 4 節の最大を超えた
- 出すのは、次のどちらかのときだけ:
  - (a) 同じ finding に、たどれた記録が 1 つ以上ある (一部だけたどれた形。同じロールが GitHub の実行と、それ以外の両方から使われた手がかり)
  - (b) たどった鎖の上のロール (記録の主体と、途中の発行の呼び出し側のロール) のどれかが、2 節の範囲で `AssumeRoleWithWebIdentity` の `role_arn` になっている
    (OIDC の入り口のロールのセッションなのに、1 段目が見つからない。収集の抜けか、入り口のロールの認証情報が鎖の外で使われた手がかり)
- どちらでもないとき (人の SSO のセッションなど、OIDC に関わらない finding) は出さない。人の SSO のセッションの発行 (`AssumeRoleWithSAML`) は残さないので、
  出すと、ほとんど全部の finding に `no_issuance` が付き、読む量だけが増えるため
- (b) の「入り口のロール」も 3 節と同じく判定に使わない。data に出すだけ
- 移行: 以前の版で集めた記録にはハッシュが無い。上げた直後は `no_key` / `no_issuance` が (a)(b) の条件を満たす finding にだけ出る。重大度は変わらないので、鳴る数は増えない

### 7. 見えないもの (引き受ける)

- CloudFormation の実行のロールの操作 (4 節)。CDK の IAM の変更・公開設定の変更の多くは、CloudFormation が自分で引き受けたロールで行われ、キーでは deploy-role に戻れない。
  deploy-role の `CreateChangeSet` / `ExecuteChangeSet` とスタックで結ぶ形は、キーのような AWS の 1 対 1 の値が無く、時刻と名前の推測になるので、この ADR では入れない (次の候補)
- 収集していないリージョンの STS で入った場合 (2 節)。`no_issuance` で分かるのは 6 節の条件を満たすときだけ
- `accessKeyId` が記録に無い・空の場合 (背景の 2)。`no_key`
- GitHub の側で何が起きたか (どのワークフローのファイル・どのコミット)。0055 のとおり `job_workflow_ref` は記録に無い。`run_id` から人が GitHub を見る

### 8. ファズテストと文書 (ADR 0041・0025・0058)

ファズで次の規則を固定する。

- `normalizeRaw`: 出力の `data` に `ASIA` で始まる認証情報の形の文字列が現れない。`issued_key_hash` は 1 節の 3 つの発行の記録にだけ、`session_key_hash` は `userIdentity.type` が
  `AssumedRole` の記録にだけ現れ、どちらも 16 進 32 桁 (**0076 の 7 節の「`session_key_hash` は秘匿値の読み取りにだけ現れる」の規則を、この規則で置き換える**。1 節で `session_key_hash` を残す記録を広げるため。0076 のほかの節は変えない)
- 鎖をたどる関数 (任意のハッシュ・時刻・種類の発行と記録の組): 必ず止まる。`chain_depth` は 1〜4。付く要素は `AssumeRoleWithWebIdentity` の発行の値だけで、
  どの段も発行の時刻が 2 節の範囲に入る。付く値は 3 節の形に合う。たどれた記録とたどれなかった記録の数の和は、finding の記録の数と一致する
- 付ける finding の Key・Fingerprint・重大度・見出しが、`oidc_origins` の有無で変わらない (チェックごとのテスト。値を書き換えた記録で同じ結果になる)

文書:

- playbook: `unknown_assume_role.md`・`iam_changes.md`・`defense_evasion.md`・`public_exposure.md` に `oidc_origins`・`oidc_origin_unmatched` の読み方と、
  「証拠ではなく手がかり。`run_id` は呼ぶ側が書ける。既知のリポジトリから来ても、それだけで片付けない」を足す。`oidc_assume_role.md` に、2 段目以降の finding から 1 段目へ戻れることを足す
- `docs/ai/index.md` (data の項目)・`docs/design.md` 6 章 (collector の残す値の決定、突き合わせの決定)・`docs/threats.md` と `docs/ai/threats/wfx-loot-2026-11.md` の
  「乗り移り」の段の注記 (承認済みでないときに出る high に、来た実行の手がかりが付く。承認済みなら出ないのは変わらない)

### 9. 次の段 (この ADR では実装しない): GitHub の記録と突き合わせて、知らないアカウント・実行からの利用を見る

目的: OIDC で引き受けられたロールが、知らない GitHub のアカウントや実行から使われていないかを知る。特に、枝の制限が無い environment の `sub` で信頼するロール
(`repo:<repo>:environment:<名前>`。どの枝のワークフローからでも、その environment を名乗れる) で知りたい。
乗っ取られた正規のアカウントは見分けられないので対象外にする。

形 (案。今は決めない): 3 節の `oidc_origins` の 1 つの要素 (`repo`・`environment`・`ref`・`run_id`・`assumed_at`) を、GitHub の API の値と次の 3 点で突き合わせる。

1. 実行 (Actions の runs) のリポジトリと environment が、`sub` (GitHub が署名した値) と合う
2. 1 段目の引き受けの時刻 (`assumed_at`) が、その実行の開始から終了の間にある
3. その environment の、その時刻の Deployments の記録がある (ワークフローからは書き換えられない)。`run_id` は、同じ時刻に記録が複数あるときに見分けるためにだけ使う

合わなければ「`run_id` を偽った疑い」(呼ぶ側が書ける値を偽った) とする。合えば、実行の actor・triggering_actor・head_branch・head_sha・workflow を
「誰が・どの枝・どのコミットで」の手がかりとして 2 段目以降の finding に付ける。

この ADR が次の段のために揃えるもの: 2 段目以降の finding の data の要素ごとに、1 段目の `repo`・`environment`・`ref`・`run_id` と `assumed_at` が揃う (3 節)。
次の段は、この要素をそのまま GitHub と突き合わせればよく、AWS 側の突き合わせ (1〜4 節) は変えずに済む。

次の段に要るもの (どれも今は決めない):

- GitHub の API を読む新しい収集元。今の arata は AWS (と、そのログ) だけを読む (ADR 0001 の責務、設計書 8 章の権限)
- 読み取りのトークン (権限の範囲・置き場所・更新)、読んだ値のストアへの保存の形 (保持の期間・rebuild・actor は GitHub のハンドルで、レポートに個人を特定できる値を書かない決まりとの関係)
- 合わないときの重大度と、GitHub の API が読めないときの扱い (鳴る側か)

**次の段に進むには、利用者 (オーナー) の判断が要る。** arata の読む範囲を AWS から GitHub に広げる判断で、秘密 (トークン) と権限が増え、
「AWS のログの定期監査」という arata の範囲 (README・設計書 1 章) を変えるため。判断が出たら新しい ADR で決める。

検討して採らなかった形 (次の段の検討に使う):

- **`sub` に `actor_id` を入れる** (GitHub の OIDC の `sub` のカスタマイズ): 全部のロールの信頼ポリシーを直すことになり、人の入れ替えのたびに直す手間がある
- **`role-session-name` に actor・run_id を入れる**: 枝の制限が無いロールでは、ワークフローを書き換えれば偽れる (下の「検討した選択肢」の 1 つ目も参照)

## 検討した選択肢

- **`role-session-name` に actor と run_id を入れてもらい、`roleSessionName` を残す**: 利用者のワークフローを全部直す必要があり、CDK が引き受ける 2 段目のセッション名は CDK が決める。
  値は呼ぶ側が書けるので、`run_id` と同じく信用できない。何より「`roleSessionName` は残さない」(人の値が入りうる) を変える。却下
- **セッションタグ・`sourceIdentity` を 2 段目へ引き継がせる**: 呼ぶ側の設定 (ワークフロー・信頼ポリシーの `sts:TagSession` など) を利用者に求め、値は呼ぶ側が書く。
  arata は読み取りだけで、利用者の設定を前提にしない形を選ぶ。却下 (使っている利用者がいれば、記録の形を確かめてから別に足せる)
- **名前を分ける (`oidc_issued_key_hash`・`chain_issued_key_hash` など)**: 発行の種類は記録の別の項目で分かり、名前を分けても使う側の絞りは要る。項目が増えるだけ。却下
- **キーそのものを残す**: 0076 のとおり、突き合わせには一致だけが要る。却下
- **ロールと時刻だけで結ぶ (1 段目でロール X を引き受けた後、1 時間以内に X が呼んだ `AssumeRole`)**: 同じロールを使う実行が重なると、どの実行かを決められない。
  盗まれた X の認証情報が外で使われた形も、近い時刻の正規の実行に結び付けてしまう (誤った手がかりを付ける)。却下
- **呼び出し側の `sessionContext.webIdFederationData` (プロバイダの名前) を使う**: 公式文書の例ではプロバイダの ARN が入るが、`sub` も実行の ID も入らず、どの実行かは分からない。
  実際の記録の形も確かめていない。「OIDC 由来のセッション」の印として 6 節の (b) を置き換えうるので、記録で確かめてから次の候補にする。今回は入れない
- **突き合わせを run の窓の中だけにする**: hourly の run では、1 段目が前の時間にあるのがふつうで、ほとんどたどれない。却下
- **範囲を一律 12 時間にする**: たどれる組は同じだが、役割の連鎖の発行 (最大 1 時間) を 12 時間まで探すと、ありえない組 (寿命の後の利用) も結んでしまう。発行の種類ごとの寿命にした
- **3 段目以降をたどらない (2 段目だけ)**: 1 段乗り移るだけで手がかりが消える (4 節)。CDK の deploy-role のセッションの操作も 2 段目のセッションの操作で、たどらないと付かない。却下
- **たどれなかったことを常に出す**: 6 節のとおり、人のセッションの finding のほとんどに `no_issuance` が付く。却下。**常に出さない**: 一部だけたどれた形と、入り口のロールなのにたどれない形
  (どちらも調べる価値がある) を見落とす。却下
- **たどれた 1 段目が既知 (`oidc_entrances` で承認済み) なら重大度を下げる・info にする**: 3 節のとおり、既知のリポジトリの既存のワークフローの書き換えを通す。
  利用者が毎回の片付けに困っているのは事実だが、片付けの判断は人が `run_id` で GitHub を見て行う形にとどめる。下げる形は、この ADR の値を使った運用を見てから、新しい ADR で判断する。今回は却下

## 結果 (良い点・引き受けるコスト)

- `unknown_assume_role` の high (2 段目・3 段目の引き受け) と、そのセッションの `iam_changes`・`defense_evasion`・`public_exposure` に、どのリポジトリの・どの ref / environment の・
  どの実行から来たかの手がかりが付く。人は `run_id` から GitHub の実行を開いて確かめられる (CloudTrail を見比べる手間が減る)
- 結び付きは AWS が発行したキーの一致で決まり、`roleSessionName` を残さない決まりを守る
- 判定は変えない (重大度・Key・Fingerprint・見出し)。付ける値を信用しない前提を、規則とテストで固定する
- 引き受けるコスト:
  - collector の残す値が増える (`issued_key_hash` の 2 種類の発行、`session_key_hash` は `AssumedRole` の注目イベントの全部に。1 記録 32 桁)。ストアの量は注目イベントの数に比例して少し増える
  - 4 つのチェックが、finding にハッシュのある記録があるとき、過去 最大 15 時間 (12 + 1 × 3) の `AssumeRole*` の注目イベントを引く。引き受けの多いアカウントでは読む量が増える
  - CloudFormation 経由の変更はたどれない (7 節)。CDK の IAM の変更の多くはこれで、手がかりは付かない
  - 上げる前に集めた記録はたどれない (`no_key` / `no_issuance`)。保存の形・スキーマ (finding の `data` は型を決めていない。ADR 0054) は互換
- 実装: `record` (変えない。`SessionKeyHash` を使う)・cloudtrail collector (1 節)・`internal/checks` の共通の関数 (2〜4・6 節) と 4 つのチェック・ファズ・playbook と文書 (8 節)。
  権限・設定は増えない (既定値も無い。ADR 0014 の `config init --diff` に出るものは無い)

# oidc_assume_role: OIDC でのロールの引き受け (GitHub Actions など)

## この指摘の意味

OIDC のトークンでのロールの引き受け (`AssumeRoleWithWebIdentity`) を、(プロバイダ, sub, ロール) の組にまとめ、
既知リストの `oidc_subjects` (既知の入り口) と比べる (hourly)。GitHub Actions のトークンは sub からリポジトリと、ブランチ・タグ / environment / pull_request を読む。

- **high** 既知のロールに、既知リストに無い入り口から (`role_known: true`)。知らないリポジトリ・ブランチ・environment・プロバイダ
- **medium** どの項目にも無いロール (`role_known: false`)。導入直後は、今ある入り口の数だけ出る
- **medium** 入り口は既知だが、項目に書いた時間帯 (`hours`)・送信元 (`source_ips`) の外 (`reasons` に `outside_hours` / `unexpected_source`)
- **low / medium** 入り口は既知だが、その日の回数が平常帯を超えた (Key が `volume:` で始まる。`reasons: above_baseline`)
- **low** 上の high / medium で、引き受けが全部失敗 (`denied: true`)。信頼ポリシーなどが止めた試行
- **info** 既知の入り口からの引き受けを報告しなかった記録 (Key が `known:<ロールの ARN>`)。対応は要らない

読み方の注意:

- **どのワークフローのファイルからかは分からない。** CloudTrail の記録にトークンの `job_workflow_ref` は残らない。
  既定のブランチの既存のワークフローを書き換える手口は、既知の入り口のままなので、ここでは見つからない (回数の外れと、入った後の操作で見る)
- **失敗した引き受けの記録にはロールが無い** (`role_recorded: false`。Key のロールの部分は `-`)。CloudTrail の失敗の記録は `requestParameters` が空で、
  どのロールを試したかは分からない。見出しは入り口 (sub) で書かれる。`entrance_known: true` なら、その入り口は既知リストのどれかの項目にある (一時的な失敗の可能性)
- `coverage.notes` の「以前の版の arata が集めた … 記録 N 件を見ていない」は、プロバイダと sub を残す前に集めた記録。finding にはならない (版を上げた直後だけ出る)
- `sub_form: unparsed` は sub が決まった形でない (sub の形をカスタマイズしたリポジトリを含む)。値は残していないので、リポジトリは CloudTrail で確かめる
- `sub_form: not_read` は GitHub 以外のプロバイダ (EKS のサービスアカウント、Cognito など)。sub は読まず、(プロバイダ, ロール) の組で見る
- ID 入りの sub (`repo:example-org@1234567/example-repo@7654321:…`) は ID を外して比べる。ID は `owner_id` / `repo_id` (複数あれば `owner_ids` / `repo_ids`)。
  同じ名前で ID が複数あるなら、組織・リポジトリの名前の付け替えか取り直しがあった
- `run_ids` は userAgent にあった GitHub Actions の実行の ID。**呼ぶ側が書ける値**なので、証拠ではなく手がかりとして使う
- 引き受けた後のロールの活動は別のチェック (new_principal・principal_new_source・iam_changes・secret_access など) が見る。主体はロールの ARN

- Key は `<プロバイダ>|<sub。読めなければ unparsed、GitHub 以外は ->|<ロールの ARN。失敗の記録で無ければ ->`
- data: `provider`、`provider_account`、`role_arn`、`repo`、`sub_kind` (ref / environment / pull_request)、`ref`、`environment`、`sub_form`、`reasons`、
  `role_known`、`role_recorded` (false のときだけ)、`entrance_known`、`allowlist_status` (unknown / expired / approved)、`count`、`ips`、`run_ids`、`has_errors`、`denied`、`outside_count`。
  平常帯の行は `date`・`count`・`baseline_median`・`threshold`。info の行は `subjects`・`subjects_total`

## まず確かめること

1. `arata review --format json` で、同じロール (`role_arn`) が主体の finding (iam_changes・secret_access・access_denied・unknown_assume_role・new_principal) を探す。
   引き受けの後に操作があれば、まとめて 1 つの話として書く
2. 入り口が何か: `repo` と `ref` / `environment` を、リポジトリの管理者に確かめる。そのブランチ・environment からこのロールを使う予定があったか
3. ロールの信頼ポリシー: `aws iam get-role --role-name <ロール名> --query Role.AssumeRolePolicyDocument`。
   `token.actions.githubusercontent.com:sub` の条件が、リポジトリとブランチ / environment まで絞っているか (`repo:example-org/*` や条件なしは広すぎる)
4. CloudTrail の記録: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity --start-time <first_time> --end-time <last_time>`。
   `userIdentity.userName` が sub、`responseElements.credentials.accessKeyId` が一時キー
5. 引き受けた後の操作: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<一時キー>`
6. GitHub の側: `run_ids` があれば `https://github.com/<repo>/actions/runs/<run_id>` の実行と、そのコミット・ワークフローの変更履歴を人に見てもらう
7. `denied: true` なら引き受けは成功していない。同じ入り口の成功が別の時間帯に無いかを 4 で確かめる。ロールが記録に無いときは、6 のワークフローの実行で、どのロールを指定していたかを見る

## 判断の分かれ目

- **正規の可能性が高い**: 新しく足したワークフロー・ブランチ・environment で、リポジトリの管理者が把握している。導入直後の medium (今ある入り口)
- **要対応**: 管理者の知らないリポジトリ・ブランチから既知のロールに入れた (high)。信頼ポリシーが意図より広い。引き受けの後に、アクセスキーの作成・
  信頼ポリシーの変更・秘匿値の読み取り・別のロールへの引き受け・拒否の急増がある。回数が平常帯を大きく超え、対応するデプロイが無い
- 失敗だけ (`denied`) は、誰かがそのロールを試した記録。ロールの ARN は秘密ではないので単独では弱い兆候だが、信頼ポリシーの確認は勧める

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (侵害の疑い): ロールの発行済みのセッションを失効する (IAM > ロール > 対象の `Revoke sessions`)。信頼ポリシーの sub の条件を正規の入り口だけに絞る。
   GitHub の側で、不審なワークフローの実行を止め、アカウントのトークンを失効する。引き受けの後に作られたアクセスキー・変えられた信頼ポリシーを元に戻す
2. **既知リストに足す**: 正規の入り口なら、人が allowlist.yaml の `oidc_subjects` に項目を書く (`arata approve` は対応していない)。
   data の `provider`・`role_arn`・`repo` と、`ref` (→ `refs`) / `environment` (→ `environments`) / pull_request (→ `pull_request: true`) を写し、`note` を書く。
   形の確認は `arata config check`。次の run で finding は解消される (`resolved_reason: known_oidc_subject`)。PR で直す運用は `arata help ai approve`

   ```yaml
   oidc_subjects:
     - provider: token.actions.githubusercontent.com   # GitHub 以外は provider と role (と note) だけ
       role: arn:aws:iam::123456789012:role/gha-deploy  # ロールの ARN (完全一致)
       repo: example-org/example-repo                   # 完全一致 (glob は書けない)
       refs: ["refs/heads/main"]                        # refs (glob 可)・environments (完全一致)・pull_request: true のどれか 1 つ以上
       note: 本番のデプロイ                               # 必須。hours: ["18:00-19:00"] (UTC)・source_ips: [CIDR]・expires は任意
   ```
3. **ack / snooze**: 既知リストに書けないもの (`sub_form: unparsed`)、正規と確かめた 1 回の回数の外れは ack。期間の決まった作業は snooze
4. **設定の修正**: 信頼ポリシーの sub の条件をブランチ / environment まで絞る。environment に承認を付ける。ロールの権限を最小にする。
   ロールを `principals` に `dynamic_source: true` で承認する (principal_new_source の送信元の指摘を減らす。入り口は既知にならない)

## やってはいけないこと

- 入り口を確かめずに `refs: ["*"]` や広い glob を提案しない (同じリポジトリのどのブランチからでも入れることを既知にする)
- 「既知の入り口だから正規」と書かない。既定のブランチのワークフローが書き換えられていても、入り口は同じに見える
- `run_ids`・userAgent を証拠として書かない (呼ぶ側が書ける)
- ロールを `principals` で承認して済ませない (入り口は既知にならず、この指摘は止まらない)
- 信頼ポリシーの変更・セッションの失効を LLM が実行しない

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats wfx-loot-2026-11`: ジョブの OIDC のトークンで、リポジトリが使うロールを引き受ける段階 (出典はスクリプトの機能として書く。既知の入り口のままなら出ない)

# 承認 (approve) の判断基準

## 原則

- approve は allowlist.yaml を書き換え、以後その主体を報告しなくなる。**LLM は実行せず、人に提案するだけ**にする
- 提案には次を書く: finding の `id`、承認の対象 (`arata review --format json` の `approve`)、承認してよい理由、期限を付けるか、タグ
- 人が実行するコマンドの例を添えてよい:
  `arata approve <id> --note "<理由>" [--expires YYYY-MM-DD] [--tag deploy|ai] [--by <承認者>]`
- `--commit` を付けると allowlist.yaml だけを git commit する。push とレビューは人が行う

## allowlist.yaml を PR で直す運用

定期実行が GitHub Actions (ストアは S3) で、allowlist.yaml の変更は PR でレビューする運用では、`arata approve` を使わない。
approve は追記と同時にストアの finding を resolved にするので、PR がマージされる前に finding が消えてしまう。代わりに allowlist.yaml を直す PR を作る。
PR は提案で、承認するのは差分を見てマージする人 (上の原則と同じ)。LLM が PR を作ってよいのは、人に頼まれたときだけ。

1. `principals` の末尾に項目を足す。ほかの行 (コメント・順序・空行) は変えない。1 つの PR には 1 つの判断だけを入れる

   ```yaml
     - arn: arn:aws:iam::123456789012:role/Deploy   # arn / account / arn_pattern のどれか 1 つ (下の各節の基準で選ぶ)
       note: GitHub Actions のデプロイロール          # 承認の理由 (必須と考える)
       approved_by: alice                            # 承認する人 (頼んだ人)。LLM 自身を書かない。分からなければ PR で尋ねる
       approved_at: 2026-11-09                       # 今日 (UTC)
       expires: 2027-03-31                           # 任意。期限付き承認の基準は下
       tags: [deploy]                                # 任意。語彙は下
   ```

2. `arata config check -c <arata.yaml>` を実行し、`ng` と `warn` (同じ主体の重複、行き先の重複・期限切れ) が無いことを確かめる (AWS にもストアにも繋がない)
3. PR の本文に、finding の `id`・承認の対象・承認してよい理由 (下の目安に照らして) を書く。ARN やアカウント ID を、リポジトリの外 (公開の場所) に書かない
4. 人が差分を見てマージする。次の run が、一致する finding を allowlisted として解消する (resolve は要らない)。
   行き先 (`assume_destinations`。下の「行き先を既知にする」) を足したときは、外向き・MFA ありの finding が known_destination として、OIDC の入り口 (`oidc_subjects`。書き方は `arata help ai playbook oidc_assume_role`) を足したときは、その入り口の finding が known_oidc_subject として解消する (ack 済みのものも)

主体の承認ではないもの (下の「approve ではなく ack / snooze / resolve にするもの」) は PR では止まらない。ack / snooze / resolve を人に提案する。

## 承認してよい主体の目安

- 誰が・何のために使うかを説明できる (社員の switch role、CI/CD のロール、運用委託先、SaaS 連携)
- 送信元 IP が業務の場所 (オフィス、CI のランナー、SaaS の公開レンジ) と整合する
- 操作の内容が役割と合っている (デプロイロールが IAM を変えるのは整合、監視 SaaS が IAM を変えるのは不整合)
- 迷う場合は承認せず、`ack` (再報告しないが未対応一覧に残る) を提案する

## SaaS 連携は account で承認する

監視 SaaS などの SaaS は、自社の AWS アカウントからクロスアカウントで AssumeRole してくる。
引き受けられた側の CloudTrail には呼び出し元のアカウント ID しか残らないので、その主体は「外部アカウント NNN」(`arn:aws:iam::NNN:root`。アカウントそのものを指す ARN) に見える。

- この形の主体 (data に `external_account`。unknown_assume_role は `caller_identity: account_only`、ほかのチェックは `principal_identity: account_only`) の finding を approve すると、`account: "NNN"` (そのアカウントの全主体) で承認される
- アカウント ID が SaaS の公式ドキュメントに載っているものと一致するかを確かめてから提案する
- 自社の別アカウント (本番 / 検証) も同じ扱い。`--account` で ARN の主体のアカウント全体を承認できる

## 行き先を既知にする (assume_destinations)

社員 (IAM ユーザー) が、受託先など別のアカウントのロールに MFA 付きでスイッチロールするのが通常業務のとき、unknown_assume_role は外向きの引き受けを
人 × ロールの組ごとに high で報告する。社員 (呼び出し元) を承認すると、その人の**知らないアカウントへの引き受けまで止まる**。代わりに行き先のアカウントを既知にする。

```yaml
assume_destinations:                # principals とは別の節。account: の意味が違う (あちらは呼び出し元)
  - account: "111122223333"         # 行き先のアカウント (12 桁)
    note: 運用を受託しているアカウント    # 必須。契約・受託の内容
    approved_by: alice
    approved_at: 2026-11-13
    expires: 2027-03-31             # 任意。契約の終わりに合わせる。roles: ["ReadOnly", "ops-*"] (任意。ロール名の glob) でロールに絞れる
```

- 報告されなくなるのは、**外向き・このアカウントのロール・MFA あり** の全部を満たす引き受けだけ。誰のものでも止まる (info の 1 行に件数が残る)。
  MFA なし・不明の引き受け、ほかのアカウントへの引き受け、内向き・内部の引き受けは今までどおり high
- 人が実行するコマンド: `arata approve <id> --destination --note "<理由>" [--expires YYYY-MM-DD] [--destination-role '<glob>'] [--by <承認者>]`。
  使えるのは unknown_assume_role の外向きで `mfa: true` の finding だけ (`arata review --format json` の `approve_destination` に行き先のアカウントが出る)。
  PR で直す運用では、上の形の項目を `assume_destinations` の末尾に足す (節が無ければファイルの末尾に作る)
- **既知にしてよい行き先の目安**: そのアカウントが何者かを説明でき (受託・保守の契約、自社の別アカウント)、ID を契約書や相手の管理者で確かめた。
  そこへのスイッチロールが複数の社員の日常の業務である (1 回きり・1 人だけなら ack で足りる)。契約に終わりがあれば `expires`、
  管理者のロールだけは毎回見たいなら `roles` で絞る
- **既知にしてはいけないもの**: 何者か分からないアカウント、個人のアカウント、監査対象のアカウントそのもの (効かない。`arata doctor` が ng にする)。
  「MFA があるから」だけを理由にしない (MFA は本人確認で、行き先の妥当性は示さない)
- **残るリスク** (提案に書き添える): MFA 済みのセッションを奪われると、既知の行き先への引き受けは本人のものと区別できず報告されない
  (principal_new_source と、行き先のアカウント側の監査で補う)。行き先の中での操作は相手の CloudTrail にしか残らない。
  契約が終わったら項目を消す (残すと、終わった後の引き受けも黙る。`arata config check` は期限切れを warn にする)

## 監査する側のアカウント (audit_account)

別のアカウントのロールが監査対象の読み取り専用ロールを引き受けて arata を動かす構成では、監査そのものが「外部アカウント NNN の AssumeRole」として記録される。

- `arata config init --audit-account NNN` が、設定に `audit_account: "NNN"` を、allowlist.yaml に `account: "NNN"` (note つき) を書く。
  監査対象を足すたびに init を使えば書き忘れない
- 設定の `audit_account` と同じアカウントからの読み取り専用ロールの引き受けが unknown_assume_role に出ていたら、allowlist の書き忘れか期限切れ。
  `arata config check` が ng で示す。承認ではなく、allowlist.yaml に `account: "NNN"` を足す PR を提案する
- `audit_account` と違うアカウントが読み取り専用ロールを引き受けていたら、正規の監査ではない。承認を提案せず、信頼ポリシーの確認を提案する
- `audit_account: none` (外から監査しない) なのに外部アカウントが読み取り専用ロールを引き受けていたら、同じく信頼ポリシーの確認を提案する
- `audit_account` に監査対象のアカウント自身の ID を書いてはいけない (`account:` がそのアカウントの全主体を承認する。`arata doctor` が ng にする)

## 外部アカウント root の見方

- 「外部アカウント NNN」は、そのアカウントの誰か (どの IAM 主体かは CloudTrail に残らない) が操作したことを表す。
  自社アカウントのルートユーザーの利用 (root_usage、critical) とは別物
- ARN の末尾の `root` は「アカウントそのもの」の意味で、**そのアカウントのルートユーザーが使われたことを表さない**。
  data の `caller_identity` / `principal_identity` が `account_only` なら、見出しのとおり「外部アカウント NNN (呼び出した主体は記録に無い)」と書き、「NNN の root」「ルートユーザー」と書かない
- 知らないアカウント ID からの AssumeRole は、ロールの信頼ポリシーが広すぎる可能性がある。承認より先に信頼ポリシーの確認を提案する

## arn_pattern の使いどころ

- 同じ役割の主体が名前を変えて増えるとき (例: `arn:aws:iam::123456789012:role/github-actions-*`)
- `*` は `/` や `:` も含む任意の文字列に一致する。広すぎるパターン (アカウント全体に近いもの) は `account:` と変わらないので避ける
- `arata approve <id> --arn-pattern '<glob>'` は、パターンが finding の主体に一致するときだけ受け付ける

## 期限付き承認の使いどころ

`--expires YYYY-MM-DD` を付けると、その日の終わりまで有効。過ぎたら expired として再報告される。

- 外部委託・契約者・一時的な調査用の主体
- 移行期間だけ残す旧ロール
- 理由を確かめきれないが業務を止められないもの (短い期限で付け、期限前に再確認する)

## tags の語彙

- `deploy`: 既知のデプロイ主体。この主体による IAM 変更 (iam_changes) を info に下げる (finding は残る)
- `ai`: 監査ロール・AI (LLM) 用の主体。ai_path_usage がこの主体の利用を主体 × 送信元 IP で毎回 info に 1 行出す (自己監査。いつもと違う IP からの利用に人が気づけるように)
- 語彙は `deploy` と `ai` だけ。それ以外のタグは approve が拒否する

## access_denied が鳴ったとき

access_denied は allowlist で主体を承認しても止まらない (承認済みの主体でも拒否の急増は報告する)。
`--expected-denied` を付けない approve は拒否される。data の `apis` (拒否された API と件数) を見て、次のどれかを提案する。

- **想定内の拒否** (IAM の Deny を意図して入れている、権限外の API を試す運用が分かっている): `expected_denied` で主体 × API の単位で除く。
  除いた後も、想定外の API の拒否は数え続ける (乗っ取られたときの列挙は見える)
  - 主体の項目がまだ無いとき: `arata approve <id> --expected-denied 'logs:StartQuery' --expected-denied 'logs:Get*' --note "<なぜ想定内か>"`。
    finding は resolved にならず、次の run で除いて数え直す
  - 主体の項目が既にあるとき: approve は書き換えずに止まり、足す行を示す。人がその項目に `expected_denied: [...]` を手で足す
  - 書式は「サービス:操作」の glob (`apis` と同じ形。`*` は任意の文字列)。広すぎるもの (`*:*`、`iam:*` など) は列挙を隠すので避ける。
    期限を付けられる (`--expires`)。期限を過ぎたら再び数える
  - 注意: 項目を新しく作ると、その主体そのものも承認される (new_principal なども止まる)。主体の承認として妥当でないなら作らない
- **主体ごと止めたい** (権限の足りないバッチの修正待ちなど): `ack` か `snooze`。ただし ack / snooze しても、重大度が上がれば (medium → high など) 再報告される
- **説明が付かない**: 承認も ack もせず、要対処として扱う (乗っ取り・SaaS 側の侵害の疑い。`arata help ai report` の相関付け)

## principal_new_source・secret_access が鳴ったとき

どちらも承認済みの主体の悪用を見るチェックなので、approve では止まらない (主体の承認ではない)。正規と確かめられたときの止め方は、人が allowlist を手で編集する
(approve は書かない)。調べる前に提案しない。

- principal_new_source: 恒常的な拠点の送信元は `source_ips` に (`cidr` と `note`)。CI のランナーのように送信元が毎回変わる主体は、主体の項目に `dynamic_source: true`
  (low が出なくなる。書き込みが多い・新しいリージョン・拒否も出ているときの medium 以上は出る)。一時的な出張などは ack / snooze
- secret_access: 恒常的な「主体 × 秘匿値」は `secrets_access` に (`principal` と `secrets` の glob。例 `["prod/app-a/*"]`)。初出に数えなくなる (一括読み出しには数える)。
  広い glob (`*`) は初出を隠すので勧めない。一時的な読み取りは ack / snooze

## approve ではなく ack / snooze / resolve にするもの

- 主体の承認ではない finding (root_usage、login_bruteforce、probe_paths、endpoint_abuse、waf_block_trend、principal_new_source、secret_access など) は approve できない。access_denied は上の `--expected-denied` だけ
- `ack`: 確認したが allowlist に入れたくないもの。再報告しないが未対応一覧に残る。ack したときより重大度が上がったら変化 (changed) として再報告される
- `snooze --until YYYY-MM-DD`: 対処の予定が決まっているもの。期日以降に再び観測されたら新規として再報告される。期日前でも重大度が上がれば再報告される
- `resolve`: 対処が終わったもの。再び観測されたら新規として報告される。選び方の基準と導入直後に片付ける流れは `arata help ai onboarding`

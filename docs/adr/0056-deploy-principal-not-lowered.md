# 0056. 既知デプロイ主体でも、アクセスキーの作成と、信頼ポリシーを外へ広げる変更は下げない (`iam_changes`)

- 日付: 2026-11-14
- 状態: 提案

## 背景

`iam_changes` は、既知リストの `principals` で `tags: [deploy]` の主体による IAM の変更を info に下げる (ADR 0008)。
CI/CD のロールは毎日ポリシーを更新するので、medium のままでは毎回鳴るため。

2026-11 に報告された攻撃 (ADR 0055 の背景) のスクリプトは、CI の OIDC で引き受けたロールで `iam:CreateAccessKey` を呼んで長期のキーを作り、
信頼ポリシーを `"Principal": {"AWS": "*"}` に書き換える。CI のロールは `deploy` のタグを持つことが多いので、**この 2 つは今、info に下がって通知に出ない。**

## 決定

**既知デプロイ主体でも、次の変更は下げない。ほかの変更は今のまま (info)。**

| 変更 | 重大度 (既知デプロイ主体でも) |
|---|---|
| `CreateAccessKey` | medium |
| `UpdateAssumeRolePolicy` で、信頼ポリシーに、そのアカウントの外の主体がある | medium |
| `UpdateAssumeRolePolicy` で、信頼ポリシーが読めない | medium |
| `UpdateAssumeRolePolicy` で、信頼ポリシーに `*` がある | **high** (デプロイ主体でない主体も high) |
| `UpdateAssumeRolePolicy` で、読めて、`*` も外の主体も無い | info (今のまま) |

- デプロイ主体でない主体の変更は今までどおり medium (`*` だけ high に上げる)
- 下げなかったときは、data に `known_deploy_principal: true` と `not_lowered: [理由]` (`access_key` / `trust_external` / `trust_wildcard` / `trust_unreadable`) を出す。
  信頼ポリシーから読んだ値は `trust_wildcard`・`trust_external_accounts`・`trust_external_federated`・`trust_has_condition`・`trust_policy` (`ok` / `unreadable`)
- Key は変えない。1 つの Key にまとめた呼び出しの中で、いちばん重い重大度を採る。Fingerprint は今の形 (重大度を含む) のままなので、
  今まで info だった該当の finding は、次に観測されたときに重大度が上がって changed として報告される (意図どおり)
- 全部が拒否されたとき (「IAM 変更の試行 (拒否)」) の扱いは変えない (重大度はそのまま)。拒否された呼び出しは `requestParameters` が記録されないので、
  `UpdateAssumeRolePolicy` は「読めない」になり、デプロイ主体でも medium になる

### 信頼ポリシーの読み方 (`requestParameters.policyDocument`。ログ由来の値)

- 収集のとき (cloudtrail の collector) に読み、**判定に使う値だけ** を残す (文書そのものは残さない)。チェックは残した値と、記録を受け取ったアカウント
  (`recipient_account`。無ければ呼び出した主体のアカウント) を比べる
- 見るのは `Effect: Allow` の Statement の `Principal` だけ (`Statement` は 1 つでも配列でも読む)
  - `"Principal": "*"`、`"AWS": "*"` (配列の中も) → `*`
  - `AWS` の値が 12 桁のアカウント ID か、IAM / STS の ARN → そのアカウントを取り出す。自アカウントでなければ「外の主体」
  - `Federated` の値が自アカウントの `oidc-provider/`・`saml-provider/` の ARN でなければ「外の主体」(`cognito-identity.amazonaws.com` など)
  - `Service` (AWS のサービス) は外の主体に数えない
  - 上のどれでもない値 (消えた主体の ID、知らないキー、`NotPrincipal`) がある、JSON として読めない、大きすぎる → 「読めない」
- **「読めて、`*` も外の主体も無い」と確かめられたときだけ下げる。** 読めないものを安全な側 (info) に寄せない
- **`Condition` は判定しない。** `*` に `Condition` (組織の ID など) を付けて絞る書き方はあるが、条件が実際に絞っているかを規則で決められない。
  `Condition` の有無は data (`trust_has_condition`) に出し、重大度は high のまま。正規のものは ack する (重大度が上がれば再報告される)
- 解釈する関数にファズテストを足す (ADR 0041)。守る規則: パニックしない、取り出すアカウントは 12 桁の数字だけ、
  `*` を含む Allow の文書を「`*` なし」と読まない、読めない文書を「ok」と読まない、同じ入力で同じ結果

## 検討した選択肢

- **`deploy` のタグをやめる (全部 medium に戻す)** — 却下。毎日のポリシーの更新が medium で鳴り、ADR 0008 の前に戻る
- **`CreateAccessKey` を high にする** — 却下 (この版では)。デプロイで IAM ユーザーとキーを作る構成は実在する。medium で通知に出れば、人が見られる。
  長期のキーの棚卸しは `credential_hygiene` が週次で見る
- **下げない操作を設定で選べるようにする** — 却下。守りを設定で外せる形にしない (この 2 つは攻撃の手口そのもの)。正規のものは ack で片付く
- **外のアカウントが `principals` の `account:` で承認済みなら下げる** — 却下。`account:` は「呼び出し元として既知」で、
  信頼ポリシーに足してよいかは別の判断 (ADR 0047 と同じ理屈)。data に外のアカウントを出すので、人が見て ack できる
- **`Condition` を読んで、絞られた `*` を下げる** — 却下。条件のキーと演算子の組み合わせが多く、読み違えると `*` を見逃す
- **文書をそのまま events に残して、チェックで読む** — 却下。残す値を識別子に絞る今の方針 (collector の `extractDetail`) に合わせる。
  ポリシーの全文は大きく、ログ由来の値を広く持ち回ることになる
- **`CreateRole` の信頼ポリシー (`assumeRolePolicyDocument`) も見る** — この ADR では扱わない。`CreateRole` は今 `iam_changes` の対象外で、
  足すと「`*` や外の主体を信頼するロールの作成」という新しい指摘になる。同じ読み方が使えるので、次の候補にする

## 結果 (良い点・引き受けるコスト)

- CI のロールが奪われて、長期のキーを作る・信頼ポリシーを広げる、が通知に出る。毎日のポリシーの更新 (Attach / Put) は今までどおり info
- デプロイで IAM ユーザーのキーを作る・別のアカウントを信頼するロールを更新する構成では、そのたびに medium が出る (Key ごとに 1 回。ack で片付く)
- `UpdateAssumeRolePolicy` の記録から、判定に使う値を新しく残す。以前に集めた記録には無いので、rebuild で作り直した古い記録は「読めない」になる
  (デプロイ主体でも medium。下げすぎない側)
- ADR 0008 の「既知デプロイ主体の IAM 変更は info」を、上の表の変更について置き換える
- 残るリスク: `CreateRole` で最初から広い信頼ポリシーのロールを作る (上のとおり対象外)。`Attach*Policy` / `Put*Policy` で権限を広げる (デプロイ主体なら info のまま)

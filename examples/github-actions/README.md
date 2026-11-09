# GitHub Actions で定期実行する

サーバーを持たずに arata と aratam を定期実行する見本です。[arata-audit.yml](arata-audit.yml) を自分のリポジトリの `.github/workflows/` に写して使います。
実行環境は毎回消えるので、ストアは S3 に置きます (README「S3 ストア」、ADR 0034)。ここの値はすべて架空です。

```
schedule → OIDC で実行用ロール ┬→ 読み取り専用ロールへ連鎖 → 監査対象 (読むだけ)
                               └→ ストアのバケット (読み書き)
         → arata run → aratam notify → Slack
```

S3 ストアを含む arata の版 (v0.4.0 以降) が要ります。

## 用意するもの

設定ファイルを置くリポジトリは **非公開** にしてください。allowlist にはアカウント ID や ARN が入り、Actions のログもリポジトリを読める人に見えます。

### 1. OIDC プロバイダ

監査を動かすアカウントに `token.actions.githubusercontent.com` のプロバイダを作ります (対象者は `sts.amazonaws.com`)。アカウントに 1 つだけで、既にあれば作り直しません。

### 2. ストアのバケット

バージョニング・既定の暗号化・パブリックアクセスブロックを有効にします。できれば監査対象とは別のアカウントに置きます。

### 3. 実行用ロール

信頼ポリシーは 1 つのリポジトリと 1 つのブランチに絞ります。`sub` は `StringEquals` で完全に一致させ、`repo:example-org/*` のようなワイルドカードは使いません。

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:example-org/example-audit:ref:refs/heads/main"
      }
    }
  }]
}
```

定時実行は既定のブランチでだけ動くので、`main` が既定なら上のとおりです。
GitHub の environment で承認や secrets を分けるなら、ジョブに `environment: audit` を足し、`sub` を `repo:example-org/example-audit:environment:audit` にします (`sub` の形が変わるので、ブランチの条件は効かなくなります)。

権限は次の 3 つの文だけです。

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123456789012:role/arata-readonly" },
    { "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::example-arata-store/example/*" },
    { "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::example-arata-store" }
  ]
}
```

`s3:ListBucket` は `s3:prefix` の条件を付けません。S3 は `ListBucket` の無い主体に、無いキーを 404 ではなく 403 で返します。arata は 404 だけを「無い」とみなすので、403 になると初回の run が `STORE_UNAVAILABLE` で止まるおそれがあります。見えるのはキーの名前だけなので、バケットは arata 専用にしてください。

### 4. 監査対象の読み取りロール

[deploy/iam/readonly-role.yaml](../../deploy/iam/readonly-role.yaml) の `TrustedPrincipalArn` に実行用ロールの ARN を指定します。ストアへの権限は足しません。

実行用ロールの `AssumeRole` は CloudTrail に残るので、allowlist に足さないと `unknown_assume_role` が毎回報告します。

```yaml
principals:
  - arn: arn:aws:iam::123456789012:role/example-arata-runner
    note: GitHub Actions の実行用ロール
    approved_at: 2026-11-04
    dynamic_source: true   # ランナーの送信元は毎回変わる (ADR 0027)
```

### 5. 設定ファイル

`arata/` に `arata.yaml`・`aratam.yaml`・`allowlist.yaml` を置きます (任意で `llm.context_file` のファイル)。

```yaml
# arata/arata.yaml
store: s3://example-arata-store/example   # ワークフローの ARATA_STORE_URL と同じ値
aws:
  region: ap-northeast-1
  profile: arata-audit                    # ワークフローが書くプロファイル。監査の読み取りはこのロールで行う
# store_profile は書かない。ストアは標準の連鎖 (実行用ロール) で書く
```

バケットを別のロールで書くときだけ、ワークフローの AWS の設定に `[profile arata-store]` (`role_arn` と `credential_source = Environment`) を足して `store_profile: arata-store` と書きます。`credential_source` は `role_arn` なしでは使えません。

```yaml
# arata/aratam.yaml (抜粋)
max_age: 26h
on_quiet: short            # 死活監視を兼ねるので silent にしない
llm:
  provider: none           # bedrock なら実行用ロールに bedrock:InvokeModel を足す。claude-cli は実行環境に入っていない
slack:
  webhook_env: ARATAM_SLACK_WEBHOOK
  urgent_webhook_env: ARATAM_SLACK_URGENT_WEBHOOK
```

### 6. Secrets

| 名前 | 中身 |
|---|---|
| `ARATA_RUNNER_ROLE_ARN` | 実行用ロールの ARN |
| `ARATA_AUDIT_ROLE_ARN` | 読み取り専用ロールの ARN |
| `ARATAM_SLACK_WEBHOOK` | 通常用の Webhook |
| `ARATAM_SLACK_URGENT_WEBHOOK` | 緊急用の Webhook |

### 7. 初回の収集は手元で

`arata init` は数時間かかることがあり、ワークフローの認証の期限 (1 時間) を超え得ます。手元で同じ `arata.yaml` を使って実行してください。

```sh
# ~/.aws/config に同じ名前の arata-audit のプロファイルを用意し、ストアを書ける認証を標準の連鎖で渡す
AWS_PROFILE=example-store-writer arata doctor -c arata/arata.yaml
AWS_PROFILE=example-store-writer arata init -c arata/arata.yaml
```

`store: s3://` のまま実行するので、結果はそのままバケットへ置かれ、次のワークフローの run が続きから動きます。実行できたら `workflow_dispatch` で 1 回動かして確かめます。

## 失敗したとき

| 起きたこと | Slack | ジョブ |
|---|---|---|
| 新規なし | 通常用に 1 行 (`on_quiet: short`) | 成功 |
| 一部のソースが取れない (arata の終了コード 3) | 取れた分の報告を緊急用に | 失敗 |
| `STORE_CONFLICT`・`INTERRUPTED`・設定の誤り・OIDC の失敗など | 「arata の出力が無いか古い」を緊急用に | 失敗 |
| バイナリの取得の失敗、checkout の失敗 | 届かない | 失敗 |

`STORE_CONFLICT` は再実行で解消します (手元の `arata ack` と重なったときなど)。走らなかった窓は次の run が引き直します。

**ログには原因の詳細を出しません**。Actions に出るのは `level`・`code`・`source` と終了コードだけです。`msg` と `error` には ARN やアカウント ID が入り得るためです。詳細は手元で同じコマンドを実行して確かめます。
`::add-mask::` で値を列挙して隠す方式は採りません。監査の結果に何が出るかは列挙できないからです。アカウント ID はロールの ARN を secrets に置くことと `mask-aws-account-id: true` で隠します。

## 死活監視

毎日の Slack で足ります。`on_quiet: short` なら何も無い日も 1 行届くので、**届かなければ止まっています**。上の表の「届かない」場合も、GitHub の定時実行が止まった場合も、これで気づけます。

## 詳しい内容の置き場所

Slack に載らない詳細はストアのバケットの `reports/` にあります。

- `reports/<profile>.md`・`reports/<profile>.json`: 最新のレポート (arata が置く)
- `reports/waf-proposals.md`: WAF の提案の全文 (ワークフローの最後の step が置く)。Slack に出るパスは消えた実行環境のものなので、こちらを見ます。バージョニングで過去の版も残ります

Actions の artifacts はリポジトリを読める人に見えるので使いません。

## 費用の目安

| 項目 | 目安 |
|---|---|
| Actions | 1 回 1〜3 分として月 34 回で 100 分ほど。非公開リポジトリでも GitHub Free の無料枠 (月 2,000 分) に収まる。分単位で切り上げ |
| Logs Insights | 使うときの主な費用。`arata doctor` の `cost` の行に 1 日・30 日の概算が出る (東京 0.0076 USD/GB)。`max_scan_gb` を必ず設定する |
| Cost Explorer | `cost-anomaly` のソースを使うと 1 リクエスト 0.01 USD。1 回の run で 2 回ほどなので月 1 USD 未満 |
| S3 | SQLite の gzip と raw の出し入れだけで、ふつうは僅か |

単価は改定されるので、最新の価格は各サービスの料金表で確かめてください。

## 注意

- **定時実行は遅れます**。GitHub の負荷が高いと遅れ、落ちることもあります。監査の窓は実行時刻から決まるので、遅れても次の run が続きから引きます
- **定時実行は止まることがあります**。公開リポジトリでは、活動が 60 日無いと定時実行が無効になります。ワークフローを最後に編集した人が組織から外れた場合も止まることがあります。Slack が届かなくなったら Actions の画面を見てください
- **時刻の変更**: weekly の `cron` を変えたら、`PROFILE` の式の文字列も揃えます (`github.event.schedule` を文字列で比べているため)
- **Action の更新**: この見本の SHA は写した時点で固定されます。自分のリポジトリの Dependabot で更新してください
- **取得の照合の限界**: `SHA256SUMS` は同じリリースのものなので、壊れた取得は防げてもリリース自体のすり替えは防げません。arata が公開リポジトリになったら `gh attestation verify` を足せます (README「来歴の検証」)

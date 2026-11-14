# env-extortion-2024-08: 公開された .env から得たアクセスキーで、管理者のロールを作り、S3 のデータを消して身代金を求める

## 概要

- 公開日: 2024-08-15
- Web アプリが誤って公開していた `.env` のファイルから IAM のアクセスキーを集め、その AWS 環境に入った攻撃。Unit 42 が被害の環境の調査として報告した
- 規模: `.env` を取られたドメインが 11 万以上。漏れた値のうち、クラウドのアクセスキーが約 7,000
- 入った後は、権限の確認、管理者権限のロールの作成、全リージョンへの Lambda 関数の配置 (ほかのドメインの `.env` を集める踏み台)、S3 のデータの持ち出しと削除、身代金の要求の順
- 偵察と Lambda の作成は Tor、S3 の操作は VPN からと出典は書く

## 出典

- Palo Alto Networks Unit 42 "Leaked Environment Variables Allow Large-Scale Extortion Operation in Cloud Environments" (2024-08-15): https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/

## 攻撃の段階と arata で見えるもの

| 攻撃の段階 | 出典の書き方 | arata のチェック | 記録 | 出るもの |
|---|---|---|---|---|
| 初期の侵入: 公開された `.env` を大量のドメインから探して取る | 観測 | `probe_paths` | アクセスログ (http_access): `/.env` への 403 / 404 | 探索が IP ごとの平常帯を超えれば low。**当たった取得 (200) は数えない** |
| 発見: 権限と中身を確かめる (`GetCallerIdentity`、`ListUsers`、`ListBuckets`、SES の読み取り) | 観測 | `principal_new_source`, `new_principal` | CloudTrail: 漏れたキーの主体の API 呼び出し | 既知の主体が新しい送信元から使われて low (読み取りだけで、成功している間)。主体が既知リストにもベースラインにも無ければ、主体の初出として medium |
| 権限の昇格: ロールを作り (`CreateRole`)、`AdministratorAccess` を付ける (`AttachRolePolicy`) | 観測 | `iam_changes`, `principal_new_source` | CloudTrail: `AttachRolePolicy` | iam_changes は medium (`policy_arn` に付けたポリシー)。`CreateRole` だけでは出ない。新しい送信元からの書き込みが下限以上なら principal_new_source が medium |
| 実行: EC2 での採掘の準備 (セキュリティグループ、キーペア、`RunInstances`) は失敗 | 観測 | `access_denied`, `unused_region_activity` | CloudTrail: 拒否された呼び出し | 拒否が主体の平常帯を超えれば medium か high。ふだん使わないリージョンでの `RunInstances` の失敗は medium |
| 実行: Lambda 関数を作り、有効な全リージョンへ配る | 観測 | `unused_region_activity`, `principal_new_source` | CloudTrail: `CreateFunction` (各リージョン) | ふだん使わないリージョンでの計算資源の作成で critical。書き込みをしていなかったリージョンでの書き込みで principal_new_source が medium |
| 持ち出しと破壊: S3 のオブジェクトを取り出して消し、身代金の文書を置く | 観測 | — | S3 のデータイベント (`GetObject`、`DeleteObject`) | 見えない (arata が読むのは管理イベント。出典も、この記録は既定で有効でないと書く) |

## arata では見えないもの

- **`.env` が実際に取られたこと**: `probe_paths` が数えるのは 403 / 404 だけ。200 で返したリクエストは「探索」に数えない。公開していないことは別に確かめる
- **S3 のオブジェクトの読み出しと削除**: データイベントは arata の読む記録 (CloudTrail の管理イベント) に無い。S3 のサーバーアクセスログも読まない
- **ロールを作っただけの段階**: `CreateRole` は `iam_changes` の対象外。ポリシーを付けた時点で出る
- **漏れたキーが、正規の利用と同じ送信元の帯から使われた場合**: `principal_new_source` は /24 (IPv6 は /48) の単位で見る
- 攻撃者の側の基盤 (集めた `.env` の置き場、ほかの被害者)

## 予定している改善

無し。

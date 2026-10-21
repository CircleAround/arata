# 0008. 既知デプロイ主体は allowlist の principals に `tags: [deploy]` で表す

- 日付: 2026-10-21
- 状態: 採用

## 背景

設計書 7 章の `iam_changes` は「medium (既知デプロイ主体なら info)」と定めているが、
「既知デプロイ主体」をどこで宣言するかは決まっていなかった。CI/CD のロール (GitHub Actions の OIDC ロール、
CodeBuild のロールなど) は毎日 IAM ポリシーを更新するので、medium のままでは毎回鳴る。

## 決定

- allowlist.yaml の `principals[].tags` (文字列の配列、任意) を追加する。
- `tags` に `deploy` を含み、かつ承認が有効 (expires 前) な主体による IAM 変更は severity を `info` に下げる。
  finding は作る (根拠として `known_deploy_principal: true` を Data に残す) が、`info` セクションに回り summary には数えない。
- タグの語彙は今のところ `deploy` のみ。後続のチェック (`ssm_session` の運用主体、`ai_path_usage` の AI 用主体など) も
  同じ仕組みで `ops` / `ai` のようなタグを足す想定。

## 検討した選択肢

- allowlist に `deploy_principals:` のような専用セクションを足す: 主体ごとの情報が 2 か所に散り、expires の扱いも二重になる。却下
- config.yaml 側に書く: 顧客ごとの git 管理の対象は allowlist なので、承認の記録と同じ場所にある方が追いやすい。却下
- 既知デプロイ主体の IAM 変更は finding 自体を作らない: 「取れていたが鳴らなかった」ことが報告から消える。
  info として残せば月次の棚卸しで見える。却下

## 結果

- allowlist の 1 エントリで「承認」と「役割」を同時に表せる
- タグ付けは人の判断 (approve 時に `--tag deploy` のような指定を後続 Step で足す)

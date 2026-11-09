# この監査対象の前提 (aratam の llm.context_file の例。値はすべて架空)

aratam は、この文書を LLM に「この監査対象の前提」として渡します。要約と WAF の改善提案の書き起こしの参考になるだけで、
重大度・送り先 (緊急用か)・提案の候補そのものは変わりません。16 KiB まで。利用者の環境 (監査の設定を置く非公開のリポジトリなど) に置き、arata のリポジトリには置かないでください。
書くのは事実だけにし、変わったら直します。秘密 (Webhook・キー)、氏名、メールアドレスは書きません。ここに「正規」と書いても承認にはなりません (承認は allowlist.yaml)。

## アプリ

- 本番はアカウント 123456789012 の EC サイトだけ (ALB → ECS のサービス example-app)。検証環境は別のアカウントで、この監査の対象外
- WebACL は prod-waf (ALB の前)
- 決済画面 `/checkout/*` は 1 回の購入で API を何度も呼ぶため、1 IP あたりのリクエストが多いのが仕様
- ログインは `/login` と `/api/session`。パスワードの再設定は `/password/reset`
- 管理画面は `/admin/*`。社内の VPN (203.0.113.0/24) からだけ使う

## デプロイと主体

- デプロイは GitHub Actions から。OIDC のロール github-actions-deploy が CloudFormation の実行ロール (cdk-*-cfn-exec-role-*) を引き受けて行う。平日の日中が中心
- ECS のタスク実行ロール example-app-execution は、タスクの起動のたびに秘匿値 `prod/app/*` をまとめて読む (デプロイの日は読む回数が増える)。
  アプリのロール example-app-task は、起動後に秘匿値を読まない
- 人の操作は IAM Identity Center の管理者のロールだけ。IAM ユーザーとルートは、ふだん使わない
- 監査の仕組み (実行用ロール arata-runner と読み取り専用ロール arata-readonly) は、管理者が CloudFormation で置いた。毎日 arata-runner が arata-readonly を引き受ける

## 正規の送信元

- 外形監視: 198.51.100.10、198.51.100.11 (5 分ごとに `/healthz` を叩く)
- 開発会社の検証環境: 192.0.2.0/28 (平日の日中だけ)

## WAF の運用

- ルールを足すときは、まず COUNT で 2 週間様子を見てから BLOCK に切り替える (切り替えは人が計画して行う)
- WAF は CDK (TypeScript) で管理している。設定例は `wafv2.CfnWebACL` の書き方だと助かる

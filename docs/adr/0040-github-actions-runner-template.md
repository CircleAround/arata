# 0040. GitHub Actions の実行の仕組みは素の CloudFormation で配り、信頼は `sub` の完全一致に絞る

- 日付: 2026-11-09
- 状態: 採用

## 背景

GitHub Actions で arata を定期実行するには、動かす側のアカウントに OIDC プロバイダ・ストアのバケット・実行用ロールが要る (ADR 0034、設計書 9 章)。
これまでは見本の README に信頼ポリシーと権限の JSON を載せ、手で作る手順だった。手順が長く、写し間違い (`sub` のワイルドカード、公開ブロックの付け忘れ) が起きやすい。

監査対象に置く読み取り専用ロールは、既に素の CloudFormation で配っている (`deploy/iam/readonly-role.yaml`。ADR 0020)。

## 決定

- **`deploy/github-actions/runner.yaml` (素の CloudFormation) を足す**。1 回の `aws cloudformation deploy` で次を作る
  - GitHub の OIDC プロバイダ。アカウントに 1 つしか作れないので、`OIDCProviderArn` に既存の ARN を渡せば作らない
  - ストアのバケット。バージョニング・SSE-S3・パブリックアクセスブロック・ACL の無効化・TLS 必須のバケットポリシー・古い版の期限
  - 実行用ロール。最大セッション 1 時間
- **信頼は完全一致だけ**。`StringEquals` で `aud` = `sts.amazonaws.com`、`sub` = `repo:<GitHubRepository>:ref:refs/heads/<GitHubBranch>`。
  `StringLike` を使わず、パラメータの `AllowedPattern` でワイルドカードとコロンを拒む
- **`GitHubRepository` は `sub` の `repo:` の部分をそのまま受ける**。GitHub は 2026-07-15 より後に作った (名前を変えた・移した) リポジトリの `sub` を
  `repo:owner@OWNER_ID/repo@REPO_ID:...` の形に変えた。従来の形と両方を受け付け、どちらかは利用者が指定する
- **`job_workflow_ref` は任意の条件にする** (`GitHubWorkflowRef`。既定は空)。
  AWS の文書は GitHub 固有の条件キーとして `job_workflow_ref` を挙げている (ほかに `repository`・`repository_id`・`ref`・`environment` など。2026-11-09 に確認)。
  GitHub の文書はこのクレームを「再利用ワークフローを使うジョブでの、そのワークフローへの参照」と定め、ふつうのワークフローでの値は定めていない。
  既定で足すと、文書に無い挙動に定時の監査が依存する。指定すれば、同じリポジトリの同じブランチの別のワークフローからは引き受けられなくなる
- **権限**: ストアの `s3:GetObject`・`s3:PutObject` (prefix の下)・`s3:ListBucket` (バケット)、`AuditRoleArns` (一覧) への `sts:AssumeRole`。ほかは付けない
- **Bedrock は任意** (`BedrockInferenceProfileArn`。既定は空で、何も足さない)。aratam の `provider: bedrock` は Converse を 1 回ずつ呼ぶだけなので、足すのは `bedrock:InvokeModel` だけ。
  推論プロファイルを呼ぶには、プロファイル自身と、それが振り分ける先の各リージョンの基盤モデルの両方に権限が要る (AWS の文書。グローバルのプロファイルはリージョンが空の ARN も要る)。
  基盤モデルの側は `Resource` を `foundation-model/*` にし、`bedrock:InferenceProfileArn` の完全一致で「そのプロファイルを通した呼び出し」に絞る。
  監査対象の読み取り専用ロールには足さない
- **残すもの**: バケットとバケットポリシーは `Retain`。OIDC プロバイダも `Retain` (アカウントで共有され、ほかのロールが後から使い始め得る)
- **手順は 2 つの `deploy`**: 先に実行の仕組み (監査ロールの ARN は名前から決まるので、まだ無くてよい)、次に読み取り専用ロール (`TrustedPrincipalArn` に実行用ロール)。
  同じアカウントを監査するときも、別のアカウントのときも同じ
- **検査**: Go のテストが YAML を読み、信頼の条件・パラメータの拒否・権限 (doctor の `store_actions` と一致)・`Retain`・公開ブロックを固定する。
  実機 (開発用のアカウント) で `validate-template` と deploy を確かめる。CI では AWS に接続しない

## 検討した選択肢

- **CDK**: sandbox は CDK だが (ADR 0020)、配る先のアカウントに `cdk bootstrap` (専用のバケットと複数のロール) を要る。
  監査のために置くものを最小にしたいので却下。読み取り専用ロールと同じ考え
- **Terraform のモジュール**: 利用者に Terraform と状態の置き場所を求める。AWS CLI だけで済む CloudFormation にした
- **README の JSON を残して手で作る**: 写し間違いが起き、守りをテストで固定できない。「テンプレートを使わない場合」として要点だけを残し、定義は写さない
- **読み取り専用ロールも同じテンプレートに入れる**: 同じアカウントなら 1 コマンドになるが、別のアカウントでは使えず、テンプレートが 2 通りになる。
  信頼先の実行用ロールが先に要るという順序も 1 つのスタックでは隠れる。分けたままにした
- **`sub` をリポジトリの単位で許す (`repo:owner/repo:*`)**: プルリクエストやほかのブランチのワークフローからも引き受けられる。却下
- **`sub` の代わりに `repository_id` と `ref` の条件キーで絞る**: ID は名前の変更に強い。ただし IAM は GitHub の信頼ポリシーに `sub` の条件を必須にしており、
  `sub` の完全一致で足りる。条件を二重にすると利用者が調べる値が増える。採らない
- **`job_workflow_ref` を必須にする**: 上のとおり、ふつうのワークフローでの値が文書で保証されていない。実際のトークンで確かめるまで任意にする
- **OIDC プロバイダを常に作る / 常に既存を使う**: 前者は既にあるアカウントで失敗し、後者は初めてのアカウントで手作業が残る。パラメータで選ぶ
- **OIDC プロバイダをスタックと一緒に消す**: 作った後に別のロールが使い始めていると、スタックの削除でそれらが止まる。残す
- **SSE-KMS**: 鍵の権限と費用が増える。arata の推奨は「SSE-S3 か SSE-KMS」なので、既定は SSE-S3
- **実行用ロールに `s3:GetBucketVersioning` などを付ける (doctor の推奨の確認用)**: ワークフローは doctor を実行しない。手元の doctor は別の認証で動く。付けない
- **Bedrock の基盤モデルの ARN をパラメータで列挙させる**: 文書の例はこの形だが、利用者が振り分け先のリージョンを調べて並べることになり、AWS が振り分け先を足すと通知の要約が止まる。
  条件キーで絞れば、許す範囲は同じ (そのプロファイル経由だけ) で列挙が要らない。却下
- **Bedrock の権限を常に付ける / モデルを絞らない**: 使わない利用者にも権限が付く。漏れたトークンで任意のモデルを呼べ、費用が出る。却下
- **`bedrock:InvokeModelWithResponseStream` も付ける**: aratam は使わない。付けない
- **cfn-lint を CI に足す**: Python の依存が増え、待機期間の検査 (ADR 0017) の対象も増える。守りたい性質は Go のテストで見ている。足さない
- **複数のアカウントで、アカウントごとに secret を分けて `secrets[format(...)]` で選ぶ**: 式で動的に選ぶと、ジョブにすべての secrets が渡る。
  1 つの secret に JSON でまとめ、step の中で取り出して隠す
- **複数のアカウントで、GitHub の environment ごとに secret を分ける**: `sub` が `environment` の形に変わり、ブランチの条件が使えなくなる。却下

## 結果

- 良い点: 用意が 2 つのコマンドになる。信頼の条件と権限の範囲がテストで固定され、利用者が広げにくい。複数のアカウントを 1 つのリポジトリで監査できる
- 引き受けるコスト: スタックを消してもバケットと OIDC プロバイダが残り、片付けは手作業になる。
  リポジトリの `sub` の形 (ID の有無) は利用者が調べて指定する。実行用ロールは 1 つなので、複数のアカウントのストアを権限では分けない (分けたいときはリポジトリごと分ける)。
  GitHub の environment を使う構成は、このテンプレートの対象外。
  GitHub からの実際の引き受け (`job_workflow_ref` の値を含む) と、Bedrock の実際の呼び出しは、この ADR の時点では確かめていない (IAM のシミュレーションまで)

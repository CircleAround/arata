# wfx-loot-2026-11: 乗っ取った GitHub アカウントから CI の秘密を盗むスクリプトを push する ("wfx-loot")

## 概要

- 公開日: 2026-11-12
- 2026-11-10 から、盗まれた GitHub の認証情報を使って、多数のリポジトリに CI の秘密を盗むシェルスクリプトが push された。
  入れ方は、既存のワークフローへの追記、使い捨ての枝のワークフロー、`package.json` の postinstall フックなど
- 規模 (Aikido): 乗っ取られたアカウント 4,837、下調べの PR が約 6.1 万リポジトリ、スクリプトが動いた形跡が少なくとも 1,806 リポジトリ
- GitGuardian は 2026-10-24 からの先行する動きを追い、ワークフローを書き換える形は GitHub が承認待ちで止め、postinstall フックの形が実行されたと書く
  (公開のログ 19 リポジトリで実行、うち 18 でスクリプトが送信の成功を報告)
- **AWS に関する記述は、どちらの出典も「スクリプトにその機能がある」という説明**。被害者の AWS アカウントで起きたと観測した、とは書いていない
- 2026-10 の GhostAction (`arata help ai threats ghostaction-2026-10`) と被害のアカウントが重なるが、出典は別の攻撃者の別の攻撃と見ている

## 出典

- Aikido "wfx-loot campaign pushes CI secret stealer to tens of thousands of repositories" (2026-11-12): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories
- GitGuardian "wfx-loot: A CI Secret Stealer Pushed With Stolen GitHub Credentials" (2026-11-13): https://blog.gitguardian.com/wfx-loot-a-ci-secret-stealer-pushed-with-stolen-github-credentials/

## 攻撃の段階と arata で見えるもの

| 攻撃の段階 | 出典の書き方 | arata のチェック | 記録 | 出るもの |
|---|---|---|---|---|
| 初期の侵入: GitHub の認証情報を手に入れる (方法は出典に無い) | 観測 | — | 無し | 見えない (GitHub の中) |
| GitHub での準備: 下調べの PR、ワークフロー・フックの書き換え、実行、実行の記録の削除 | 観測 | — | 無し | 見えない (GitHub の中) |
| 認証情報の収集: secrets・vars、プロセスのメモリ、認証情報のファイル、self-hosted のランナーではクラウドのメタデータ | 機能 | — | 無し | 見えない (ランナーの中) |
| 外への送信: 攻撃者のサーバーへの HTTP POST (後に Telegram) | 観測 | — | 無し | 見えない (ランナーの通信) |
| AWS での利用: ジョブの OIDC のトークンで、リポジトリが使うロールを引き受ける | 機能 | `oidc_assume_role`, `new_principal` | CloudTrail: `AssumeRoleWithWebIdentity`、そのロールの API 呼び出し | 既知リストの `oidc_subjects` に無い入り口 (リポジトリ・ブランチ・environment) からなら、既知のロールは high、どの項目にも無いロールは medium。**既知の入り口のまま (既定のブランチの既存のワークフローの書き換え) なら出ない**。その日の回数が平常帯を超えたときだけ low か medium。CI のロールが既知リストにもベースラインにも無ければ、ロールの初出が medium |
| 権限の昇格: 見つけた別のロールへ乗り移る (セッションタグ付きの `AssumeRole`) | 機能 | `unknown_assume_role`, `new_principal` | CloudTrail: `AssumeRole` | 呼び出し元の CI のロールが承認済みでなければ high。承認済みなら出ない (今の抜け)。乗り移った先のロールが既知でなければ、その初出が medium |
| 永続化: IAM ユーザーを列挙し、最大 2 人に長期のアクセスキーを作る | 機能 | `iam_changes` | CloudTrail: `CreateAccessKey` | medium。変更した主体が既知デプロイ主体 (`tags: [deploy]`) でも下げない |
| 永続化: 乗り移った先のロールの信頼ポリシーを、どの AWS アカウントからでも引き受けられる形に書き換える | 機能 | `iam_changes`, `access_analyzer` | CloudTrail: `UpdateAssumeRolePolicy`。Access Analyzer の検出 | iam_changes は、信頼ポリシーが誰でも (`*`) を許す形なら high、外のアカウントを足す形なら medium (どちらも既知デプロイ主体でも下げない。ロールを作るときの信頼ポリシーも同じ)。access_analyzer は公開として high (weekly。Access Analyzer が有効なとき。最大 1 週間遅れる) |
| 後日の利用: 作ったキーを攻撃者の環境から使う、開いたロールを外のアカウントから引き受ける | 想定 | `principal_new_source`, `unknown_assume_role`, `new_principal` | CloudTrail: その主体の API 呼び出し、`AssumeRole` | 既知の IAM ユーザーが新しい送信元から使われて low、書き込みがあれば medium、拒否の急増が重なれば high。外部アカウントからの引き受けは high (内向き) |

## arata では見えないもの

- **GitHub の中の動き** (PR、ワークフローとフックの書き換え、実行、実行の記録の削除): arata が読むのは AWS の記録だけで、GitHub の監査ログは読まない
- **外への送信**: GitHub が用意する実行環境の通信は、利用者の AWS のどの記録にも残らない。self-hosted のランナーでも、arata は VPC フローログを読まない
- **OIDC の引き受けが、どのワークフローからか**: CloudTrail の `AssumeRoleWithWebIdentity` の記録に、トークンの `job_workflow_ref` は残らない。正規のワークフローと、書き換えられたワークフローを区別できない。
  `oidc_assume_role` が比べるのは sub にある単位 (リポジトリと、ブランチ・タグ / environment / pull_request) まで
- **CI と同じロール・同じ実行環境からの操作**: 主体も送信元の帯も正規の CI と同じなので、`principal_new_source` では区別できない (CI のロールは `dynamic_source` にしていることが多い)
- **AWS 以外に効く秘密** (GitHub のトークン、パッケージの公開用のトークン、ほかのクラウド): 盗まれても AWS の記録に現れない
- どの段階も、出典が AWS の側で観測した記録ではない。上の表は「スクリプトが書かれた通りに動いたら」の対応

## 予定している改善

- 承認済みのロールからの乗り移り (CI のロールから、初めてのロールへの `AssumeRole`) を見ること (予定。まだ決めていない。ADR 0055 に次の候補として書いてある)

# credential_hygiene: 認証情報の衛生

## この指摘の意味

IAM の認証情報レポートから、漏れたときに被害が大きい認証情報を報告する (weekly、状態型。直れば resolved)。

- `unused_key|<ユーザー>|<番号>` (medium): 有効なアクセスキーが `unused_days` (既定 90) 日を超えて使われていない (使われていなければ作成・ローテーションから)。
  使っていないキーは消し忘れで、漏れても気づきにくい
- `no_mfa|<ユーザー>` (medium): コンソールのパスワードがあるのに MFA が無い
- `root_access_key|<番号>` (high): ルートユーザーに有効なアクセスキーがある
- data: `user`、`arn`、`key`、`last_used`、`last_rotated`、`days_unused`、`password_last_used`、`report_generated_at` (レポートの作成時刻。最大 4 時間ほど古いことがある)

## まず確かめること

1. `arata review --format json` で同じユーザーの new_principal・access_denied・iam_changes を探す (使われていないはずのキーが急に使われ始めたら重い)
2. キーの最終使用: `aws iam get-access-key-last-used --access-key-id <キー ID>` (`LastUsedDate`・`ServiceName`・`Region`)。キー ID は `aws iam list-access-keys --user-name <ユーザー>`
3. 最新の状態: `aws iam generate-credential-report` は書き込み系なので LLM は呼ばない。`aws iam get-credential-report` で既存のレポートを読む (CSV が base64 で返る)
4. MFA: `aws iam list-mfa-devices --user-name <ユーザー>`。コンソールは IAM > ユーザー > 対象 > セキュリティ認証情報
5. ルートのキー: `aws iam get-account-summary` の `AccountAccessKeysPresent`。ルートのキーの最終使用はルートでサインインしてセキュリティ認証情報の画面で見る
6. キーの持ち主と用途 (どのバッチ・誰の端末か) を利用者の事情から確かめる。分からなければ人に聞く

## 判断の分かれ目

- **急がなくてよい**: 年に 1 回のバッチなど、使う予定が分かっているキー。MFA が付けられない理由が分かっている (ただし例外として記録する)
- **要対応**: ルートのアクセスキー (用途があっても無くす方向)。持ち主の分からないキー。使っていないはずのキーが最近使われた (`last_used` が新しいのに用途が分からない)。
  管理者権限のユーザーに MFA が無い

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (不審な使用がある): キーを無効化する (`aws iam update-access-key --user-name <ユーザー> --access-key-id <キー> --status Inactive`)。ルートのキーはルートでサインインして無効化・削除する
2. **承認**: 対象外
3. **expected_denied**: 対象外
4. **ack / snooze**: 対処の予定が決まっていれば `arata snooze <id> --until YYYY-MM-DD`。意図して残す (例外として記録済み) なら ack
5. **設定の修正**: 使っていないキーは「無効化 → しばらく様子を見る → 削除」の順で消す。MFA を登録する (IAM のポリシーで MFA なしの操作を拒否する方法もある)。
   長期のアクセスキーは、IAM Identity Center・ロール・OIDC などの一時的な認証情報に置き換える

## やってはいけないこと

- 使用中かを確かめずにキーの削除を勧めない (止まるバッチがある)。まず無効化を勧める
- LLM が `generate-credential-report` やキーの変更を実行しない
- レポートやキーの情報から、ユーザーの氏名・メールアドレスを推測して書かない (主体は ARN で書く)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats ghostaction-2026-10`: リポジトリの履歴に残った古いアクセスキーが盗まれる。使っていないキーを先に消す備え

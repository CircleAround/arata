# ghostaction-2026-10: 乗っ取った GitHub アカウントに「Security Audit」のワークフローを足し、secrets と履歴の認証情報を送る (GhostAction)

## 概要

- 公開日: 2026-10-07
- 2025 年から続く攻撃の 2026 年の波。乗っ取った GitHub アカウントで、監査を装った名前のワークフローをリポジトリに足す
- ワークフローは、名前を決め打ちした secrets に加えて、作業ツリーと git の全履歴を正規表現で探し、見つけた認証情報を 1 つのサーバーへ HTTP で送る。
  AWS のアクセスキー ID は、対になる秘密の値を得るために前後の行ごと送る (後の版で追加)
- 規模 (GitGuardian): 2026-08-31 から 09-30 に公開リポジトリ 772、2026-10-08 から 09 に 3 万以上。GitHub は 10-09 から実行を止めた
- StepSecurity は 10-08 の 345 リポジトリの波を追い、実行のログに攻撃者のサーバーの応答が残っていたと書く
- **盗んだ AWS のキーが AWS で使われたとは、どちらの出典も書いていない**
- 2026-11 の wfx-loot (`arata help ai threats wfx-loot-2026-11`) と被害のアカウントが重なる

## 出典

- GitGuardian "The campaign that never stopped: tracking GhostAction from 2025 to 2026" (2026-10-07。10-09 と 10-13 に追記): https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/
- StepSecurity "GhostAction Returns: Malicious "Security Audit" Workflows Now Mine Credentials from Entire Git Histories" (2026-10-09): https://www.stepsecurity.io/blog/ghostaction-returns

## 攻撃の段階と arata で見えるもの

| 攻撃の段階 | 出典の書き方 | arata のチェック | 記録 | 出るもの |
|---|---|---|---|---|
| 初期の侵入: メンテナーの GitHub の認証情報を手に入れる (漏れたトークンなどと出典は見ている) | 推定 | — | 無し | 見えない (GitHub の中) |
| GitHub での準備: 監査を装ったワークフローを足し、push で実行させる | 観測 | — | 無し | 見えない (GitHub の中) |
| 認証情報の収集: 決め打ちの secrets、作業ツリーと全履歴の認証情報 (AWS のアクセスキー ID と前後の行を含む) | 機能 | — | 無し | 見えない (ランナーの中)。履歴に残った古いキーも対象になる |
| 外への送信: 攻撃者のサーバーへの HTTP POST | 観測 | — | 無し | 見えない (ランナーの通信) |
| 事前の備え: 履歴に残りがちな、使っていない長期のアクセスキーが有効なまま | 想定 | `credential_hygiene` | IAM の認証情報レポート | 有効で長く使われていないキーが medium、ルートのアクセスキーは high (weekly)。盗まれる前に消す材料 |
| AWS での利用: 盗んだアクセスキーを攻撃者の環境から使う | 想定 | `principal_new_source`, `access_denied` | CloudTrail: その主体の API 呼び出し | 既知の IAM ユーザーが新しい送信元から使われて low、書き込みがあれば medium、拒否の急増が重なれば high (休眠していたキーは `active_in_baseline: false`)。権限の列挙で拒否の種類が平常帯を超えれば medium か high |
| AWS での利用: ふだん使わないリージョンで資源を作る | 想定 | `unused_region_activity` | CloudTrail (ふだん使わないリージョン) | 成功した書き込みは high、計算資源の作成は critical |

## arata では見えないもの

- **GitHub の中の動き** (ワークフローの追加・実行): arata は GitHub の監査ログを読まない
- **外への送信**: GitHub が用意する実行環境の通信は、利用者の AWS の記録に残らない
- **リポジトリの履歴に認証情報が残っていること**: arata はリポジトリを読まない (`log_hygiene` が数えるのは CloudWatch Logs の行だけ)
- **盗まれたこと自体**: キーが AWS で使われるまで、AWS の記録には何も現れない。使われ方が正規の利用と同じ送信元・同じ操作なら、使われても出ない
- **AWS 以外に効く秘密** (SSH の鍵、ほかのクラウド、SaaS のトークン)
- 「AWS での利用」の行は出典に無い。盗まれたキーが使われたら、という想定

## 予定している改善

無し。OIDC の引き受けの見張りなど、同じ系統の攻撃に向けた予定は `arata help ai threats wfx-loot-2026-11` に書いた。

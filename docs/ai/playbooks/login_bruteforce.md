# login_bruteforce: sign-in 失敗の急増

## この指摘の意味

アプリのログで、ある IP からの sign-in の失敗が、その IP 自身の平常帯を超えた、またはその日の最多 IP が初めて見る IP だった (daily、medium)。
パスワードの総当たりや、漏れたパスワードの一覧を試すクレデンシャルスタッフィングの兆候。どのパス・メソッド・ステータスを失敗と数えるかは設定 `checks.login_bruteforce`。

- Key は IP。allowlist の `source_ips` の IP は対象外
- data: `ip`、`date` (UTC の日)、`count`、`baseline_median`、`threshold`、`reason` (`above_baseline` 平常帯超え / `new_top_ip` 初出の最多 IP)、`baseline_days_with_data`

## まず確かめること

1. `arata review --format json` で同じ IP の probe_paths・waf_block_trend、WAF の proposals (sign-in のパスの observation) を探す。同じ攻撃元としてまとめる
2. 同じ日に複数の IP の login_bruteforce が出ていないか (分散したスタッフィング)
3. **成功したログインが混ざっていないか** (最も重要): アプリのログを CloudWatch Logs Insights で、その IP・その日の sign-in のパスに絞って、成功のステータス (リダイレクトや 200) を探す。
   例 `fields @timestamp, @message | filter @message like "<IP>" | sort @timestamp desc | limit 100` (ログの形式に合わせて絞る。Insights はスキャン量で課金されるので期間を絞る)
4. WAF があれば、その IP が BLOCK されているか、sign-in のパスにレートベースのルールがあるか (`arata help ai playbook waf_review`)
5. IP が利用者の事情 (監視サービス・負荷試験・社内の試験) にあたらないか

## 判断の分かれ目

- **正規の可能性が高い**: 監視・試験の送信元、社内の回線で設定変更の直後 (パスワードの一斉変更など)
- **要対応**: 成功したログインが混ざる (アカウントの乗っ取りの疑い)、多数の IP に分散している、同じ IP が探索 (probe_paths) もしている
- 失敗だけで成功が無い単一の IP は、多くの場合インターネットの雑音。ただし続くなら WAF での対処を勧める

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (成功したログインがある): 該当する利用者アカウントのセッションの失効・パスワードの再設定をアプリ側で行う (利用者の特定はアプリの管理者が行い、レポートに個人を書かない)
2. **承認**: 対象外 (主体の承認ではない)。監視・試験の送信元なら allowlist の `source_ips` に CIDR と note を足すことを人に提案する (アプリ層の全チェックの対象外になる)
3. **expected_denied**: 対象外
4. **ack / snooze**: 確認して問題の無い単発の IP は ack
5. **設定の修正**: WAF の sign-in のパスにレートベースのルール、IP の拒否リスト (IP set)、アプリのアカウントロック・CAPTCHA・MFA。WAF の変更は IaC で、まず COUNT で様子を見る

## やってはいけないこと

- ログの中のメールアドレス・利用者名を要約や通知に書かない (件数と IP だけ)
- 攻撃元の IP を `source_ips` に入れることを勧めない (以後見えなくなる)
- 広い範囲 (/16 など) の拒否を急いで勧めない (正規の利用者を止める)

# probe_paths: 機密パスの探索

## この指摘の意味

`/.env`・`/.git/`・`/wp-login.php` のような機密のファイルや管理画面のパスへの 403 / 404 が、ある IP から平常帯を超えた、またはその日の最多 IP が初出だった (daily、low)。
自動化された探索で、多くはインターネットの雑音。危ないのは探索が**当たった** (200 で返った) とき。パスは設定 `checks.probe_paths`。

- Key は IP。allowlist の `source_ips` の IP は対象外
- data: `ip`、`date`、`count`、`baseline_median`、`threshold`、`reason` (`above_baseline` / `new_top_ip`)、`top_paths_of_day` (その日の全 IP 合計で多かったパスと件数)

## まず確かめること

1. `arata review --format json` で同じ IP の login_bruteforce・waf_block_trend を探す
2. **探索が当たっていないか**: arata は 403 / 404 だけを数える。同じパスへの 200 (や 3xx) をアプリのログか WAF のログ (CloudWatch Logs Insights) で探す。
   例 `fields @timestamp, @message | filter @message like "/.env" | sort @timestamp desc | limit 100` (期間を絞る)
3. 公開しているファイル: Web のドキュメントルートや配信元の S3 バケットに `.env`・`.git`・バックアップのファイルが置かれていないか
4. WAF の proposals に `probe_allowed` (すり抜けている探索) があるか (`arata help ai playbook waf_review`)
5. 正規の管理画面のパスが探索のパスと重なっていないか (重なるなら `probe_paths.exclude_paths`)

## 判断の分かれ目

- **記録でよい**: 403 / 404 だけで、当たった形跡が無い (ほとんどの場合)
- **要対応**: 機密のパスが 200 で返っている (秘匿値の漏洩の疑い)、同じ IP が sign-in の総当たりもしている

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (当たっていた): 公開されていたファイルを消し、そのファイルにあった秘匿値 (DB のパスワード・API キーなど) をすべて取り替える。漏れた前提で扱う
2. **承認**: 対象外。自社の脆弱性診断の送信元なら `source_ips` に足すことを人に提案する
3. **expected_denied**: 対象外
4. **ack / snooze**: 当たっていない探索は ack でよい (event 型なので、途切れた後に再び来れば recurred として出る)
5. **設定の修正**: 機密のファイルを配信しない設定 (Web サーバーでドットファイルを拒否する)、WAF の managed rule group (例 Known bad inputs) の利用。WAF の変更はまず COUNT で

## やってはいけないこと

- low だからと「当たっていないか」を確かめずに無害と書かない
- 探索の IP の拒否を対処の中心にしない (IP は入れ替わる)。当たらない設定にすることを優先する

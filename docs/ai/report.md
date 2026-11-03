# report.json の読み方と要約の手順

## report.json の構造

```json
{
  "profile": "daily", "window": {"from": "...", "to": "..."}, "name": "acme", "run_id": "...",
  "summary": {"new": 3, "changed": 1, "recurred": 0, "resolved": 2, "still_open": 7, "max_severity": "high", "collect_errors": []},
  "findings": {"new": [], "changed": [], "recurred": [], "resolved": [], "still_open": []},
  "already_reported": [],
  "info": [],
  "coverage": {"sources_ok": [], "sources_failed": [], "checks_run": [], "checks_skipped": [], "formats": []}
}
```

- finding 1 件: `id`, `check`, `key`, `severity`, `summary`, `status`, `first_seen`, `last_seen`, `data` (根拠。件数・IP・日付など)
- `summary.max_severity`: new / changed / recurred の最大。still_open は含まない
- `already_reported`: 別の周期 (hourly など) で報告済みの事象。二重に騒がない
- `info`: 重大度 info (既知デプロイ主体の IAM 変更など)。記録のみ
- `coverage.sources_failed`: 取れなかったソースと `code`、不足した `action`。`covered_from` / `covered_until` は取れた期間。
  `partial: true` は一部の項目だけ取れなかった (取れた項目で評価済み。取れなかった項目は前回の状態のまま)
- `coverage.checks_skipped`: 走らなかったチェックと理由 (必要なソースが無い / 失敗)
- `coverage.formats`: アプリログの解釈率 (`match_rate`、`code` が FORMAT_MISMATCH / FORMAT_DRIFT のこともある)

## 読む順序

1. `summary` で件数と最大重大度を掴む
2. `coverage` で取れていなかったものを確認する。失敗したソースやスキップしたチェックがあれば「静かだから平和」とは書かない
3. `findings.new` → `changed` → `recurred` → `resolved` → `still_open` の順に読む

## 要約の手順

要約は日本語で、次の順に書く。

1. **新規**: 何が・どこから・どの主体で起きたか。重大度の高い順
2. **変化**: 前回から何が変わったか (送信元 IP の増加など)
3. **再発**: しばらく途切れていた事象が再び起きた
4. **解消**: 解消した指摘
5. **未対応**: still_open の件数と、長く残っているもの
6. **取れなかったもの**: coverage の失敗・スキップ・解釈率の問題。対処方法 (`arata help ai` の code 表) を添える

## 相関付け

個々の finding を横断して読み、同じ主体・同じ IP・近い時刻のものをまとめる。

- 新規主体 + 国外 IP + 秘匿値取得が同じ主体なら、1 件のインシデント候補として書く
- unknown_assume_role の呼び出し元と new_principal が同じなら 1 つの話としてまとめる
- login_bruteforce / probe_paths / waf_block_trend の IP が重なれば、同じ攻撃元の可能性として書く
- access_denied (拒否された API 呼び出しの急増) は権限の列挙の兆候。同じ主体の new_principal・unknown_assume_role・iam_changes (拒否) と合わせて 1 つの話として書く。
  data の `apis` (拒否された API と件数)・`threshold` (`breadth` = 種類が多い、`volume` = 同じ API の件数が多い)・`allowlist_status` を根拠にする。
  `breadth` は乗っ取りや侵害の疑い、`volume` だけなら設定ミスのアプリの可能性が高い
- access_denied は allowlist で承認済みの主体 (`allowlist_status: approved`) でも出る。承認は「その主体が居ること」を認めるもので、権限を探ってよいという意味ではない。
  承認済みの主体の列挙は乗っ取り・SaaS 側の侵害の疑いとして扱う
- allowlist のメモ、前回レポート、時間帯 (デプロイ時刻、メンテナンス時間) を踏まえる

## 分類の基準

各 finding を次の 3 つに分け、理由を根拠 (data のどの値か) 付きで書く。

- **要対処 (今動く)**: critical / high で正当な説明が付かないもの。root の利用、既知外主体の AssumeRole、
  設定不備のうち公開につながるもの。侵害の兆候が複数重なるもの
- **確認依頼 (人が判断する)**: 新規の主体や送信元で、業務上の理由があり得るもの。承認するかを人に聞く
- **情報 (記録のみ)**: info、既知の傾向の範囲の low、解消した指摘

`summary.max_severity` が high 以上のときは、LLM の分類に関係なく組み込み側が緊急通知する規則になっている。
LLM は critical / high を「情報」に格下げして沈黙させない。

## 書いてはいけないこと

- 個人特定値 (氏名・メールアドレス) を書かない。主体は ARN、外部アカウントは「外部アカウント NNN」と書く
- エンジンのログのサンプル行 (FORMAT_MISMATCH の samples) を要約に転記しない
- 推測を事実として書かない。裏取りしていないことは「可能性」と書く

## 追加の裏取り (任意)

high 以上の finding は、同じ読み取りロールで追加照会して根拠を足してよい (例: その主体の直近の CloudTrail イベント)。
追加照会は読み取りのみ。書き込み・設定変更はしない。

## 期間レポート (report --month / --from --to)

`"kind": "period"` の report.json は収集せずストアから作る月次・任意期間の集計。顧客向けの報告や棚卸しに使う。

- `notes`: 「YYYY-MM-DD 以前は状態遷移の履歴なし」など。期間の一部の件数が数えられていないことを要約の冒頭に書く
- `summary`: 期間内の new / changed / recurred / resolved の件数、`by_severity` (新規・再発した指摘の重大度別)、`open` (今の未対応)
- `events`: 状態遷移の一覧。`profile` が空の resolved は人の resolve / approve か allowlist の編集による解消
- `new_principals` / `open` / `metrics` (アプリ層の日次推移、UTC) / `runs_missing` (partial / failed / RUN_MISSED)
- 要約は「期間の概況 → 重大なもの → 解消したもの → 残っているもの → 取れなかった run」の順。`runs_missing` があれば監視の穴として書く

## approve について

新規の主体のうち正当と思われるものは「approve してよいか」を人に提案する。**LLM 自身は approve しない** (ADR 0001)。
提案には finding の `id`、承認の対象 (`arata review --format json` の `approve`)、理由、期限を付けるべきかを書く。
判断基準は `arata help ai approve`。

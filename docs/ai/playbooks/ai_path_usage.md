# ai_path_usage: AI・監査用の主体の利用

## この指摘の意味

allowlist で `tags: [ai]` を付けた主体 (監査ロール・AI 用の調査ロール) が使われた (daily、info)。主体 × 送信元 IP で、窓の中で使われた組を毎回 1 行出す。
自己監査のための記録で、件数・通知には数えない。監査や AI の経路が乗っ取られても、いつもと違う IP が並ぶことで人が気づけるようにする。

- Key は `<主体 ARN>|<IP>`
- data: `arn`、`ip`、`first_seen` / `last_seen` (その組の初出と最終)、`count_total` (累計の件数)

## まず確かめること

1. IP がいつもの実行環境 (arata を動かすホスト、CI のランナー、AI の実行環境) か。利用者の事情に書かれた送信元と照らす
2. `first_seen` が最近の組 (新しい IP) が無いか。前回までのレポートと比べる (`arata report --from <日付> --to <日付>`)
3. 新しい IP なら、その主体の操作を CloudTrail で見る: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole` で、
   この主体のロールを引き受けたイベントを探し、その一時キー (`AccessKeyId`) で続く操作を引く
4. `arata review --format json` で、同じ主体の access_denied (調査ロールの想定外の拒否) が出ていないか

## 判断の分かれ目

- **記録でよい**: いつもの IP だけ、または実行環境の移行など説明の付く新しい IP
- **要対応**: 説明の付かない新しい IP、ふだんと違う時間帯の大量の利用、想定外の拒否 (access_denied) と重なる。監査・AI の経路の認証情報の漏洩の疑い

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (漏洩の疑い): ロールの `Revoke sessions`、引き受け元の認証情報 (アクセスキー・OIDC の設定) の取り替え、信頼ポリシーの見直し
2. **承認**: 既に承認済み (`tags: [ai]`)。新しい実行環境なら、利用者の事情 (context_file など) に送信元を書き足すよう人に提案する
3. **expected_denied**: 対象外 (想定内の拒否は access_denied の側で)
4. **ack / snooze**: info は finding の件数に入らないので不要
5. **設定の修正**: 信頼ポリシーや IAM の条件 (`aws:SourceIp` など) で、使える場所を絞る

## やってはいけないこと

- info だからと読み飛ばさない。新しい IP があれば書く
- 監査・AI 用の主体の権限を広げる提案をしない (調査に足りない権限は人が判断する)

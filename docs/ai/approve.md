# 承認 (approve) の判断基準

## 原則

- approve は allowlist.yaml を書き換え、以後その主体を報告しなくなる。**LLM は実行せず、人に提案するだけ**にする
- 提案には次を書く: finding の `id`、承認の対象 (`arata review --format json` の `approve`)、承認してよい理由、期限を付けるか、タグ
- 人が実行するコマンドの例を添えてよい:
  `arata approve <id> --note "<理由>" [--expires YYYY-MM-DD] [--tag deploy|ai] [--by <承認者>]`
- `--commit` を付けると allowlist.yaml だけを git commit する。push とレビューは人が行う

## 承認してよい主体の目安

- 誰が・何のために使うかを説明できる (社員の switch role、CI/CD のロール、運用委託先、SaaS 連携)
- 送信元 IP が業務の場所 (オフィス、CI のランナー、SaaS の公開レンジ) と整合する
- 操作の内容が役割と合っている (デプロイロールが IAM を変えるのは整合、監視 SaaS が IAM を変えるのは不整合)
- 迷う場合は承認せず、`ack` (再報告しないが未対応一覧に残る) を提案する

## SaaS 連携は account で承認する

監視 SaaS などの SaaS は、自社の AWS アカウントからクロスアカウントで AssumeRole してくる。
CloudTrail ではその主体が「外部アカウント NNN」(`arn:aws:iam::NNN:root`) に見える。

- 外部アカウントの root の finding を approve すると、`account: "NNN"` (そのアカウントの全主体) で承認される
- アカウント ID が SaaS の公式ドキュメントに載っているものと一致するかを確かめてから提案する
- 自社の別アカウント (本番 / 検証) も同じ扱い。`--account` で ARN の主体のアカウント全体を承認できる

## 外部アカウント root の見方

- 「外部アカウント NNN」は、そのアカウントの誰か (どの IAM 主体かは CloudTrail に残らない) が操作したことを表す。
  自社アカウントのルートユーザーの利用 (root_usage、critical) とは別物
- 知らないアカウント ID からの AssumeRole は、ロールの信頼ポリシーが広すぎる可能性がある。承認より先に信頼ポリシーの確認を提案する

## arn_pattern の使いどころ

- 同じ役割の主体が名前を変えて増えるとき (例: `arn:aws:iam::123456789012:role/github-actions-*`)
- `*` は `/` や `:` も含む任意の文字列に一致する。広すぎるパターン (アカウント全体に近いもの) は `account:` と変わらないので避ける
- `arata approve <id> --arn-pattern '<glob>'` は、パターンが finding の主体に一致するときだけ受け付ける

## 期限付き承認の使いどころ

`--expires YYYY-MM-DD` を付けると、その日の終わりまで有効。過ぎたら expired として再報告される。

- 外部委託・契約者・一時的な調査用の主体
- 移行期間だけ残す旧ロール
- 理由を確かめきれないが業務を止められないもの (短い期限で付け、期限前に再確認する)

## tags の語彙

- `deploy`: 既知のデプロイ主体。この主体による IAM 変更 (iam_changes) を info に下げる (finding は残る)
- `ai`: 監査ロール・AI (LLM) 用の主体。ai_path_usage がこの主体の利用を主体 × 送信元 IP で毎回 info に 1 行出す (自己監査。いつもと違う IP からの利用に人が気づけるように)
- 語彙は `deploy` と `ai` だけ。それ以外のタグは approve が拒否する

## access_denied が鳴ったとき

access_denied は allowlist で主体を承認しても止まらない (承認済みの主体でも拒否の急増は報告する)。
`--expected-denied` を付けない approve は拒否される。data の `apis` (拒否された API と件数) を見て、次のどれかを提案する。

- **想定内の拒否** (IAM の Deny を意図して入れている、権限外の API を試す運用が分かっている): `expected_denied` で主体 × API の単位で除く。
  除いた後も、想定外の API の拒否は数え続ける (乗っ取られたときの列挙は見える)
  - 主体の項目がまだ無いとき: `arata approve <id> --expected-denied 'logs:StartQuery' --expected-denied 'logs:Get*' --note "<なぜ想定内か>"`。
    finding は resolved にならず、次の run で除いて数え直す
  - 主体の項目が既にあるとき: approve は書き換えずに止まり、足す行を示す。人がその項目に `expected_denied: [...]` を手で足す
  - 書式は「サービス:操作」の glob (`apis` と同じ形。`*` は任意の文字列)。広すぎるもの (`*:*`、`iam:*` など) は列挙を隠すので避ける。
    期限を付けられる (`--expires`)。期限を過ぎたら再び数える
  - 注意: 項目を新しく作ると、その主体そのものも承認される (new_principal なども止まる)。主体の承認として妥当でないなら作らない
- **主体ごと止めたい** (権限の足りないバッチの修正待ちなど): `ack` か `snooze`。ただし ack / snooze しても、重大度が上がれば (medium → high など) 再報告される
- **説明が付かない**: 承認も ack もせず、要対処として扱う (乗っ取り・SaaS 側の侵害の疑い。`arata help ai report` の相関付け)

## approve ではなく ack / snooze / resolve にするもの

- 主体の承認ではない finding (root_usage、login_bruteforce、probe_paths、waf_block_trend など) は approve できない。access_denied は上の `--expected-denied` だけ
- `ack`: 確認したが allowlist に入れたくないもの。再報告しないが未対応一覧に残る。ack したときより重大度が上がったら変化 (changed) として再報告される
- `snooze --until YYYY-MM-DD`: 対処の予定が決まっているもの。期日以降に再び観測されたら新規として再報告される。期日前でも重大度が上がれば再報告される
- `resolve`: 対処が終わったもの。再び観測されたら新規として報告される

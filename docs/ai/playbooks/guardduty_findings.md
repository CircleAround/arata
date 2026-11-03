# guardduty_findings: GuardDuty の検出

## この指摘の意味

GuardDuty のアーカイブされていない検出を 1 件ずつ報告する (weekly、状態型)。重大度は GuardDuty の値で決まる (7 以上 → high、4 以上 → medium、それ未満 → low)。
同じ検出の回数 (`count`) が増えると changed、GuardDuty 側でアーカイブされると resolved。GuardDuty が無効なリージョンは posture の `guardduty_enabled` が扱う。

- Key は GuardDuty の finding ID
- data: `type` (例 `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`)、`title`、`severity_score`、`count`、`region`、`resource_type` (AccessKey / Instance / S3Bucket など)、`updated_at`
- `type` は「脅威の目的:影響を受けた資源/脅威の名前」の形。目的の部分 (`UnauthorizedAccess`・`CredentialAccess`・`Exfiltration`・`CryptoCurrency`・`Recon`・`Policy` など) で重さの見当がつく

## まず確かめること

1. 検出の詳細を見る: GuardDuty コンソール > 検出結果 (Findings) で finding ID を開く。CLI は
   `aws guardduty list-detectors --region <region>` で detector ID を得て、`aws guardduty get-findings --detector-id <ID> --finding-ids <finding ID> --region <region>`
2. 影響を受けた資源 (アクセスキー・インスタンス・バケット) と、操作した主体・送信元 IP を確かめる
3. `arata review --format json` で同じ主体・同じ IP の finding (access_denied・unknown_assume_role・iam_changes・root_usage) を探す。重なればインシデントの候補としてまとめる
4. `type` が認証情報 (`IAMUser`・`InstanceCredentialExfiltration`) にかかわるなら、その認証情報の操作を CloudTrail で引く
   (`aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<キー>`)
5. 業務の事情 (脆弱性診断・負荷試験・新しい SaaS の利用) で説明が付くかを利用者の事情と照らす

## 判断の分かれ目

- **正規の可能性が高い**: 自社の診断・試験の送信元、既知の SaaS の動作で、利用者の事情に説明がある (GuardDuty は正規の動作でも出ることがある)
- **要対応**: high (7 以上)、認証情報の持ち出し・不正なアクセス・暗号通貨の採掘・データの持ち出しの種類、他の finding と重なる
- `count` が増え続ける (changed) ものは、まだ続いている

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め**: 資源の種類に合わせる。アクセスキーなら無効化 (`aws iam update-access-key ... --status Inactive`)、ロールなら `Revoke sessions`、
   インスタンスなら証拠 (EBS のスナップショット) を残してからセキュリティグループで隔離する。止める前に証拠を残すかは人が判断する
2. **承認**: 対象外
3. **expected_denied**: 対象外
4. **ack / snooze**: 調べて正規と分かったものは、GuardDuty 側でアーカイブする (人が行う。arata では resolved になる) か、`arata ack <id>`
5. **設定の修正**: 正規の動作で繰り返し出る種類は、条件を絞った抑止ルール (suppression rule) を人が作る

## やってはいけないこと

- 調べずにアーカイブ・抑止ルールで黙らせることを勧めない。抑止ルールを広く (種類だけで) 作らない
- 証拠を残さずにインスタンスの終了・資源の削除を勧めない
- LLM が GuardDuty の設定・検出を変更しない

# セキュリティの報告

arata / aratam の脆弱性を見つけたら、公開の Issue ではなく、GitHub の非公開の報告を使ってください。

- 報告のフォーム: https://github.com/CircleAround/arata/security/advisories/new
  (リポジトリの **Security** タブ → **Report a vulnerability** と同じ)
- 報告は管理者だけが読めます。公開の Issue・PR・Discussion には書かないでください

報告には、再現の手順、影響 (例: 読み取ったログが意図しない先へ送られる、通知に個人を特定できる値が出る)、使った版 (`arata --version`) を書いてください。

## 対応の流れと目安

1. 受け取ったことを、7 日以内を目安に、報告のスレッドで返します
2. 再現と影響を確かめ、直すかどうかと見通しを、報告のスレッドで共有します
3. 直した版を Release で出してから、GitHub Security Advisory で公開します。報告から 90 日以内の公開を目安にします。
   報告した人が望めば、Advisory に名前を載せます

目安は約束ではありません。少人数で保守しているため、遅れるときは報告のスレッドで知らせます。

## English

Please report vulnerabilities privately via https://github.com/CircleAround/arata/security/advisories/new — not in public issues.
We aim to acknowledge within 7 days and to publish a fix and a GitHub Security Advisory within 90 days (coordinated disclosure).

## 対象の版

最新のリリースだけを直します。古い版を使っている場合は、最新の版に上げてから確かめてください。

## arata の約束 (報告の手がかり)

- arata は監査対象の AWS に対して読み取り専用です。例外は `iam:GenerateCredentialReport` だけです (`docs/design.md` 8 章)
- arata は LLM を使いません。LLM と Slack への送信は aratam だけが行います
- レポートと通知に、メールアドレスや氏名を書きません

これらが破れる挙動は、脆弱性として扱います。

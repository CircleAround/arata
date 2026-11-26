# 0092. `aws login` のログインのセッション (`CreateOAuth2Token`) を残し、同じセッションの出し直しが知らない送信元から来たことを報告する (`signin_session`)。サインインの長さの変更は iam_changes で報告する

- 日付: 2026-11-27
- 状態: 採用 (2026-11-27、ユーザーの判断)

## 背景

### 守りたいこと

AWS CLI の `aws login` は、ブラウザでサインインしたあと、手元のファイルに出し直しの控え (refresh token) を置く。CLI はこの控えで一時の鍵を何度でも出し直す。
サインインの長さは IAM ユーザーごとに延ばせる (長いほど便利で、盗まれたときの害も長い)。控えのファイルを写し取った者は、サインインが切れるまで、
MFA もブラウザも無しに、別の場所から鍵を出し直し続けられる。止める手 (ログインのセッションの取り消し) はあるが、盗まれたことに気づく手が arata に無い。

### 今の arata で見えること・見えないこと (main を読んで確かめた)

- 出し直しの記録 (`signin.amazonaws.com` の `CreateOAuth2Token`。下の 1) は readOnly で、collector がストアに残す一覧 (`notable`) に入っていない。**記録そのものは残らない**
- 主体の活動の日次集計 (ADR 0027) は、残すかどうかと関係なく全部の記録を数える。出し直しも、その後の API の呼び出しも、IAM ユーザーの送信元 (/24) として数えられる。
  そのため、知らない /24 からの出し直しと利用は、今も `principal_new_source` の low (書き込みが多ければ medium、拒否も同じ窓にあれば high) として出る
- ただし principal_new_source は、**どのログインのセッションか**を見ない。ふだん使う回線が複数ある利用者 (サーバーと人の端末) では、
  盗んだ控えを利用者のふだんの回線の 1 つから使われると何も出ない。逆に、新しい回線からの、本人の新しいログインも同じ low になり、区別がつかない
- サインインの長さの変更 (`UpdateLoginProfile`) は IAM の書き込みなのでストアに残るが、iam_changes の報告の一覧に入っていない。**報告されない**

### 実際の記録で分かった形 (2026-11-26 に、利用者の 1 つのアカウントの CloudTrail を読んで確かめた。値は書かず形だけ)

1. `CreateOAuth2Token`
   - eventSource `signin.amazonaws.com`、eventType `AwsApiCall`、readOnly `true`、managementEvent `true`。**ログインしたリージョンに入る** (us-east-1 には無かった)
   - userIdentity は type `IAMUser`、arn は `user/<名前>`。`sessionContext.attributes.mfaAuthenticated` は `"true"`、`sessionContext.signInSessionArn` は
     `arn:aws:signin:<リージョン>:<アカウント>:session/<UUID>`
   - requestParameters は `client_id` の 1 つだけで、`arn:aws:signin:::devtools/cross-device` か `…/same-device`
   - additionalEventData のキーは `signInSessionArn`・`SignInSessionExtended` (`"false"` の文字列)・`grant_type`・`success` (`"true"` の文字列)。
     `grant_type` は、最初のログインが `authorization_code`、出し直しが `refresh_token`
   - responseElements は null (控えも鍵も載らない)
   - 出し直しは定期ではなく、CLI を使うときにだけ出る (1 日に 10 件、間が 15 分〜4 時間)
2. 1 日の形: 同じ IAM ユーザーで、ログインのセッション (`signInSessionArn`) が 4 つあった (cross-device が 2 つ、別の回線からの same-device が 2 つ)。
   **1 人に 1 つのセッションではない**。送信元の /24 は 3 つ。User-Agent には CLI の版がそのまま出て、同じ日に 4 つの版があった
3. 続く API の呼び出し
   - userIdentity は type `IAMUser`、accessKeyId は一時の鍵 (`ASIA…`)。`sessionContext` に `signInSessionArn` と `mfaAuthenticated` がある
   - **出し直しの前後で `signInSessionArn` は同じで、accessKeyId は変わる**。絞った資格 (GetScopedCredentials) でも `signInSessionArn` は元と同じ
   - 例外: signin の `ListSessions` の呼び出しには `signInSessionArn` が付かない
4. 別のアカウントへのスイッチロール: 先のアカウントの `AssumeRole` の記録は、userIdentity が type `AWSAccount` で、sessionContext が無い。
   その後のロールのセッションの呼び出しには、**元のアカウントのログインの `signInSessionArn` がそのまま載る** (アカウントをまたいで残る)
5. `UpdateLoginProfile`: eventSource `iam.amazonaws.com`、awsRegion `us-east-1`。requestParameters は `userName` と `maxSigninSessionDuration` (秒の数値)

## 決定

### 1. collector: 出し直しの記録を残し、ログインのセッションを data に持つ

- `signin.amazonaws.com` の `CreateOAuth2Token` を、readOnly でも残す (`notableNames` に足す)。件数は CLI の利用の回数に比例し、1 人 1 日に数十件までの見込み
- 残す記録の data に、規則で形を確かめた値だけを足す。**形に合わない値は入れない** (ログ由来の値は信用しない。ADR 0037)
  - `signin_session`: `additionalEventData.signInSessionArn` (無ければ `sessionContext.signInSessionArn`)。`^arn:aws:signin:[a-z0-9-]+:[0-9]{12}:session/[0-9a-f-]{36}$` に合うときだけ
  - `grant_type`: `authorization_code`・`refresh_token` のどちらか。ほかの値は `other`
  - `signin_client`: `client_id` が `arn:aws:signin:::devtools/cross-device` なら `cross-device`、`…/same-device` なら `same-device`、ほかは `other`
  - `signin_success`: `success` が `"true"` なら true、`"false"` なら false。無ければ入れない
  - `signin_extended`: `SignInSessionExtended` が `"true"` なら true、`"false"` なら false。無ければ入れない
- 残すほかの記録 (IAM の書き込み、AssumeRole、ConsoleLogin など) にも、`sessionContext.signInSessionArn` が形に合えば `signin_session` を足す。
  受け取る人が、どのログインのセッションの操作かを追えるようにするため。項目を足すだけなので互換 (ADR 0054)
- 主体の活動の日次集計に、`principal_signin_session` (キーは主体の ARN と `signin_session` の UUID) を足す。**全部の記録を数える** (残すかどうかに依らない)。
  2 節の数の判定の材料にする。ふつうの利用でキーは 1 人 1 日に数個

### 2. 新しいチェック `signin_session`

対象は IAM ユーザーのログインのセッション (`signin_session` を持つ `CreateOAuth2Token`)。評価は窓に重なる記録で行い、過去は `baseline_days` 日を見る。

| 形 | 重大度 | 理由 |
|---|---|---|
| 同じセッションの `refresh_token` の出し直しが、そのセッションでまだ見ていない /24 から来て、その /24 がその主体の平常帯 (過去 `baseline_days` の `principal_source`) にも無い | **high** | 控えを写し取って別の場所で使った形。本人の端末の移動では、ふだんの回線の外に出ることが少ない |
| 同じセッションの出し直しが、そのセッションでまだ見ていない /24 から来たが、その /24 は主体の平常帯にある | low | 同じ人の別の回線 (端末の移動) と、ふだんの回線の 1 つからの悪用の両方がある。消さずに残す |
| 失敗した出し直し (`signin_success: false`、または errorCode がある) が、主体 × 日で `min_failures` 回以上 | low | 取り消した控えや、壊れた控えを使い続けている形。形は未確認 (未確認の点 1) |
| 主体の 1 日のセッションの数 (`principal_signin_session` の異なるキーの数) が、平常帯の最大より多く、`min_sessions` 以上 | low | 知らないログインのセッションが増えた形。1 人に複数のセッションがふつうなので、平常帯と比べる |

- 「そのセッションでまだ見ていない /24」は、そのセッションの過去の `CreateOAuth2Token` (最初のログインを含む) の送信元と比べる。
  過去は `session_lookback` (サインインの長さの上限に合わせて利用者が決める。既定は持たない。ADR 0014) まで見る。
  そのセッションの最初の記録が lookback の外にあり、窓の中で初めて見るセッションの最初の出し直しは、「まだ見ていない /24」の判定をせず、主体の平常帯だけと比べる
  (平常帯に無ければ high。あれば報告しない)
- 平常帯の日は ADR 0090 のとおり、収集した日だけで数える。`min_baseline_days` に足りないうちは、high の形も medium に下げ、data に `baseline_short: true` を出す
- 送信元が IP でない記録 (サービス名) は判定しない
- 最初のログイン (`authorization_code`) が新しい /24 から来たことは、このチェックでは報告しない。MFA とブラウザを通った本人のログインが多く、
  新しい送信元としては principal_new_source が既に low で出す (二重に出さない)
- User-Agent は重大度に使わない (偽れる。ADR 0091 でも下げる材料にしていない)。data には、CLI の版の形 (`aws-cli/<数字>.<数字>.<数字>`) に合うときだけ出す
- Key は `<主体の ARN>|<セッションの UUID>|<形>`。セッションごとに 1 つ。同じセッションの新しい /24 が増えれば changed で出直す
- data: `signin_session`・`signin_client`・`new_prefixes` (そのセッションで初めての /24)・`known_prefixes` (そのセッションのそれまでの /24)・`in_principal_baseline`・`refreshes` (窓の中の回数)・
  `first_seen` (そのセッションの最初の記録の時刻)
- 片付け (ADR 0068): high は snooze・resolve だけ。low は ack も許す (セッションは期限で終わるので、ack の対象は自然に消える)

### 3. サインインの長さの変更を iam_changes で報告する

- `UpdateLoginProfile` で requestParameters に `maxSigninSessionDuration` があるものを、iam_changes の一覧に足す。重大度は medium。
  **既知のデプロイの主体 (`tags: [deploy]`) でも下げない** (ADR 0056 の「下げない変更」に足す。延ばすのは、奪った者が居座りを長くする手口)
- data に `max_signin_session_duration` (秒。0 以上の整数のときだけ) を出す。延ばしたのか縮めたのかは、前の値が記録に無いので出さない
- ロールのサインインの長さの変更 (`UpdateRole` の同じ名前の項目) と、既定に戻す操作は、形を見ていない (未確認の点 2)。形を確かめてから同じ規則で足す

### 4. アカウントをまたぐ追跡は、この ADR ではしない

- スイッチロールの先のアカウントの操作にも、元のログインの `signin_session` が載る (背景の 4)。1 節の data で、先のアカウントの指摘にも `signin_session` が出るので、
  受け取る人は同じ UUID を手で突き合わせられる
- 先のアカウントの監査で、元のアカウントの出し直しの記録を読む仕組み (ストアをまたぐ読み取り) は作らない。監査のストアはアカウントごとに分けている

### 5. 設定 (案)

```yaml
checks:
  signin_session:
    baseline_days: 14
    min_baseline_days: 7
    session_lookback: 3d     # サインインの長さの上限に合わせる
    min_failures: 3
    min_sessions: 3
```

`config init` の雛形に足し、`config init --diff` で見えるようにする。プロファイルに入れなければ動かない (ADR 0014)。

## 検討した選択肢

- **ログインのセッションの一覧 (`signin:ListSessions`) を posture として読む**: 却下。読み取りロールに新しい権限を足すことになる。
  一覧は「今生きているもの」だけで、過去の日の比較ができない (`arata rebuild` で同じ結果を出せない)。セッションの数は 1 節の集計で記録から数えられる
- **principal_new_source の延長 (送信元の比較にセッションを足す)**: 却下。principal_new_source は全部の主体 (ロール・長い鍵) を同じ規則で見るチェックで、
  セッションの /24 の動きは IAM ユーザーの `aws login` にしか無い。重大度の決め方 (同じセッションが別の場所に移った = high) も違う
- **セッションの /24 が変わったら、平常帯に依らず high**: 却下。人の端末は回線を変えて使われる (背景の 2 では、人の端末の same-device のセッションが、サーバーと別の 2 つの回線から来ていた。1 つのセッションの中で回線が変わる形は未確認)。
  ふだんの回線の中の移動まで high にすると、毎日の片付けで本当の high が埋もれる
- **User-Agent の変化を重大度に使う**: 却下。偽れるうえ、CLI の版は本人の更新で変わる (背景の 2)
- **全部の API の呼び出しの (セッション, /24) で移動を見る**: 今回は採らない。出し直しの記録だけで「控えを別の場所で使った」は見える (控えから鍵を作るには出し直しが要る)。
  一時の鍵だけを写し取った場合は、鍵の期限 (出し直しの間) の中の利用で、principal_new_source が見る

## 結果 (良い点・引き受けるコスト)

- 良い点: 控えを盗まれた形 (同じセッションが知らない場所に移る) を、本人の新しいログインと区別して high にできる。
  延ばしたサインインの長さの変更が、デプロイの主体からでも報告される。アカウントをまたいだ操作を、元のログインに手で結び付けられる
- コスト: 残す記録が、CLI の利用の回数の分だけ増える。チェックとクエリが 1 つずつ増える。`session_lookback` を利用者が決める必要がある
- ふだんの回線の 1 つから使われた悪用は low にとどまる。ふだんの回線そのもの (サーバー) の上で控えを使われると、このチェックでは見えない

## 未確認の点 (実装の前に確かめる)

1. 失敗した出し直しの記録の形 (errorCode の値、`success` が `"false"` になるか)。取り消したセッションの控えを使ったときの形も
2. ロールのサインインの長さの変更 (`UpdateRole`) と、既定に戻す操作の記録の形
3. ログインのセッションの取り消しの記録の eventName と eventSource。分かれば、取り消しの後の出し直しを high の補強に使えるかを考える
4. AWS の公式文書の、`CreateOAuth2Token` の記録の説明 (additionalEventData の `SignInDuration` など)。今回の記録には `SignInDuration` が無かった
5. IPv6 の送信元からの出し直しの形 (/48 で比べる想定)
6. 手口に対応する公開の事例。実装の PR で探し、無ければ playbook の「関連する事例」に「対応する公開の事例はまだ無い」と書く (ADR 0058)

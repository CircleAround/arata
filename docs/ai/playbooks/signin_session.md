# signin_session: aws login のログインのセッションの出し直し

## この指摘の意味

AWS CLI の `aws login` は、ブラウザでサインインしたあと、手元のファイルに出し直しの控え (refresh token) を置き、それで一時の鍵を出し直す
(CloudTrail の `signin.amazonaws.com` の `CreateOAuth2Token`)。控えを写し取った者は、サインインが切れるまで MFA もブラウザも無しに、別の場所から鍵を出し直せる。
このチェックは IAM ユーザーのログインのセッション (`signin_session`) ごとに出し直しの送信元を追い、控えが別の場所で使われた形を報告する (daily。ADR 0092)。

- 形 (`form`。Key の最後の欄) と重大度:
  - `new_prefix`: 同じセッションの成功した出し直しが、そのセッションでまだ見ていない送信元 (/24・/48) から来た。
    その送信元が主体の平常帯 (過去 `baseline_days` の送信元) にも無い → **high**。平常帯にある → low (同じ人の別の回線と、ふだんの回線の 1 つからの悪用の両方がある)
  - `failures`: 失敗した出し直し (`signin_success: false` か errorCode) が主体 × UTC の日で `min_failures` 回以上 → low。取り消した控え・壊れた控えを使い続けている形。
    **失敗の記録の形は実際の記録で確かめていない** (ADR 0092 の未確認の点 1)
  - `sessions`: 主体の 1 日のログインのセッションの数が、平常帯の最大より多く `min_sessions` 以上 → low
- 過去の出し直しは `session_lookback` まで遡って見る。セッションの始まりがそれより前 (`first_outside_lookback: true`) なら、その出し直しは主体の平常帯だけと比べる
- CloudTrail を収集し終えた過去日が `min_baseline_days` 未満の間は、high を medium に下げ (`baseline_short: true`)、`sessions` は判定しない
- 最初のログイン (`grant_type` が `authorization_code`) の新しい送信元は、このチェックでは報告しない (principal_new_source が見る)。User-Agent は重大度に使わない
- Key: `<主体の ARN>|<セッションの UUID>|new_prefix`、`<主体の ARN>|<UTC の日>|failures`、`<主体の ARN>|<UTC の日>|sessions`。
  同じセッションの新しい送信元が増えれば changed で出直す
- data: `principal`、`form`、`signin_session`、`signin_client` (cross-device / same-device / other)、`new_prefixes`、`known_prefixes` (そのセッションのそれまでの送信元)、
  `in_principal_baseline`、`refreshes` (窓の中の成功した出し直しの回数)、`first_seen`、`first_outside_lookback`、`cli_versions` (`aws-cli/<版>` の形のものだけ)、
  `failures`・`error_codes`・`signin_sessions` (failures)、`sessions`・`baseline_max` (sessions)、`baseline_short`、`baseline_days_collected`

## まず確かめること

1. `new_prefixes` と `known_prefixes` を、利用者の業務の場所 (オフィス・VPN・自宅回線・サーバー) と照らす。`whois <IP>` で事業者を見る。
   `in_principal_baseline: false` なら、その主体がふだん使わない送信元に、同じログインのセッションが移った
2. 利用者に、その時刻にその場所で CLI を使ったかを確かめる。同じセッションを 2 つの端末で使うことは、控えのファイルを写さない限り起きない
3. 同じセッションの後の操作を並べる: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<ユーザー名>` を新しい送信元のリージョンでも引き、
   `userIdentity.sessionContext.signInSessionArn` が `signin_session` と同じで、`sourceIPAddress` が新しい送信元の記録 (書き込み・IAM の変更・秘匿値の読み取り) を探す。
   スイッチロールの先のアカウントの記録にも同じ `signInSessionArn` が載る (arata の指摘の data にも `signin_session` が出る)
4. `arata review --format json` で同じ主体の principal_new_source・access_denied・secret_access・iam_changes を探す。
   iam_changes にサインインの長さの変更 (`signin_duration`) があれば、居座りを長くする手口の疑いが強まる
5. `failures` なら、利用者がセッションを取り消した後か、控えのファイルが古いままかを確かめる。取り消した覚えがなければ、ほかの場所で使われている疑い

## 判断の分かれ目

- **正規の可能性が高い**: 利用者が端末の移動 (ノートを持って自宅と会社) を説明できる。`in_principal_baseline: true` の low。
  `sessions` で、その日に新しい端末やサーバーでログインしたと説明できる
- **要対応**: high (同じセッションが、主体のふだん使わない送信元に移った)。利用者が説明できない。VPS・匿名化の出口からの出し直し。
  新しい送信元からの書き込み・IAM の変更・秘匿値の読み取り。同じ日のサインインの長さの延長

## 対処の選択肢

緊急度の順。封じ込めと設定の変更は**人が判断して実行する**。LLM は提案まで。

1. **封じ込め** (説明が付かない): その IAM ユーザーのログインのセッションを取り消す (AWS のコンソールの IAM ユーザーの画面などから)。
   すでに出した一時の鍵は期限まで使えるので、ユーザーの権限を一時的に外す・拒否のポリシーを付けることも検討する。利用者の端末の控えのファイル (`aws logout` で消える) と、端末そのものを調べる
2. **サインインの長さを縮める**: IAM ユーザーのサインインの長さを、業務に要る最短にする (盗まれたときに使える時間が縮む)
3. **片付け**: 片付けは下の「片付け」の節
4. **設定の修正**: `session_lookback` は、そのアカウントのサインインの長さの上限に合わせる (短いと、長いセッションの始まりが見えず、平常帯だけと比べる)

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high・medium | なし | snooze・resolve |
| low | あり | ack・snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- ack: low だけ。端末の移動と確かめたもの。同じセッションが平常帯の外に移れば high で出直す。セッションは期限で終わるので、ack の対象は自然に消える
- snooze: 確かめ中のものを、確かめが終わる日まで
- resolve: 確かめて終わった 1 回の出来事
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- `cli_versions` (User-Agent) が同じ・ふだんの版だからと軽く扱わない (呼ぶ側が書ける値)
- low を「平常帯の内だから正規」と決めつけない (ふだんの回線の 1 つから使われた悪用も low になる)
- 調べる前に `session_lookback` を短くする・チェックを外すことを提案しない。LLM がセッションの取り消し・ack を実行しない

## 関連する事例

対応する公開の事例はまだ無い (`arata help ai threats`)。

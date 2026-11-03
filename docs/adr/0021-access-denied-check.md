# 0021. 拒否された API 呼び出しを events に残し、主体ごとの種類と件数を平常帯と比べる `access_denied` チェックを足す

- 日付: 2026-11-03
- 状態: 採用

## 背景

試験環境で、承認済み (allowlist の `account:`) の外部アカウントが、権限の無いロールを引き受けて
`iam:ListUsers` / `s3:ListBuckets` / `ec2:DescribeInstances` / `secretsmanager:ListSecrets` / `iam:CreateUser` を呼び、すべて拒否された。
arata が拾えたのは new_principal (セッションの初出) と iam_changes (拒否された CreateUser) だけだった。
読み取りの拒否は注目イベント (`cloudtrail.DefaultNotable`) に入らず、保存も評価もされていなかった。

拒否が続くのは、盗んだ認証情報で「何ができるか」を探っている (権限の列挙) ときの典型的な兆候である。
承認済みの主体でも起き得る (承認した後に乗っ取られる、SaaS 側が侵害される)。

## 決定

- 拒否された呼び出し (CloudTrail の `errorCode` が `checks.access_denied.error_codes` に完全一致するもの) を、読み取りも含めて **events テーブルに残す**。
  既定のコードは `AccessDenied`, `AccessDeniedException`, `UnauthorizedOperation`, `Client.UnauthorizedOperation`。
  保存はチェックを有効にしているかどうかに関わらず行う (init のベースライン収集でも残し、平常帯に使う)。
  error_codes は保存の条件なので、profile の overrides では変えられない (全体の `checks:` でだけ変える)
- チェック `access_denied` (daily、event 型) は、主体ごとに窓の拒否を数え、次のどちらかを満たしたら 1 件報告する (Key は主体 ARN)
  - **幅**: 拒否された API (`eventSource:eventName`) の種類が `min_distinct_apis` (既定 5) 以上で、かつ平常帯を超える → medium。`high_distinct_apis` (既定 20) 以上なら high
  - **量**: 件数が `max(min_count (既定 50), 中央値 × factor)` を超える → medium (同じ API を叩き続ける設定ミスのアプリ。medium 止まり)
  - 両方満たすときは重い方 (幅) を 1 件として出す
- 平常帯は、その主体自身の、窓の始まりの日の前日から `baseline_days` (既定 14) 日分の UTC の日ごとの件数・種類 (無い日は 0) の中央値 × `factor` (既定 3)。
  拒否のある過去日が `min_baseline_days` (既定 7) 未満 (導入直後) は平常帯を 0 とみなし、絶対の閾値だけで判定する
- 評価するのは窓のイベント (窓内に加え、再走査で遅れて届いたもの。重なり区間の評価済み分は含めない。ADR 0013)。UTC の日で分けない
- サービス主体と root (root_usage が critical で扱う) は除く。**allowlist で承認済みでも除かない** (承認は「その主体が居ること」を認めるもので、
  「権限を探ってよい」ではない)。Data に allowlist_status を残し、止めたいときは ack / snooze を使う
- Fingerprint は重大度と IP 集合 (件数・API の並びは入れない)。run の stats に `denied_events` (拒否として出した件数) を残す
- 必要な IAM action は増えない (cloudtrail:LookupEvents だけ)

## 検討した選択肢

- **metrics テーブルに主体ごとの日次集計を入れる**: 却下。metrics は「同じ日の値は後の値で置き換える」(Logs Insights を日の頭から引き直す前提。ADR 0009) が、
  CloudTrail は窓単位で引くので、daily の窓 `[D-1 09:00, D 09:00)` の部分的な件数で丸 1 日分を上書きしてしまう。
  events に残せば event_id の重複排除と collected_at による再走査の扱い (ADR 0013) をそのまま使える
- **窓に重なる UTC の日ごとに数える (login_bruteforce と同じ)**: 却下。窓の前半の日 (D-1 の 00:00〜09:00) を前回と今回の 2 回評価するか、
  窓に入る部分だけを数えて日の境目 (00:00 UTC) をまたぐ列挙が 2 つに割れ、閾値を下回るおそれがある。daily の窓は 24 時間なので、窓全体を丸 1 日と比べる
- **承認済みの主体を除く**: 却下。試験で観測した経路 (承認済みの外部アカウントによる列挙) をちょうど見逃す
- **ConsoleLogin の失敗も数える**: 対象外。失敗は errorCode ではなく responseElements に出る。将来の別チェックにする

## 結果 (良い点・引き受けるコスト)

- 良い点: 権限の列挙を、承認済みの主体でも拾える。既存の注目イベントの仕組み (重複排除・再走査) に乗るので新しい保存の形を持たない
- 良い点: 毎日いくつかの API で拒否される主体 (権限の足りないバッチなど) は自分の平常帯で吸収される
- コスト: events テーブルが増える。拒否が多い (設定ミスの多い) アカウントでは目立つ。run の stats の `denied_events` を目安にする
- コスト: error_codes に後からコードを足しても、足す前の拒否は保存されていないので、そのコードの平常帯は 0 から始まる
- コスト: 平常帯は丸 1 日と比べるので、窓が 24 時間より短いプロファイル (hourly に入れた場合) では鳴りにくい。いまは daily だけに入れる (hourly は将来の課題)
- 他のチェック (iam_changes / root_usage / unknown_assume_role) は今の絞り込みのままで、拒否イベントが増えても結果が変わらない
  (root のイベント・AssumeRole*・IAM の書き込みはもともと残している。増えるのはそれ以外の拒否だけ)。テストで固定した

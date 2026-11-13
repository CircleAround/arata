# 導入の流れ (init の後、定時の通知を始めるまで)

## 流れ

`arata init` は finding を出さない。その後の**最初の run で、長く溜まっていたものが一度に出る**。
これを通知 (aratam) に流さず、手元で 1 件ずつ片付けてから定時の実行に任せる。毎回この順番で行う。

1. `arata config init --audit-account <12 桁の ID>|none` で雛形を書き出し、name / store / sources を編集する
2. `arata doctor` で権限・ロググループ・解釈率を確かめる (問題があれば終了コード 2。直してから進む)
3. `arata init` でベースラインを収集する (findings は出さない。止まったら `arata init --resume`)
4. **通知をつながずに**、設定に書いたプロファイルを 1 つずつ流す。`--out` は手元のディレクトリにする

   ```sh
   arata run --profile daily  --out /tmp/arata-first/daily
   arata run --profile weekly --out /tmp/arata-first/weekly
   ```

5. `arata review` で未対応の一覧を見る (`--format json` で機械向け。中身は `--out` の report.md / report.json)
6. 1 件ずつ片付ける (下の「1 件ずつ片付ける」)。終わったら `arata review` で残りを確かめる
7. 15 分以上置いてから、もう一度 `arata run --profile daily --out /tmp/arata-first/daily` を流し、導入作業そのものの記録を拾って同じように片付ける
8. 定時の実行と通知 (aratam) を始める

LLM がこの流れを手伝うときも、run と review を読んで材料を整えるところまで。approve は人が実行し、ack / snooze / resolve は人の指示があるときだけ実行する。

## 最初の run で出るもの

多くは侵害ではなく「今まで誰も見ていなかった通常の動作と、直していない設定」。ただし本物が紛れ得るので、まとめて消さずに 1 件ずつ見る。

| 出やすいもの | チェック | 典型的な片付け方 |
|---|---|---|
| アプリの起動時に、実行用のロールが秘匿値をまとめて読む (一括読み出し。high) | secret_access | 正規の読み手なら、平常帯がそろう日まで snooze (下の注)。ack しない |
| 導入作業の IAM 変更 (読み取り専用ロールを作る・ポリシーを付ける) | iam_changes | 作業として確認できたら ack。IaC のデプロイ主体なら approve (`--tag deploy`) |
| 監査の仕組みや社員によるロールの引き受け | unknown_assume_role / new_principal | 説明できる主体は approve。受託先などへのスイッチロールは行き先を `assume_destinations` に |
| 設定していない守り (証跡・GuardDuty・パスワードポリシーなど) | posture | 直す日を決めて snooze。意図して外しているなら理由を残して ack |
| 古いアクセスキー・MFA の無いユーザー | credential_hygiene | 直す日を決めて snooze |
| 監査の主体や調査用のロールの、想定内の拒否 | access_denied | 設定で直す (`expected_denied`) |

secret_access の一括読み出しの注: 閾値は `max(min_distinct, その主体の日ごとの数の中央値 × factor)`。中央値は過去 `baseline_days` (既定 14) 日で取り、記録の無い日は 0 と数える。
導入直後は中央値が 0 (data の `baseline_median_distinct: 0`、`baseline_days_with_data` が小さい) で、絶対の閾値 `min_distinct` だけで判定されるので、
毎日同じ十数個を読むだけの正規のロールも high になる。

- 正規の読み手だと確かめたら、導入から `baseline_days` が過ぎる日まで `arata snooze <id> --until YYYY-MM-DD`。平常帯がそろえば出なくなる。期日の後も出るなら調べる
- **ack しない**。high は secret_access の最も重い重大度なので、ack すると本物の持ち出しが後で起きても報告されない (下の「使い分け」)
- allowlist.yaml の `secrets_access` は初出 (low / medium) を止めるだけで、一括読み出しの数には数える。書いても high は消えない。初出を止めたいときだけ書く

チェックごとの確かめ方は `arata help ai playbook <check>`、承認してよいかの基準は `arata help ai approve`。

## 1 件ずつ片付ける

finding の ID は `arata review` と report に出る。手段は 4 つで、上から順に当てはまるものを選ぶ。

1. **承認する**: 誰が・何のために使うかを説明できる主体は、人が `arata approve <id> --note "<理由>"` を実行する (allowlist.yaml に追記され、finding は解消する)。
   LLM は提案まで。approve できるのは主体の承認になるチェックだけで、`arata review` が対象を示す
2. **設定で直す**: 主体の承認ではない正常な動作は、allowlist.yaml の該当する節に人が書く
   (`secrets_access` / `source_ips` / `assume_destinations` / `expected_denied`。形式は `arata help ai`)。編集したら `arata config check`。
   何が止まるかは節ごとに違う (`secrets_access` が止めるのは初出だけ。一括読み出しは止まらない)。既に出た finding が残ったら、下の選び方で snooze か ack を選ぶ
3. **直す予定を決める**: 直すつもりのもの (設定していない守り、使っていないキーなど) は、期日を決めて `arata snooze <id> --until YYYY-MM-DD`
4. **確認して残す**: 正規の動きか、もう終わった出来事だと確かめたものだけ `arata ack <id>`

- 説明の付かないものは片付けない。playbook の「封じ込め」に進み、人が判断する
- critical / high を、数が多いことを理由に ack で流さない
- 何もしなかった finding は open のまま残る。一度レポートに出たものは、同じ内容のままなら次の run で再報告されないので、**定時の通知には出てこない** (`arata review` と週次の未対応にだけ残る)。
  だから通知を始める前に、ここで全部に目を通す

## ack・snooze・resolve の使い分け

| コマンド | 以後の動き | 使うとき |
|---|---|---|
| `ack` | 再報告しない (二度と報告されない)。`arata review` の未対応一覧には残る (acked) | 正規の動き、またはもう終わった出来事 |
| `snooze --until YYYY-MM-DD` | 期日まで沈黙する。期日以降に再び観測されたら新規として再報告する。直って観測されなくなれば解消になる | 直すつもりのもの。期日は直す予定の日 |
| `resolve` | 解消にする。再び観測されたら新規として報告する | 対処が終わり、もう観測されないはずのもの |

ack と snooze の選び方:

- **直すつもりなら snooze**。例: 証跡のログファイルの検証が無効、90 日使っていないアクセスキー。期日までに直せば解消になり、直っていなければ期日以降にまた報告される (忘れない)
- **ack は、正規の動きか、もう終わった出来事にだけ**使う。例: 導入作業で読み取り専用ロールを作った IAM 変更 (終わった出来事)、
  意図して入れていない守り (理由を記録したうえで)。ack したものは、同じ内容である限り二度と報告されない
- **報告が来なくなると困るものを ack にしない**。「いつか直す」「後で調べる」を ack にすると、直さないまま誰にも報されなくなる。期日を決めて snooze にする
- ack / snooze 中でも、重大度がそのときより上がれば変化 (changed) として再報告される。ただし当てにできない場面がある:
  **そのチェックの最も重い重大度 (例: secret_access の high) で出た finding を ack すると、重大度が上がる余地が無いので、後で本物が起きても二度と報告されない**。
  最も重い重大度のものは ack せず、期日を決めて snooze にする
- まだ観測され続けるもの (今の状態を見るチェックや、数日分を集計するチェック) を `resolve` すると、次の run で同じものが新規に戻る。直る前に `resolve` しない
- 状態型 (new_principal と週次のチェック) は、直して観測されなくなれば自動で解消になる。`resolve` を打たなくてよい
- 主体の承認は approve (allowlist.yaml に残る)。ack は承認ではなく、その finding を黙らせるだけ

## 導入作業の記録を拾う

導入作業 (読み取り専用ロールの作成、最初の `arata doctor` / `init` / `run` による引き受けや API 呼び出し) も CloudTrail に記録され、finding になり得る。
CloudTrail は記録まで最大 15 分ほど遅れるので、最初の run には作業の終わりの分が入らない。

- 最後の作業から 15 分以上置いて、`arata run --profile daily --out /tmp/arata-first/daily` をもう一度流す
  (run は前回の窓の終わりから続け、`ingest_delay` の分だけ前を引き直す。収集済みの出来事は再報告しない)
- 出たものは上と同じ手順で片付ける。自分たちの作業だと確認できたもの (終わった出来事) は ack、監査の主体は approve か `audit_account` の設定で
- この run で新しい指摘が出ず、`arata review` に見ていないものが残っていなければ、片付けは終わり

## 定時の通知を始める

- 定時の実行 (`arata run --profile <名前> --out DIR` → `aratam notify --in DIR`) をつなぐ。以後は新しく起きたことだけが通知される
- aratam の設定と疎通 (`aratam doctor` / `aratam test-notify`) は先に済ませてよい。**止めておくのは最初の run の結果の送信だけ**。
  通知の文面を見たければ `aratam notify --in /tmp/arata-first/daily --dry-run` (送らない)
- allowlist.yaml の変更は git に commit する (approve の `--commit` か、人が行う)。PR で直す運用は `arata help ai approve`
- ack / snooze にしたものは `arata review` (`--status snoozed` で snooze 中も) でいつでも見直せる

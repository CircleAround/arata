# 0068. 片付けの守り (理由と操作した人をストアに残し、high 以上の ack を止め、黙らせているものを週次に出し、許す操作を review に載せる)

- 日付: 2026-11-17
- 状態: 提案

## 背景

ある利用者の最初の本番の片付けで、secret_access の high (そのチェックの最も重い重大度) が ack された。
`docs/ai/onboarding.md` と secret_access の playbook には「secret_access の high は ack しない。`baseline_days` が過ぎるまで snooze」とあるが、
案を出した側も流した側も読んでいなかった。

ack / snooze 中でも重大度が上がれば changed として再報告する (ADR 0022)。しかし最も重い重大度で ack すると、上がる余地が無い。
同じ主体が後で本物の持ち出しをしても、同じ重大度・同じ Key の観測なので二度と報告されない。
片付けは誰が・なぜ・いつ行ったかもストアに残らず (ADR 0042 で見送り)、Actions の実行の Summary だけが記録で、保持期間で消える。
黙らせた finding は `arata review` を自分から引かない限り目に入らない。

根っこは、**落とし穴を避けることを、人が文書を読むことだけに任せていた**こと。守りを文書ではなく規則に置く (ADR 0037 と同じ考え)。

## 決定

5 つの段に分ける。1〜4 をこの順に実装し (段ごとに PR)、5 は後の段とする。

### 1. 片付けの理由と操作した人をストアに残す (ADR 0042 の見送りを置き換える)

- `arata ack` / `snooze` / `resolve` に `--reason` と `--by` を足す。`approve` は既にある `--note` / `--by` を同じ記録に使う
  - `--by` の省略時は `approve` と同じく OS のユーザー名
  - `--by` の形は `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` に絞る。メールアドレス (`@`) や氏名 (空白) を受け付けない
    (レポートに個人を特定できる値を書かない。GitHub のハンドルと OS のユーザー名はこの形に収まる)
  - `--reason` は 1 行・300 文字まで、制御文字と書式の文字 (Unicode の Cc・Cf) を受け付けない (見本のワークフローと同じ上限)。
    利用者の入力なので、形の検査はファズテストで確かめる (ADR 0041)
  - **`--reason` は省略できる** (`--force` のときだけ必須。2 節)。既存の手元の使い方とスクリプトを壊さない。
    見本のワークフローは今も理由を必須にしており、それを `--reason` に渡す
- 保存は新しい表 `finding_actions` (ストアのスキーマを 7 → 8)。1 回の操作を 1 行で、追記だけ (書き換えない):
  `seq`、`finding_id`、`check`、`key`、`action` (ack / snooze / resolve / approve)、`by`、`reason`、`forced`、
  `severity` (操作したときの重大度)、`status_before`、`snooze_until`、`at`
  - **finding_events には入れない**。finding_events は観測による状態遷移 (new / changed / recurred / resolved) の履歴で、期間レポートが種類ごとに数える (ADR 0016)。
    人の操作を混ぜると、同じ finding への 2 回目の ack や、既に resolved の finding への resolve をどう数えるかの規則が要り、期間レポートの数の意味が変わる。
    今の「人の resolve は finding_events にも resolved を 1 行足す」は変えない (期間レポートの解消の数はそのまま)
  - **findings の行には足さない**。evaluate は findings を読み直して丸ごと書く (UpsertFinding) ので、列を足すと書き戻しのたびに引き継ぐ規則が要る。
    最後の操作は `finding_actions` から finding ごとの最大の `seq` で引く
  - 状態の変更 (findings) と操作の記録 (finding_actions) は同じトランザクションで書く。片方だけが残ることはない
- 保持: findings と同じに扱う。今は findings の行を消す処理が無い (`retention.findings` は設定だけ) ので、操作の記録も消さない。
  findings を消す処理を足すときは、その finding の操作の記録も一緒に消す
- 移行 (schema 8): 表は `schema.sql` の `CREATE TABLE IF NOT EXISTS` で作られる。既存の acked / snoozed には記録が無い。
  review と報告では「記録なし (schema 8 より前の操作)」と出す (推測で埋めない)
- rebuild: `finding_actions` は raw に無い (findings と同じ)。既定では既存の SQLite から引き継ぎ、`--from-scratch` では空から作る (ADR 0033 の扱いと同じ)
- S3 ストア: SQLite を丸ごと出し入れする (ADR 0034) ので、移行は作業用の複製を開いたときに行われ、確定で S3 に戻る。オブジェクトの形は変わらない。
  - 新しい版で一度書いたストアを古い版で開いても動く (古い版は知らない表を読まない。`schema_version` が自分より新しくても止まらない、今の動作のまま)。
    ただし古い版の ack は記録を残さず、2 節の守りも効かない。**監査と片付けのワークフローは同じ版にそろえる**
    (`arata repo init` が書き出す一式は、両方の `ARATA_VERSION` が同じであることを `arata-check.yml` が既に確かめている)
- `arata review` (table と json) と報告に、最後の操作の action・by・reason・at・forced を出す。table は列を 1 つ (`LAST_ACTION`: `ack alice 2026-11-17`) にし、理由は json と報告に出す

### 2. 重大度が high・critical の finding は `arata ack` を受け付けない

- 判定は ack するときの finding の重大度 (findings の `severity`)。high・critical なら止める。チェックを問わない
  (最も重い重大度が medium のチェックでも、high 以上を ack させない規則が 1 つあるほうが、表を読み違えない)
- 止めるときは code `ACK_REFUSED` (`internal/codes` に足す) を付けた ERROR のログを出し、終了コード 2 (入力の誤り。`CONFIG_INVALID` と同じ扱い) で終わる。
  標準出力には次を出す:
  - 「approve (正規の主体と確かめた) / snooze --until YYYY-MM-DD (期日を決めて見直す) / resolve (直した) を使う」。
    そのチェックで approve ができないときは approve を出さない (4 節の表と同じ規則)
  - そのチェックの playbook の場所 (`arata help ai playbook <check>` の「片付け」の節)
- `--force` を付けたときだけ通す。`--force` には `--reason` が必須 (空なら同じ `ACK_REFUSED` で止める)。記録の `forced` を真にする
- **止める場所は `arata ack` の 1 か所** (engine の SetStatus の手前)。CLI もワークフローもここを通る。ワークフローには同じ規則を書かない (規則が 2 つになる)
- 既に ack 済みの high は自動では外さない (外すと、外した後に何が起きたかの意味が変わる。人が見て snooze / resolve にし直す)。
  3 節の「黙らせているもの」の先頭に必ず出す
- snooze と resolve は止めない。snooze は期日で必ず戻ってくる。resolve は再び観測されれば new になる
- 見本のワークフロー (`internal/repoinit/templates/workflows/arata-triage.yml` と `examples/audit-repo` の同じファイル):
  - 止められたら、ログの `ACK_REFUSED` を読んで (code は機械が読む値。ADR 0054)、Summary とログ (`::error::`) に案内を出す:
    「high 以上は ack できない。approve は allowlist.yaml の PR、期日を決めるなら snooze、直したなら resolve。どうしても ack するなら force」と playbook の場所
  - 入力 `reason` は `--reason` に、`github.actor` を `--by` に渡す
  - **入力 `force` (boolean、既定 false) を足す**。真なら `--force` を付ける。理由は今も必須なので、空の理由で force はできない (ワークフローの検査と arata の両方で止まる)。
    Summary の表に `force` の行を出す
  - 足す理由: ストアが S3 にある運用では、人の手元にストアを書ける認証が無い (ADR 0042)。ワークフローに force が無いと、正当な例外
    (例: 最も重い重大度が high のチェックで、終わった出来事だと確かめたもの) を扱う道が無く、ワークフローを手で直す運用が生まれる。
    force を明示の入力にし、理由と操作した人を残すほうが、記録が残る

### 3. 週次の報告に「黙らせているもの」の節を足す

- report.json に `silenced` を足す (互換の追加。`schema_version` は上げない。ADR 0054)。中身は 3 つ:
  - `findings`: acked / snoozed の finding。並びは重大度の高い順 (high 以上が先頭) → 黙らせた日の古い順。
    各 finding に、最後の操作 (action・by・reason・at・forced)、黙らせたときの重大度 (`suppressed_severity`)、snooze なら期日
  - `snooze_expiring`: 次の 7 日で期日が切れる snooze
  - `allowlist_expiring`: allowlist の `expires` が次の 30 日で切れる項目と、既に切れた項目。節 (principals・oidc の入り口など)・主体や対象・期限。
    `approved_by` は出さない (主体と期限があれば見直せる)
- 節を出すのは、プロファイルに `silenced: true` を書いたときだけ (暗黙の既定を持たない。ADR 0014)。`config init` の雛形は weekly のプロファイルに書く。
  既存の設定には足されないので、`config init --diff` で見える (利用者側の設定の直しは開発リードがリリースの後に行う)。
  7 日・30 日は固定値にする (設定は足さない。必要になったら足せる)
- report.md には同じ節を出す。理由は利用者の入力なので、コードの囲みに入れ、Markdown として解釈させない (見本のワークフローの Summary と同じ扱い)
- aratam: `silenced` があれば、通知に件数の 1 行を規則で足す (LLM を通さない)。例:
  「黙らせているもの: ack 3 件 (high 以上 1)・snooze 2 件 (7 日以内に期日 1)・allowlist の期限 30 日以内 1 / 切れた 0 (詳しくは report.md)」。
  high 以上の ack が 1 件でもあれば、その行を通知の重大度の下限に関わらず必ず出す。理由と操作した人は通知にも LLM の入力にも渡さない
  (理由は利用者が書いた文字列で、通知に要るのは「見直すべきものがある」ことだけ。ADR 0037)

### 4. `arata review --format json` の各 finding に、許す操作と根拠の文書を載せる

- 各 finding に `triage` を足す (互換の追加):
  `{"allowed": ["snooze","resolve"], "doc": "arata help ai playbook secret_access", "section": "片付け"}`
- 許す操作の表は、チェックと重大度から決める。**正は各 playbook の新しい「片付け」の節**。節は次の形の表にする:

  ```markdown
  ## 片付け

  | 重大度 | 許す操作 |
  |---|---|
  | high・critical | snooze・resolve |
  | medium・low | ack・snooze・resolve |
  ```

  その後に、操作ごとの使いどころを箇条書きで書く (secret_access なら「正規の読み手なら `baseline_days` が過ぎる日まで snooze」)。
- Go の表 (`internal/checks` か `internal/engine`) と playbook の表を、テストで突き合わせて固定する。テストは次も確かめる:
  - 全チェックの playbook に「片付け」の節がある (無ければ落ちる。playbook の必須の節に足す。ADR 0025)
  - high・critical の行に ack が無い (2 節と矛盾しない)
  - approve を含むのは、`arata approve` が受け付けるチェックだけ (new_principal・unknown_assume_role・iam_changes・access_denied の `--expected-denied` など、実装の判定と同じ関数で確かめる)
- `force` は表に載せない (例外の道で、許す操作ではない)
- 2 節の止める案内の文言も、この表から作る (approve を出すかどうかが表と一致する)
- schemas/review.schema.json は型から作り直す (`-update`)。`docs/ai/playbooks/*.md` はバイナリに埋め込むので、help ai のゴールデンも変わる
- あわせて、片付けの節と矛盾する既存の記述を直す (例: secret_access の playbook の「ack / snooze ... 重大度が上がれば再報告される」)

### 5. (後の段) ack の後に量が大きく増えたら、同じ重大度でも出直す

この ADR では実装しない。方向だけを決める。

- ack したときの量 (チェックごとに決めた項目) を残し、観測の量がその何倍かを超えたら、同じ重大度でも changed として再報告する。
  最初は secret_access (`distinct_secrets`) と access_denied (件数) から
- ack の見直しの期限 (例: 90 日で ack を open に戻す、または 3 節で目立たせる) を設定に書き、`config init --diff` で見える既定にする
- 倍率・項目・期限は、1〜4 を本番で回して、黙らせているものの数と中身を見てから決める

## 検討した選択肢

- **文書を強める (onboarding と playbook の注意を目立たせる、AI の手順に「必ず読む」と書く)**: 却下。今回はまさに文書があったのに読まれなかった。守りを読む人に任せない
- **ワークフローの入力の検査で high の ack を止める**: 却下。ワークフローは finding の重大度を知らない (ストアを読む前に検査する)。手元の CLI も止まらない。
  止める規則は arata の 1 か所に置く
- **high・critical の ack を例外なく止める (`--force` を作らない)**: 却下。終わった出来事だと確かめた high (導入作業の IAM 変更など) を、snooze の期日を延ばし続けるか、
  resolve にして次の観測で new に戻すしかなくなる。例外の道を、理由と記録を必須にして残す
- **チェックごとの「最も重い重大度」だけを止める (secret_access なら high、root_usage なら critical)**: 却下。ADR 0022 の再報告の余地の話だけなら正しいが、
  高い重大度を数の多さで流すことそのものを止めたい (onboarding の「critical / high を、数が多いことを理由に ack で流さない」)。規則が 1 つのほうが読み違えない
- **既に ack 済みの high を、移行で open に戻す**: 却下。人の判断を道具が黙って覆すことになり、戻した後の通知が「新しい出来事」に見える。3 節で必ず見せ、人が直す
- **記録を finding_events に足す** (`action` などの列と、`acked` / `snoozed` の種類): 却下 (1 節の理由)。期間レポートの数の意味を守る
- **記録を findings の列に足す** (最後の操作だけを持つ): 却下。履歴が残らず (2 回目の ack で 1 回目の理由が消える)、evaluate の書き戻しが列を引き継ぐ規則を持つことになる
- **`--reason` を全部の操作で必須にする**: 見送り。手元の既存の使い方を壊す。force だけ必須にし、見本のワークフローは今のまま理由を必須にする。
  必須にする要望が出たら、版を上げて Release の本文に書いて足せる
- **「黙らせているもの」を毎回の報告に出す**: 却下。hourly・daily の報告と通知に毎回同じ行が出て読まれなくなる。週次に 1 回、設定で出す
- **snooze の期日に上限を設ける (high 以上は 90 日まで、など)**: この ADR では入れない。遠い期日の snooze は 3 節の一覧に毎週出る。
  遠い期日で守りを外す使い方が実際に出たら、5 節の見直しの期限と一緒に決める

## 結果 (良い点・引き受けるコスト)

- 最も重い重大度の ack という落とし穴に、文書を読まなくても落ちない。落ちそうになったとき、何を使えばよいかと根拠の文書が出る
- 誰が・なぜ・いつ黙らせたかがストアに残り、Actions の保持期間で消えない
- 黙らせているものが週に 1 回、通知の 1 行と報告の節で目に入る。既に ack 済みの high もここで見つかる
- AI が片付けの案を出すとき、`arata review --format json` の `triage.allowed` を見れば、許されない操作を提案せずに済む。根拠の文書の場所も分かる
- 引き受けるコスト:
  - ストアのスキーマが 8 になる。古い版の arata は新しいストアを開けるが、記録を残さず守りも効かない (監査と片付けの版をそろえる)
  - schema 8 より前の ack / snooze には理由と操作した人が無い (「記録なし」と出す)
  - playbook が 1 節増え、全 23 本に表を書く。表と Go の表の 2 か所を持つが、テストで一致を固定する
  - 正当な high の ack は `--force` と理由が要り、一手間増える
  - プロファイルの設定が 1 つ増える (`silenced`)。既存の設定には自動で入らない
  - 量が増えた ack の出直し (5 節) が入るまでは、force で ack した high の後の本物は、重大度が上がらない限り報告されない。3 節の一覧に毎週出ることで補う

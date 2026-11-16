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

## 追記 (2026-11-17): 1〜5 の後にも残る穴

1・2 節を実装した後の main (909c1b4) を読み直して、次の穴が見つかった。6〜9 節を足し、5 節にも 1 つ足す。
実装の順は 3 → 4 (6 節を含む) → 7 → 8 とする (7 は小さいので、3 と並べて先に出してもよい)。9 節は 3 節に含める。

### 6. ack を止める条件を「その Key で重大度の上がる余地が無い」に広げる

- 事実: ack / snooze 中に出直すのは、観測の重大度が黙らせたときより重くなったときだけ (ADR 0022)。
  同じチェック・同じ Key で重大度が上がらないなら、**medium・low でも ack した時点で最後**になる。
  例: root_usage、unknown_assume_role、iam_changes の多く、new_principal、login_bruteforce、credential_hygiene、posture、log_hygiene
- 決定: 4 節の表を「チェック × 重大度 → **上がる余地** (その Key のまま、より重い重大度で観測されうるか)・許す操作」にする。
  **ack を許すのは、上がる余地がある行だけ**にする。high・critical の行は今までどおり ack を許さない (2 節)
- 許さない ack は、2 節と同じく `ACK_REFUSED` で止め、`--force` と `--reason` でだけ通す (守りを越える道は 1 つにする)。
  止める判定は 2 節と同じ 1 か所 (engine の SetStatus) で、4 節の表を引く
- 段の順: 4 節の PR で表を入れるときに、2 節の判定 (high 以上) を表を引く判定に置き換える。表のテストは次を確かめる:
  - high・critical の行に ack が無い
  - 上がる余地の無い行に ack が無い
  - 上がる余地は、チェックの実装 (Key ごとの重大度の決め方) と合う。チェックごとに、同じ Key でより重い重大度が出る観測をテストで作れるかで確かめる
- 「終わった出来事」の片付けは、event 型なら resolve を勧める (同じ Key で再び起きたら new として報告される。ack と違って最後にならない)。
  onboarding と playbook の「終わった出来事は ack」は、4 節の PR で表に合わせて直す
- 引き受けるコスト: 多くのチェックで ack に `--force` と理由が要る。正当な ack は、理由が残る代わりに一手間増える

### 7. 片付けで、待っていた定時の監査を取り消さない

- 事実: 片付けのワークフローは、定時の監査と同じ concurrency の group (`cancel-in-progress: false`) で動く。
  GitHub Actions の既定 (`queue: single`) では、1 つの group で待てるのは 1 つだけで、新しく入ったものが待っていたものを取り消して置き換わる
  (GitHub の文書「Control the concurrency of workflows and jobs」で確かめた)。
  片付けを流すと、待っていた定時の監査 (月曜の weekly など) が取り消されることがある。取り消された監査は aratam の step も走らないので、
  「実行されていない」の知らせも届かない
- 決定: 監査と片付けの group に **`queue: max`** を書く (同じ group に最大 100 件が待て、待ち始めた順に動く。`cancel-in-progress: false` と組める)。
  同じストアへの書き込みは今までどおり順番になり、待っていたものは取り消されない
  - 試しの実行 (`-dry-run` の付いた group) も同じにする (試しの実行どうしの取り消しも避ける)
  - 雛形 (`internal/repoinit/templates`) と `examples/audit-repo` (作り直し)、`examples/github-actions` のテストで `queue: max` を固定する
  - `queue` は GitHub の文書にある設定だが、CI の検査 (actionlint・zizmor・`tools/actionsgate`) が受け付けるかと、実際のリポジトリで
    待ちが積まれることは、実装の PR で確かめる (後者は開発リードがリリースの前に確かめる)
- 却下した案:
  - **片付けの group を分け、ストアの取り合いは arata の排他で守る**: S3 のストアの排他は条件付き書き込み (ADR 0034) だけで、
    監査の途中で片付けが確定すると、監査の確定が `STORE_CONFLICT` で失敗し、その回の監査の結果が失われる。片付けより監査のほうが失うものが大きい
  - **片付けは待たずに失敗させ、案内を出す**: 監査が走っているか・待っているかを知るには Actions の API (`actions: read`) を引く別のジョブが要り、
    確かめた後に監査が入ってくる隙も残る。権限と手順が増える割に、取り消しを止めきれない

### 8. 片付けの Summary に指摘の中身を出し、試し (dry-run) を足す

- Summary に、ID だけでなく、指摘の check・重大度・状態 (操作の前)・初出・要約・Key を出す (ID の取り違えに気づけるように)。
  値は `arata review --format json` の該当する finding から取る (機械が読む出力。ADR 0054)
  - Key と要約には ARN (アカウント ID) が入る。Summary はリポジトリの Actions を読める人に見えるので、**12 桁の数字は伏せる** (`************`)。
    ログには今までどおり出さない (Summary だけ)
- `arata ack` / `snooze` / `resolve` に `--dry-run` を足す。形の検査・finding の有無・2 節と 6 節の守りまで本番と同じに行い、
  何をどう変えるかを出して、ストアを書かない (`Commit` しない)。止められるなら本番と同じ code と終了コード (`ACK_REFUSED`・2) で終わる
- ワークフローに入力 `dry_run` (boolean、既定 false) を足し、真なら `--dry-run` を付ける。Summary に「試し (ストアは変えていない)」と出す

### 9. 期日を過ぎた snooze を見えるようにする (3 節に含める)

- 事実: event 型の finding は、観測されなくても resolved にならない (ADR 0005)。snooze の期日を過ぎても再び観測されなければ snoozed のまま残り、
  `arata review` の既定 (open・acked) にも報告にも出ない。event 型の ack は、出直さない限り永久に残る
- 決定: 3 節の「黙らせているもの」に `snooze_expired` (期日を過ぎても snoozed のままのもの) を足し、件数の 1 行にも出す。状態は自動では変えない (2 節と同じ理由)

### 5 節への追記

- still_open の finding の data は、最初に報告したときのまま更新されず、Slack には件数しか出ない。量が大きく増えたら、5 節の「量で出直す」と同じ仕組みで出し直す

### 文書とコードの食い違いの直し

この追記の PR で直す。採用済みの ADR 0005 は書き換えない。0005 の例のうち `secret_access_unknown`・`console_login`・`posture_*` は実装に無い
(`secret_access` と `posture` に置き換わった。`console_login` は実装していない)。設計書の該当箇所に注記する。

- 設計書 6-2 の「ack は週次の未対応一覧に残る」: 報告には出ず、`arata review` の未対応一覧に残る (週次の「黙らせているもの」には 3 節から出る)
- 設計書 6-2 の still_open: still_open は「その run で同じ内容で再び観測されたもの」。event 型は観測の無い窓では出ず、未対応の全部は `arata review`
- onboarding の「snooze は観測されなくなれば解消」: 解消になるのは state 型だけ。event 型は snoozed のまま残る (9 節)
- 設計書の設定例とチェックの表にある、実装に無いチェックの名前

### この ADR の外 (ロードマップに書く)

- allowlist_stale (承認した主体の長い不在) と、承認した主体の振る舞いの変化
- Actions の雛形に hourly の定時が無い (root_usage の critical でも最大で約 1 日遅れる)。ADR 0064 の `collect --incremental` と合わせて別に扱う

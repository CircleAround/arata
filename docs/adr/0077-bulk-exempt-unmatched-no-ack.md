# 0077. `bulk-exempt-unmatched:` の medium は ack を止め、片付けの表に Key の接頭辞の行を足す

- 日付: 2026-11-20
- 状態: 採用

## 背景

ADR 0076 の 5 節で、`bulk: exempt` の組を「ECS が発行した認証情報の直後でない」読み取りで読んだ主体を、secret_access の medium
(Key は `bulk-exempt-unmatched:<主体の ARN>`) で報告することにした。ack は「通常の medium と同じ扱い」とし、片付けの表 (ADR 0068) では ack を許していた。

実装 (0076) のレビューで、この扱いが目的に合わないと分かった。

- 片付けの表の secret_access の medium・low は「上がる余地あり」で ack を許す。初出の medium (Key は主体の ARN) は、同じ主体が後で一括読み出しをすれば
  同じ Key で high になるので、ack 中でも出直す (ADR 0022)
- `bulk-exempt-unmatched:` の medium は、同じ Key のまま high にならない (一括読み出しの high は主体の ARN の Key に出る)。Fingerprint は重大度と理由の集合なので、
  ack すると、同じ理由 (`no_key` / `no_issuance` / `outside_window`) の外せない読み取りがまた起きても出直さない
- 版を上げた直後の 1 回は、以前の版の記録にハッシュが無く `no_key` / `no_issuance` で鳴りうる (0076 の 4 節)。これを ack されると、以後の盗まれた認証情報の利用が
  同じ理由で黙り、この報告を足した目的 (盗まれても気づける) が消える。resolve なら、再び起きたときに新規として戻る

片付けの表は今「チェック × 重大度」で行を引くので、secret_access の medium のうち一部の Key だけの ack を止める形が無い。

## 決定

### 1. `bulk-exempt-unmatched:` の medium は ack を止める (0076 の 5 節の ack の扱いを置き換える)

- 許す操作は snooze・resolve (上がる余地なし)。`arata ack` は ACK_REFUSED で止め、resolve と snooze を案内する (high と同じ扱い。`--force --reason` でだけ通す。ADR 0068)
- playbook には「ack できない。確かめて、移行の 1 回・窓の不足 (設定を延ばす) なら resolve」と書く
- 0076 のほかの決定 (medium の条件・data・high のときに重ねないこと) は変えない

### 2. 片付けの表に「Key の接頭辞の行」を足す

- 表の行 (`checks.TriageRow`) に `KeyPrefix` を足す。Key がその接頭辞で始まる finding には、接頭辞の行が先に当たり、無ければ今の接頭辞の無い行が当たる
- 接頭辞の行は上がる余地「なし」だけ (一部の Key を守りの側に倒すためのもの。テストで固定する)。同じ接頭辞の中で同じ重大度は 1 行だけ
- playbook の「片付け」の表では、重大度の欄に `medium (`bulk-exempt-unmatched:`)` のように接頭辞を書く。表と Go の写しの突き合わせ (ADR 0068) はこの形も読む
- 表を引く関数 (`TriageRowOf`・`TriageAllows`) は Key も受け取る。ack の止め (`ackGuarded`) と、review・report.json の `triage.allowed` は、同じ関数で finding の Key を渡す

## 検討した選択肢

- **0076 のまま ack を許す**: 背景のとおり、移行の 1 回で ack されると以後の利用が黙る。却下 (レビューで決定)
- **この medium の Key を主体の ARN にそろえ、初出の medium・一括読み出しの high と同じ行にする**: 同じ Key で high に上がる余地ができ、表を変えずに済む。
  ただし初出の medium と外せない読み取りの medium が 1 件にまとまり、片方を片付けるともう片方も片付く。理由ごとの Fingerprint も初出の集合と混ざる。却下
- **重大度を high にする**: 表を変えずに ack を止められる。0076 の検討のとおり、窓の設定の不足 (延びた環境) でも鳴るので high は重すぎる。却下
- **チェックの側で、ack 中でも理由が出るたびに Fingerprint を変える (毎回 changed で出直す)**: ack が実質効かなくなるうえ、ack の意味 (再報告しない) と食い違う。止める方が明快。却下

## 結果 (良い点・引き受けるコスト)

- 外せない読み取りの報告は、resolve か snooze の期日の後に、また起きれば必ず出直す。移行の 1 回で黙ることが無い
- 片付けの表が「一部の Key だけ」を表せるようになる (今後、同じ重大度の中で守りを分けたいチェックにも使える)
- 引き受けるコスト: 表を引く関数の引数が増える。移行の 1 回と窓の設定の不足の medium は、ack ではなく resolve (また起きれば新規として出る) で片付ける
- 実装は `internal/checks/triage.go` (行の接頭辞・引く関数)・`internal/engine/triage.go` (Key を渡す)・playbook `secret_access.md` の表・onboarding・設計書。
  テストは、接頭辞の行の決まり・playbook との突き合わせ・`ackGuarded` と `triageOf` (接頭辞の Key は ack を止め、同じ重大度のほかの Key は今どおり) を固定する

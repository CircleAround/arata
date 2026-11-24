# 0084. 前提で止めるルール (国・IP セット・Host 名・レートベース・IP の評判) の BLOCK を誤検知の候補から外し、意図して止めるルールを設定で書けるようにする

- 日付: 2026-11-24
- 状態: 採用 (オーナーの決定。2026-11-24)

## 背景

waf_review の `false_positive` (ADR 0023) は、探索パス (`probe_paths`) にも sign-in のパスにも当たらないパスを、すべて「正規の画面らしい」とみなす。
外しているのは、レートベースのルールと、IP の評判のマネージドのグループ (`IpReputation` / `AnonymousIp`) だけだった。

その結果、止めるのが意図のルールで、提案 (`count_first`) と low の finding が大量に出た。

- 国で止めるルール (GeoMatch)
- 正しい Host 名で来ない通信を止めるルール (SingleHeader の host の照合)
- パスで止める自作のルール (管理画面など)

これらは「多数の IP から BLOCK される」のが正常で、「このパスだけ COUNT にする」を勧めると、止めるべき通信を通す方向に間違える。
`waf-config` (ADR 0023) は自作のルールを `type: regular` の 1 種類にまとめ、文の種類を残していなかったので、waf_review は見分けられなかった。

## 決定

### 1. 前提で止めるルール

- 次の条件を**前提の条件**とする: GeoMatch、IPSetReference、SingleHeader の `host` (大小文字を問わない) への ByteMatch / RegexMatch / RegexPatternSetReference。
  レートベースのルールと、IP の評判のマネージドのグループは、今までどおり種類 (`type`・`managed`) で見分ける (どれも前提で止めるルールに含める)
- 前提で止めるルールの BLOCK は、`false_positive` の提案にも finding にもしない。消さずに、今までと同じ observation (`about: false_positive`、`reason: excluded_by_rule`) に、
  理由の文 (前提で止めるルールで、多数の IP を止めるのが意図) と根拠の数字を添えて残す
- And・Or・Not の組み合わせは、**前提の条件を 1 つでも含めば前提の側**にする。そのうえで次のように分ける
  - And (と Not の下の Or) は、子のどれかが前提なら**前提** (前提の条件が当たらなければ止めない)。`excluded_by_rule`
  - Or (と Not の下の And) は、子のすべてが前提なら**前提**。一部だけが前提なら**前提の一部** (`premise_partial`)。
    Or の中のパスの照合だけで止めた可能性があり、どちらで止めたかは設定からもログからも分からない。「迷ったら提案しない」(ADR 0023) に合わせて提案も finding もせず、
    observation (`reason: undetermined`) に「見分けられない」と書いて残す。`excluded_by_rule` にしないのは、決まった除外に当たったと言い切れないため
  - Not は中の文の And と Or を入れ替えて見る (De Morgan。`Not(And(国, パス))` は `Or(Not 国, Not パス)` なので一部、`Not(Or(国, パス))` は前提)。葉の分類は Not で変わらない (Not 国 も国で止める)
  - 入れ子は 20 段まで読み、それより深いものは読めない (不明) とする

### 2. waf-config の snapshot に文の種類を残す

- 自作のルール (`type: regular`) に 2 つの項目を足す
  - `block_basis`: 何を根拠に止めるか。`premise` (前提) / `premise_partial` (Or の一部だけが前提) / `path` (パスの照合だけ) / `other` (前提を含まない他の照合。SQLi・クエリ・本文・ラベルなど) / `unknown` (読めない)
  - `statement_kinds`: 葉の文の種類を重複なく並べたもの (`geo_match`・`ip_set`・`host_match`・`uri_path_match`・`byte_match`・`regex_match`・`regex_pattern_set`・
    `size_constraint`・`sqli_match`・`xss_match`・`label_match`・`asn_match`・`unknown`)。evidence にも添える
- **読めない文は不明** (`unknown`) とし、提案しない側に倒す (observation `undetermined`)。知らない文 (SDK に新しい文が足された)、欠けた文 (FieldToMatch が無い・空の And)、深すぎる入れ子。
  ただし And の中に前提の条件があれば、他の子が不明でも前提にする (前提が当たらなければ止めないことは確か)
- 葉の分類は Statement の木を読む `account.WAFStatementBasis` が決め、ファズテスト (`FuzzWAFStatementBasis`) で規則を固定する:
  前提の葉を含む木だけが前提か前提の一部になる、パスの葉だけの木はパス、Not を 2 つ重ねても変わらない
- Statement の全体は今までどおり保存しない (IP セット・国・Host 名・パスの値は持たない)
- **前の版で取った snapshot** (項目が無い) では、今と同じ判定にする (提案は `count_first`、多数の IP なら low の finding)。次の weekly の snapshot から新しい判定になる
- マネージドのグループ (SQLi など) と自分のルールグループの参照は対象にしない (`block_basis` を持たない)。中のルールの文は読まない (ADR 0070 と同じ) ので、今までどおりの判定

### 3. 意図して止めるルールの設定 (`checks.waf_review.intended_block_rules`)

- `intended_block_rules: [<ルール名>, ...]` を足す。既定は空の一覧で、雛形と `config init --diff` に出る (暗黙の既定を持たない。ADR 0014)
- 書き方は、WebACL のルール名か、`<グループのルール名>/<グループの中のルール名>` (ログの key と同じ書き方)。WebACL のルール名がグループなら、中のルールすべてに当たる。
  すべての WebACL に効く (WebACL の名前では絞らない)
- 一致した BLOCK は提案も finding もせず、observation (`reason: excluded_by_config`) に残す
- `config check` (設定の読み込み) で、空の名前・重複・ルール名に使えない文字 (英数字・`_`・`-` 以外。公式の API の Rule.Name の形)・`/` が 2 つ以上・1 区間が 128 文字超えを誤りにする
- 判定のパラメータなので、overrides でも変えられる

### 4. パスの照合だけで止める自作のルール

- `block_basis: path` (葉がすべて UriPath への ByteMatch / RegexMatch / RegexPatternSetReference) のルールの `false_positive` は、`stage` を `count_first` から `review` に下げる。
  本文は「このパスを止めるのが意図かを見直す (意図なら intended_block_rules に書く)」で、COUNT にすることを勧めない
- **low の finding は出さない**。パスで止める自作のルールは、そのパスを止めるのが狙い (管理画面・使っていない入口) のことが多く、多数の IP から当たるのは正常な場合がある。
  finding (差分判定・通知・片付け) に乗せると、意図した BLOCK が毎週の片付けの対象として残り続ける。見直しの材料は proposals に残るので、事実は伝わる

### 5. 2xx / 3xx を返したパスだけを正規らしいとする案

- 「正規の画面らしい」を、アプリが 2xx / 3xx を返したパスに絞る案は、この ADR では扱わない。**別の ADR で扱う** (アクセスログとの突き合わせが要り、集計とソースの設計が変わる)

## 互換

- report.json の形 (`schemas/`) は変えない。`proposals` の `stage` と `reason` は既存の値、evidence に `block_basis`・`statement_kinds` が増える (新しい snapshot のときだけ)
- 前提で止めるルールの `false_positive` の提案と low の finding は出なくなる。既に出ていた finding は state 型なので、次の weekly で観測されなくなり解消になる
- パスだけで止めるルールの提案は `review` になり、その finding も次の weekly で解消になる (Release の本文に書く)
- 前の版の snapshot では判定は変わらない。新しい snapshot (次の weekly の waf-config) から効く
- 読み取りロールに足す権限は無い (GetWebACL の結果の Statement を読むだけ)

## 検討した選択肢

- **Or の一部だけが前提のものを前提 (`excluded_by_rule`) にする**: 採らない。パスの照合で止めた BLOCK を「決まった除外」と言い切ることになる。提案しないのは同じだが、理由は「判断できない」が正しい
- **Or の一部だけが前提のものを提案する (前提ではない枝で止めたとみなす)**: 採らない。前提の枝で止めた BLOCK に「COUNT にする」を勧めることになり、危ない方向に間違える
- **Not を中の文と同じに扱う (De Morgan を使わない)**: 採らない。`Not(And(国, パス))` はパスだけでも止めるので、前提と言い切れない
- **Statement の木を snapshot にそのまま (または形だけ) 残し、waf_review で分類する**: 採らない。Statement の全体は保存しない (ADR 0023)。分類の結果と葉の種類で足りる
- **ASN の照合 (AsnMatch) も前提の条件にする**: この ADR では入れない (決定の対象の一覧に無い)。`other` として扱い、意図した BLOCK なら `intended_block_rules` に書く。実データで多ければ別に決める
- **パスで止めるルールの low の finding を残す**: 採らない (4 節)
- **intended_block_rules を `<WebACL>|<ルール>` で書けるようにする**: 見送り。同じ名前のルールを WebACL ごとに分けて扱う必要が出たら足す

## 結果 (良い点・引き受けるコスト)

- 良い点: 止めるのが意図のルールの提案と finding が消え、本当に誤検知の疑いがあるもの (マネージドのルール・前提を含まない自作のルール) が目立つ。消したものも observation で数字が残る
- コスト: 葉の分類を足すたびに snapshot の意味が変わる (分類は collector で決まり、次の snapshot から効く)。Or を含む複雑なルールは提案されなくなる (observation に残る)。
  自分のルールグループの中の国・IP セットのルールは見分けられない (`intended_block_rules` に書いてもらう)

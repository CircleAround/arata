# 0086. Public Access Block の変更を、前の状態 (posture の snapshot か前の Put / Delete の記録) と比べて「開けた」「締めた」「前が分からない」に分ける

- 日付: 2026-11-25
- 状態: 採用 (重大度と条件はオーナーの決定。2026-11-25)

## 背景

public_exposure (ADR 0026) は、`PutBucketPublicAccessBlock`・`PutPublicAccessBlock`・`PutAccountPublicAccessBlock` の要求に
false の項目 (collector が取り出す data の `pab_disabled`) が 1 つでもあれば、前の状態を見ずに high の「<項目>=false で開けた」にしている (`exposureOf`)。

実際の記録で、次の形が high の「開けた」と報告された。

- アカウント単位の Public Access Block が無い (設定なし) 状態から、
  `BlockPublicPolicy=true`・`RestrictPublicBuckets=true`・`BlockPublicAcls=false`・`IgnorePublicAcls=false` で作った
- 実際は 2 項目を有効にした「締める」操作で、公開を許す範囲は狭まった

CloudTrail の記録には新しい設定しか無く、前の値が残らない。要求だけでは、開けたのか締めたのかが分からない。
一方、arata は前の状態の材料を 2 つ持っている。

- (a) weekly の posture の snapshot (`posture_item` の `s3_public_access_block`)。アカウント単位の 4 項目と、設定が無いこと
  (`NoSuchPublicAccessBlockConfiguration` → `configured: false`) を持つ (`internal/collect/account/posture.go` の `publicAccessBlock`)
- (b) 同じ対象への、前の Put / Delete の記録 (保存済みの注目イベント。公開設定の変更は注目イベントに残している)

## 決定

### 1. 前の状態の決め方

- 比べる相手は、**操作の時刻より前のうち、最も新しい材料 1 つだけ**にする。古い材料に戻って補わない (古い状態と比べると、その間の変更を見落とす)
  - (a) snapshot は、取得した時刻 (`SnapshotItem.Time`) が操作の時刻より**前**のときだけ使う。同じ時刻か後なら使わない (操作の結果を含むかが分からない)
  - (b) 記録は、同じ対象への、成功した (errorCode なし) `Put*PublicAccessBlock` / `Delete*PublicAccessBlock` で、操作の時刻より前のもの。
    同じ run の窓の中の、先の操作も含む (1 日に 2 回変えたら、2 回目は 1 回目と比べる)
  - snapshot の後に記録があれば記録を使う。記録と snapshot が同じ時刻なら記録を使う (記録は要求そのもの)
- 「同じ対象」は今の Key の資源 (`target`) と同じ決め方: アカウント単位の操作は `account`、バケット単位は `bucket` の名前
- 材料から得る前の状態は次のどれか
  - `configured: false` (設定なし): snapshot の `configured: false`、または前の記録が `Delete*PublicAccessBlock`
  - 4 項目の true / false: snapshot の 4 項目、または前の Put の要求の 4 項目
  - 分からない: 材料が無い、最も新しい材料が読めない (snapshot の項目が `unknown`、前の記録から 4 項目が決まらない。3 節)。
    最も新しい材料が読めないときに、それより古い材料には戻らない
- 前の記録を探す範囲は、使える snapshot があればその時刻から、無ければ保存済みのイベントのすべて (`retention.events` の範囲)。
  チェックの中で 1 回だけ引く (操作ごとに引かない)
- `Needs` は `trail_event` のままにする。snapshot は**あれば使う**。posture のソースを持たない設定では (b) だけで比べる (チェックが skip にならない)

### 2. 判定

設定なしは「4 項目すべて false」と同じに扱う。4 項目は `BlockPublicAcls`・`IgnorePublicAcls`・`BlockPublicPolicy`・`RestrictPublicBuckets`。

| 前の状態 | 今回の要求 | 判定 (`transition`) | 重大度 | 見出しの中身 |
|---|---|---|---|---|
| (問わない) | `Delete*PublicAccessBlock` | `opened` | high | 今までどおり「Public Access Block の削除で公開を許す状態に」 |
| 分かる | 前に true だった項目が 1 つでも false になった | `opened` | high | 今までどおり「<false の項目>=false で開けた」。前から false だった項目も並べる (今と同じ)。true → false になった項目は data の `newly_disabled` |
| 分かる | true → false は無く、false → true が 1 つ以上ある | `tightened` | **info** | 「<有効にした項目>=true で締めた (無効のまま: <項目>)」。無効のままが無ければ括弧を出さない |
| 分かる | 何も変わらない (false のまま、新しい true も無い) | (報告しない) | — | — |
| 分からない | false の項目がある | `prior_unknown` | **medium** | 「前の状態が分からない。今は <false の項目>=false」 |
| (問わない) | 4 項目すべて true | (報告しない。今と同じ) | — | — |

- 1 行目と 2 行目はオーナーの決定 (これまでどおり high)
- `prior_unknown` を medium にするのはオーナーの決定。low にしないのは、記録の外では、攻撃者が締めを外す操作 (true → false) も同じ形に見えるため
- バケット単位の `PutBucketPublicAccessBlock` は、posture がバケットごとに取っていないので (b) だけで比べる。前の記録が無ければ `prior_unknown`
- `PutPublicAccessBlock` は今の `target` の決め方に従う (バケットの名前があればバケット単位)

#### 締めた操作を info にする理由 (low にしない)

- 締めた操作は、公開を許す範囲を狭める変更で、侵害の兆候ではない。public_exposure の役目 (外に開いた変更を見せる) の外にある
- 無効のまま残った項目は、weekly の posture が状態として high で報告する (アカウント単位。`s3_public_access_block`)。
  low の finding にすると、同じ弱さを 2 か所で片付けることになり、しかも改善の操作のほうを毎回片付けの対象に残す (ADR 0084 の 4 節と同じ考え)
- 消さずに info で残すのは、「締めた」と判定した根拠 (前の状態の出どころと時刻) を report に残し、判定の誤りを人が追えるようにするため
- バケット単位の締めた操作で無効のまま残った項目は posture では見えない。ただしアカウント単位の Public Access Block が有効なら、そちらが上書きする。
  見落としが心配なら、access_analyzer がバケットの公開を状態として報告する

#### 何も変わらない操作を報告しない理由

- 公開の範囲が変わっていない。同じ設定の書き直し (IaC の再適用など) で毎回出るのは雑音になる
- 残っている弱さは posture (アカウント単位) と access_analyzer が状態として報告する
- 前の状態が分かっていることが前提。分からないときは `prior_unknown` で報告する

### 3. collector が取り出す値

- 今の collector は false の項目 (`pab_disabled`) だけを、1 つ以上あるときだけ残す。4 項目すべて true の要求と、要求の形が読めないもの
  (`PublicAccessBlockConfiguration` が無い) とが、どちらも「`pab_disabled` が無い」になり、(b) の前の状態に使えない
- 次の値を足す (どれも requestParameters から取り出す。値は 4 項目の名前だけ)
  - `pab_parsed: true`: 4 項目を読めた (要求に設定の形があった)
  - `pab_enabled`: true の項目
  - `pab_disabled`: false の項目 (今と同じ。省略は false。API の既定)
- **前の版で集めた記録** (`pab_parsed` が無い): `pab_disabled` があれば、残りの項目を true とみなす (前の版も 4 項目すべてを見て false を並べていたので、補集合で決まる)。
  `pab_disabled` が無ければ「すべて true」と「読めなかった」を見分けられないので、前の状態としては**分からない**にする

### 4. data に足す項目

| 項目 | 中身 |
|---|---|
| `transition` | `opened` / `tightened` / `prior_unknown` |
| `prior_source` | `snapshot` / `event` / `none` (材料が無い) / `unreadable` (最も新しい材料が読めない) |
| `prior_time` | 比べた材料の時刻 (snapshot の取得時刻、または記録の時刻)。`none` のときは無い |
| `prior_api` | `prior_source: event` のとき、前の記録の操作 (`s3:PutAccountPublicAccessBlock` など) |
| `prior_configured` | 前の状態に設定があったか (false = 設定なし・削除の後)。分からないときは無い |
| `prior_enabled` | 前の状態で true だった項目 (空の一覧もあり得る)。分からないときは無い |
| `enabled` | 今回 true にした項目 |
| `newly_enabled` | false → true になった項目 (`tightened` で 1 つ以上) |
| `newly_disabled` | true → false になった項目 (`opened` の Put で 1 つ以上) |
| `still_disabled` | 前も今も false の項目 |

- 同じ Key にまとめた複数の呼び出しでは、`prior_*` は Key の最初の呼び出しのもの (今の `a.extra` の作り方と同じ)
- 前の状態の値は、snapshot も記録も、ストアから読み戻した値を 4 項目の名前の一覧と真偽値だけに絞って使う (知らない名前は捨て、読めなければ「分からない」)

### 5. Key と Fingerprint

- Key の「開いた中身」(`exposure`) は判定ごとに分ける
  - `opened`: 今と同じ (`BlockPublicAcls=false,IgnorePublicAcls=false` / `deleted`)。既にある high の finding と同じ Key のまま
  - `tightened`: `tightened:<有効にした項目>=true` (例 `tightened:BlockPublicPolicy=true,RestrictPublicBuckets=true`)
  - `prior_unknown`: `prior_unknown:<false の項目>=false`
- 分ける理由: 同じ要求でも判定が違えば別の出来事として扱う。同じ Key に high と info が入ると、片付けの表の「上がる余地」が読めなくなる
- Fingerprint は今の形 (重大度 + IP 集合 + 資源 + 開いた中身) のまま。`exposure` に判定が入るので、判定が変われば Fingerprint も変わる。
  `prior_time` などの前の状態の値は Fingerprint に入れない (snapshot の入れ替えで、同じ出来事の Fingerprint が揺れないように)

### 6. 移行

- 古いストア (posture の snapshot が無い、または前の版で集めた記録だけ): 1・3 節のとおり、使える材料が無ければ `prior_unknown` (medium)。
  アカウント単位の操作でも、posture のソースが無い設定では (b) だけで比べる
- 版を上げた後の初回の評価では、前の記録が貯まっていないので、バケット単位の Put で false の項目があるものの多くは `prior_unknown` になる
  (今までの high から medium に下がる)。Release の本文に書く
- 既に出ている high の finding は、event 型なので消えない。再評価で同じ Key の high が出直すこともない (Key が変わる)
- 前の版で集めた記録の読み方は 3 節

### 7. playbook・threats・ファズ

- playbook (`docs/ai/playbooks/public_exposure.md`) は実装の PR で直す: 重大度の表 (`opened` high・`tightened` info・`prior_unknown` medium、変化なしは報告しない)、
  data の一覧 (4 節)、「判断の分かれ目」に `prior_unknown` の確かめ方 (今の設定を `get-public-access-block` で読み、保存の範囲より前の CloudTrail を見る) と、
  `tightened` を「前の状態の出どころと時刻を確かめてから」読むこと、片付けの表に info の行 (上がる余地なし。snooze・resolve)
- threats (`docs/threats.md`、ADR 0058): 重大度が変わるので、実装の PR で対応する公開の事例を探し直す。見つからなければ今の「対応する公開の事例はまだ無い」のまま
- ファズ (ADR 0041): 要る。前の状態と要求から判定を決める関数は、ストアから読み戻した値 (ログ由来) を解釈する。`FuzzPABTransition` を足し、次の規則を固定する
  - `Delete*` は常に `opened` (high)
  - 前の状態が分かり、前の true の項目が今の false に 1 つでも入れば、必ず `opened` (high)。締めた操作 (info) に落ちない
  - `tightened` は、true → false が無く、`newly_enabled` が空でないときだけ
  - 前の状態が分からず false の項目があれば、medium より下にならない
  - `enabled`・`still_disabled`・`newly_disabled` は互いに重ならず、4 項目の名前だけを含む
  - collector の `pab_enabled` / `pab_disabled` / `pab_parsed` は既存の `FuzzNormalizeEvent` に seed を足し、「2 つの一覧は重ならず、合わせて 4 項目」を規則にする

## 互換

- report.json の形 (`schemas/`) は変えない。data の項目が増え (4 節)、重大度 `info` の public_exposure と、Key の接頭辞 `tightened:`・`prior_unknown:` が増える
- 重大度が下がる場合がある (前が分からない Put は high → medium、締めた Put は high → info、何も変わらない Put は報告しなくなる)。Release の本文に書く
- hourly の速報 (ADR 0082。`min_severity: high`) には、`prior_unknown` (medium) は載らなくなり、daily に残る
- 読み取りロールに足す権限は無い (posture の既存の `s3:GetAccountPublicAccessBlock` と、保存済みのイベントを使う)
- 設定項目は足さない (前の状態と比べるのは判定の規則で、選べるものではない)

## 検討した選択肢

- **要求だけで判定し続ける (今のまま)**: 採らない。締めた操作を high の「開けた」と言い、片付けで「誤検知」に慣れさせる
- **true の項目がある Put を一律に下げる**: 採らない。前に 4 項目 true だったものを 2 項目 false に戻す操作 (開けた) も、同じ形に見える
- **前が分からないものを low にする**: 採らない (オーナーの決定)。記録の外では、締めを外す操作も同じ形に見える
- **前が分からないものを high のままにする**: 採らない (オーナーの決定)。版を上げた直後とバケット単位の Put の多くが high のままで、背景の誤りが残る
- **締めた操作を low にする**: 採らない (2 節)
- **締めた操作を報告しない**: 採らない。「締めた」と判定した根拠を残し、判定の誤り (材料の取りこぼし) を人が追えるようにする
- **古い材料に戻って補う (最も新しい材料が読めないとき)**: 採らない。間の変更を見落とし、開けた操作を締めたと言う方向に間違え得る
- **操作の時刻より前の snapshot を履歴として持つ (raw の古い snapshot を読む)**: 見送り。今のストアは最新の snapshot だけを引ける (`store.Query.Snapshot`。ADR 0015)。
  weekly の snapshot が操作の直後に入れ替わった場合に `prior_unknown` になるのは、安全な側 (medium) なので引き受ける。実データで多ければ別に決める
- **posture をバケットごとに取る**: 採らない。バケットの数だけ API を呼び、読み取りロールの権限も広がる。(b) で足りる

## 結果 (良い点・引き受けるコスト)

- 良い点: 締めた操作が「開けた」と報告されなくなり、high の「開けた」は前の状態と比べて確かなものだけになる。判定の根拠 (前の状態の出どころと時刻) が data に残る
- コスト:
  - 材料の取りこぼし (CloudTrail の収集が欠けた期間に、締める操作があった) では、前の状態を実際より開いていると見て、開けた操作を「締めた」(info) と言い得る。
    逆の取りこぼし (開ける操作を落とす) は、前を実際より閉じていると見るので high の側に倒れる
  - weekly の snapshot が操作の直後に入れ替わると、アカウント単位でも `prior_unknown` になる (前の snapshot を引けない)
  - バケット単位は記録が貯まるまで `prior_unknown` が多い
  - 前の記録を引く分、チェックの読み取りが増える (公開設定の操作の名前で絞った 1 回)

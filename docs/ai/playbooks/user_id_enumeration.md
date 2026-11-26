# user_id_enumeration: ログインした利用者による ID の総当たり

## この指摘の意味

アプリのログ (`format: request_lines` でユーザー ID を読むソース) で、1 人のログインした利用者が、ID を含むパスの型 (`/orders/:id` など。`path_ids`) で、
1 日にふだんより多くの異なる ID を開いた (daily)。他人の記録を順に開いて認可の抜け漏れを探す動き (IDOR の試し) の兆候。
**事実 (異なる ID の数・そのうちの成功と拒否・メソッド) の報告であり、遮断の提案ではない。**

- Key は利用者 (`<kind>:<id>`。例 `user:42`)。重大度は medium。条件を満たした型の中に、拒否 (`denied_statuses`) が `high_min_denied` 以上で成功が 1 つ以上のものがあれば **high**
- 理由 (`reasons`): `above_app_band` アプリの平常帯 (ふだんのその型で最も多い利用者の値の中央値 × `app_factor`) を超えた / `above_user_band` 本人の平常帯も超えた /
  `new_user` 本人の平常帯が無い (新しい利用者。アプリの帯と下限だけで判定) / `window` 直近 `window` 日の和で超えた (ゆっくりした試し) /
  `success_amid_denied` 拒否の多い範囲の中で開けた ID がある (high) / `success_only` 成功だけ (拒否が `high_min_denied` 未満)
- data: `user` (`kind`・`id`)、`day` (UTC)、`templates` (条件を満たした型を異なる ID の多い順に 5 つ。各々 `ids`・`ids_ok`・`ids_denied`・`methods`・`app_band`・`user_band`・
  `denied_redirects` (3xx で拒否に数えた ID の数。`denied_statuses` に 3xx を書いたときだけ)・`window`)、`templates_matched`、`related` (同じ日に条件を満たしたほかの利用者ごとのチェック)
- 異なる ID の数は**その日の正確な異なり**。窓の値は日ごとの値の和で、日をまたいで同じ ID を開けば重ねて数える
- arata は ID の値を持ち帰らない (Insights の中で数えるだけ)。どの ID が成功したかは、下の手順で原本を引く

## まず確かめること

1. `related` と、同じ利用者の `user_denied`・`user_path_breadth` を `arata review --format json` で見る。束で出ていれば同じ試しとして扱う
2. **high (`success_amid_denied`) は最優先。** 拒否の多い範囲で開けた ID は、他人のデータを開けた可能性が最も高い。その ID の持ち主が本人かをアプリの側で確かめる
3. **`success_only` は、認可がまったく効いていない最悪の場合でもある。** まず、その利用者が自分のデータを見ているのか (出力・一括の閲覧) を確かめる。
   その型が本人のデータだけを返す作りか (他人の ID で 403・404 を返すか) も、アプリの作りで確かめる
4. 原本の Insights で、その日・その利用者の要求を引く (期間は `day` の 1 日に絞る。スキャン量で課金される)。request_lines では 2 段で引く:
   `fields @message | filter @message like "actor kind=user id=42" | parse @message /\[(?<rid>[A-Za-z0-9_@-]+)\]/ | stats count(*) by rid | limit 1000` で request_id を集め、
   `fields @timestamp, @message | filter @message like "<request_id>"` で Started・Completed の行を見る (成功した ID と、その持ち主を確かめる)。
   拡張子 (`.json` など) は型から外してあるので、どの形式で開いたかもここで見る
5. `denied_redirects` があるとき: `denied_statuses` に 3xx を書いている。**まず、その型が本人の記録でも転送するか** (ダウンロードの画面から保存先への 302、取り消した記録を一覧へ戻す 302 など) を確かめる。
   本人の記録でも転送する型なら、200 と 302 が混ざるだけで high になりうる (誤り)。`exclude_templates` に書く
6. `methods` に PATCH・PUT・DELETE があれば、読み出しではなく書き換えの試し。権限の印 (`is_admin` など) の書き換えをアプリの記録で確かめる

## 判断の分かれ目

- **正規の可能性が高い**: 本人のデータの一括の閲覧・出力 (成功だけで拒否が無い)、だれでも見られる公開の画面の巡回 (`exclude_templates` に書く)、社内の担当の操作
- **要確認**: 拒否が多い (他人の ID を順に試した形)、拒否に混ざる成功 (high)、作ったばかりの利用者 (`new_user`)、何日にも分けた試し (`window`)
- 型の値に名前・ログイン名が残っているなら、`path_ids.templates` に `:id` として書き足す (`arata doctor` の `path_ids` の行。`arata help ai user_id`)

## 対処の選択肢

**止めることを勧めない。** 確認と保留の運用へつなぐ。変更は人が判断して実行する。LLM は提案まで。

1. **確認**: 成功した ID の持ち主が本人かを、アプリの運営者が確かめる。他人のデータなら、認可の抜け漏れとしてアプリの開発者に回す (直すのはアプリの側)
2. **承認**: 対象外 (主体の承認ではない)。正規の利用者 (連携・社内の担当) が繰り返し出るなら、閾値・`exclude_templates` の見直しを人に提案する
3. **expected_denied**: 対象外
4. **片付け**: 下の「片付け」の節
5. **設定の修正**: 公開の画面は `exclude_templates`、平常帯が合わなければ `min_distinct`・`factor`・`app_factor` (どれも仮の値。実データで見直す)

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium | あり | ack・snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- ack: medium (成功だけ、または拒否だけ) で、本人のデータの閲覧と確かめたもの。同じ利用者が拒否に混ざる成功を出せば high で出直す
- resolve: 説明のついた操作 (本人の一括の閲覧、公開の画面)
- snooze: アプリの側の確認・修正が終わるまで
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- 開いた ID・利用者の氏名・メールアドレス・記録の中身を要約や通知に書かない (利用者は `<kind>:<id>`、型と件数だけ)
- 利用者のアカウントを止める・利用者に連絡することを LLM が決めない (アプリの運営者が判断する)
- 成功だけの総当たりを「問題なし」と書かない (認可がまったく効いていない場合と区別できない)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats artex-2026-10`: エージェントが他の利用者のメモの添付ファイルの読み取りを試みる段階。出典はログインの有無を書いていない。ログインした利用者の操作なら、このチェックが見る形

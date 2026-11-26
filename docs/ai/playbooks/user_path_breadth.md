# user_path_breadth: ログインした利用者が触ったパスの型の多さ

## この指摘の意味

アプリのログ (`format: request_lines` でユーザー ID を読み、`path_ids` を書いたソース) で、1 人のログインした利用者が、1 日にふだんより多くの種類のパスの型に触った (daily)。
ふだん誰も使わない数の画面や API を速く広く試す動き (エージェントによる探りの典型) の兆候。**事実 (型の数と内訳) の報告であり、遮断の提案ではない。**

- Key は利用者 (`<kind>:<id>`。例 `user:42`)。重大度は **low**。型が多いだけでは、新しい機能のリリースの日・管理画面を一通り見る担当・`templates` を書いていない名前入りの画面でも起きる
- 理由 (`reasons`): `above_app_band` アプリの平常帯 (ふだんの日の、いちばん多い利用者の値の中央値 × `app_factor`) を超えた / `above_user_band` 本人の平常帯も超えた /
  `new_user` 本人の平常帯が無い (新しい利用者)。窓は使わない
- data: `user` (`kind`・`id`)、`day` (UTC)、`value` (型の数)、`templates_ok` (2xx のあった型の数)・`templates_denied` (`user_denied.statuses` のあった型の数)・
  `templates_not_found` (404 のあった型の数)、`app_band`、`user_band`、`related`
- 型の数は**その日の正確な異なり**。総当たりのパスは多くが 404 になるので、`templates_not_found` が多ければ探りの形
- 重大度は上げない。同じ日に `user_denied`・`user_id_enumeration` があれば `related` に出る。そちらの重大度で人が動く

## まず確かめること

1. `related` を見る。`user_denied`・`user_id_enumeration` と束で出ていれば、そちらの playbook から確かめる
2. `templates_not_found` と `templates_denied` の割合を見る。触った型の多くが 404 か拒否なら、開ける画面を探した形
3. 型に名前・ログイン名の区間が残っていないか (`/users/<名前>/orders` が利用者ごとに別の型になる)。`arata doctor` の `path_ids` の行の「1 日に 1 人の利用者しか触らなかった型」で確かめ、
   `path_ids.templates` に `:id` として書き足す (`arata help ai user_id`)
4. 原本の Insights で、その日・その利用者の要求を引く (期間は `day` の 1 日に絞る):
   `fields @message | filter @message like "actor kind=user id=42" | parse @message /\[(?<rid>[A-Za-z0-9_@-]+)\]/ | stats count(*) by rid | limit 1000` で request_id を集め、
   `fields @timestamp, @message | filter @message like "<request_id>"` で Started の行のパスを見る

## 判断の分かれ目

- **正規の可能性が高い**: 新しい機能のリリースの日、管理画面を一通り見る担当、ほとんどが 2xx (ふだんの画面を広く使っただけ)
- **要確認**: 多くが 404・拒否、作ったばかりの利用者 (`new_user`)、同じ日の `user_denied`・`user_id_enumeration`

## 対処の選択肢

**止めることを勧めない。** 確認と保留の運用へつなぐ。変更は人が判断して実行する。LLM は提案まで。

1. **確認**: 触った画面を、アプリの運営者が確かめる
2. **承認**: 対象外 (主体の承認ではない)。担当の利用者が繰り返し出るなら閾値の見直しを人に提案する
3. **expected_denied**: 対象外
4. **片付け**: 下の「片付け」の節
5. **設定の修正**: 名前入りの型は `path_ids.templates`、平常帯が合わなければ `min_templates`・`factor`・`app_factor` (どれも仮の値。実データで見直す)

## 片付け

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| low | なし | snooze・resolve |

上がる余地は、同じ Key のまま、より重い重大度で観測されうるか。ack を許すのは余地のある行だけ (ack 中に出直すのは重大度が上がったときだけ)。このチェックは event 型 (観測されなくても解消にならない)。

- resolve: 説明のついた操作 (リリースの日・担当の確認)
- snooze: `templates` の書き足しなど、設定を直すまで
- 表で許さない ack は arata が止める (`ACK_REFUSED`)。終わった出来事だと確かめたうえでどうしても ack するなら、人が `--force --reason "<理由>"` を付ける (記録に force が残り、週次の報告に出る)。LLM は `--force` を提案しない

## やってはいけないこと

- 利用者の氏名・メールアドレス・型に残った名前の区間を要約や通知に書かない (利用者は `<kind>:<id>`、型の数だけ)
- 利用者のアカウントを止める・利用者に連絡することを LLM が決めない (アプリの運営者が判断する)

## 関連する事例

公開の事例で、このチェックが当たる段階 (一覧と読み方は `arata help ai threats`)。指摘がその攻撃だと断定する材料ではない。

- `arata help ai threats artex-2026-10`: エージェントが 500 回以上の Web のリクエストでファイル名や拡張子を試す段階。出典はログインの有無を書いていない。ログインした利用者の操作なら、触った型の多さをこのチェックが見る

# 0011. init のベースライン収集は UTC の 1 日単位に分け、進捗を runs に記録して再開できるようにする

- 日付: 2026-10-21
- 状態: 採用

## 背景

`init --window 7d` は CloudTrail LookupEvents で 7 日分の管理イベントを全件引く。LookupEvents は毎秒 2 リクエスト・50 件/頁が上限なので、
イベントの多いアカウントでは数時間かかる。途中でスロットルが収まらない・ネットワークが切れる・端末を閉じる (SIGINT) と、
それまでの数時間が無駄になり、どこまで取れたかも分からなかった。

## 決定

- init の窓を **UTC の日の境界**で区切り、古い順に 1 日ずつ全ソースを収集する。最初と最後の日は窓の端から / 端までになる
- 1 日終わるごとに、init の run (runs、profile=init) の `stats` に `chunks_done` / `chunks_total` / `done_until` / `records` を書く
- どれかのソースが失敗した日で止める (status=partial、`failed_chunk` を記録、終了コード 3)。SIGINT / SIGTERM も同じく止めて記録する (`interrupted: true`)
- `init --resume` は直近の未完了の init (status が running または partial) を `done_until` から再開する。窓の終わりは再開時点まで延ばし、同じ run を完了させる
- 再開で同じ日を引き直しても、events は event_id で、metrics は (date, source, metric, key) の置き換えで重複しない。principal_ips.count は二重に数え得るが、判定には使わない

## 検討した選択肢

- 1 時間単位に分ける: 進捗は細かくなるが、日次集計 (metrics、ADR 0009) の日と揃わず、Logs Insights のクエリ数が 24 倍になる。却下
- ソースごとに独立して進める (失敗したソースだけ後で再開): 進捗の管理が複雑になる。init は「全ソースが揃って完了」とし、設定や権限の問題は doctor で先に潰す。却下
- 失敗した日を飛ばして先へ進む: 再開時に飛ばした日を探す必要があり、ベースラインに穴が残ったまま「完了」になり得る。却下
- LookupEvents の NextToken を記録して頁単位で再開する: トークンの有効期限と、リージョン・ソースをまたいだ状態の保存が要る。日単位で足りる。却下
- 窓の終わりを最初の init の時刻のまま再開する: 再開が数日後だと、init の終わりから最初の daily の窓の始まりまでが抜ける。却下

## 結果

- 中断しても失うのは最大 1 日分の作業。どこまで取れたかが runs に残る
- 持続的な失敗 (権限不足、FORMAT_MISMATCH) があると init は完了しない。原因を直して `--resume` する運用になる
- 1 日ごとに cloudwatch-logs の解釈率クエリも走るので、Insights のクエリ数は日数分になる (スキャン量の合計は変わらない)

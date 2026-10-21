# 0007. init のベースライン収集で初出した主体は `baseline` 状態にし、new_principal の対象外にする

- 日付: 2026-10-21
- 状態: 採用

## 背景

`new_principal` は「allowlist にも principals にも無い主体」を報告する。導入直後は既存の主体が全て「無い」ので、
最初の daily run で数十件の新規主体が一斉に鳴り、人が allowlist に移す作業が発生する。
設計書 8 章の `arata init` は「ベースライン収集 (findings は出さない)」と定めているが、
ベースラインの主体を principals テーブル上でどう区別するかは決まっていなかった。

## 決定

- `principals.status` に `baseline` を加える (既存は unknown / approved / expired)。
- `init` が収集した `principal_seen` は status=`baseline` で挿入する。通常の `collect` / `run` は `unknown` で挿入する
  (既に行があれば status は変えない。初出時の status が残る)。
- `new_principal` は status が `unknown` または `expired` の主体だけを観測する。`baseline` は対象外。
- evaluate のたびに allowlist と突合し、allowlist にある主体は `approved`、expires を過ぎたものは `expired` に同期する。
  allowlist から消えた主体は `unknown` に戻す (baseline だったかどうかは保持しないので、承認を取り消した主体は再報告される)。

## 検討した選択肢

- init で見えた主体を allowlist.yaml に自動で書き出す: allowlist は「人が承認した既知リスト」であり、
  機械が書くと承認の意味が薄れる。また導入時点で侵害済みの主体を承認してしまう。却下
- init で findings を作り reported_at だけ付けて黙らせる: findings テーブルに「報告しない open」が大量に残り、
  週次の未対応一覧 (still_open) に出続ける。却下
- init の主体を approved にする: 「人が承認した」と区別が付かず、四半期レポートの「削除候補」の扱いも曖昧になる。却下

## 結果

- 導入直後の daily が静かになり、以後に現れた主体だけが new として報告される
- baseline の主体は allowlist に載っていないため、`unknown_assume_role` (呼び出し元が allowlist に無い) では引き続き報告される。
  これは意図どおりで、AssumeRole を行う主体は明示的に承認してもらう
- 導入時点で既に侵入していた主体は baseline に紛れる。init の前後で主体一覧を人がレビューする運用を README に書く

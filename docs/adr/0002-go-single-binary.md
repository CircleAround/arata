# 0002. Go 製の単一静的バイナリ

- 日付: 2026-10-21
- 状態: 採用

## 背景

実行環境は CircleAround のオンプレサーバー (linux/arm64) と AWS Lambda (arm64 / amd64) の両方。
依存のインストールや言語ランタイムの管理を顧客環境ごとに行いたくない。

## 決定

Go で実装し、`CGO_ENABLED=0` の単一静的バイナリを配る。SQLite は純 Go 実装 (`modernc.org/sqlite`) を使い cgo を避ける。
CLI は cobra。Lambda は同じ internal パッケージを呼ぶ薄いハンドラ。

## 検討した選択肢

- TypeScript / Node: 既存の CDK や Lambda 資産と揃うが、ランタイムと node_modules の配布が要る。SQLite はネイティブ依存か実験的 API
- Python: boto3 は強いが、ランタイムと依存の配布が要る
- シェルスクリプトの集合: 差分判定と状態管理を書くには不向き

## 結果

- クロスコンパイルで配布物が 1 ファイルになり、顧客環境への導入が簡単
- AWS SDK for Go v2 を使う。SDK クライアントはインターフェース越しに注入し、テストはフェイクで行う
- Go の習熟がチームに求められる

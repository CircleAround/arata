#!/usr/bin/env bash
# aratam.yaml の Slack への送り方 (bot か webhook) を、標準出力に 1 語で出す。
# 利用者のリポジトリの .github/scripts/ に写して使う。定時の監査・試しの送信・PR の検査の 3 つのワークフローが、
# 同じこのスクリプトを呼ぶ (判別のしかたを 1 か所にして、片方だけ直して食い違うのを防ぐ)。
#
#   使い方: arata-slack-method.sh <aratam.yaml>
#   出力:   bot | webhook (終了コード 0)。判別できなければ何も出さず、終了コード 1
#
# 送り方は `aratam config check --format json` の .slack.method で読む (機械が読む出力。スキーマは aratam schema aratam-config-check)。
# 人向けの出力 (text) の行を grep で読まない: 文言と並びは版をまたいで変わり、判別が黙って外れる。
# Slack にも LLM にも繋がず、秘密も要らない (PR の検査でも動く)。
#
# bot / webhook 以外は止める。次のどれでも、送り方を決めつけて先へ進まない:
#   - 設定を読めない (.slack が無い)             → aratam config check の出力を見て設定を直す
#   - aratam が古く --format json を知らない      → ARATA_VERSION を v0.14.0 以降にする
#   - 知らない送り方 (新しい版が足した値)         → このスクリプトと、呼んでいるワークフローを新しい送り方に合わせる
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: arata-slack-method.sh <aratam.yaml>" >&2
  exit 1
fi
config="$1"

# aratam の失敗 (終了コード 2) も、JSON でない出力も、ここでは空として受けて下でまとめて止める。
# 標準エラーの JSON のログは出さない (呼ぶ側のログの方針: level / code / source だけ)。
method="$(aratam config check -c "$config" --format json 2>/dev/null | jq -r '.slack.method | strings' 2>/dev/null)" || method=""

case "$method" in
  bot | webhook)
    printf '%s\n' "$method"
    ;;
  *)
    # 読んだ値は出さない (ワークフローのコマンドとして解釈される文字を、設定から出力に運ばない)
    echo "::error::Slack への送り方を判別できない (bot / webhook のどちらでもない)。aratam config check の出力と、aratam の版 (v0.14.0 以降) を確かめる" >&2
    exit 1
    ;;
esac

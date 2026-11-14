#!/usr/bin/env bash
# aratam.yaml の Slack への送り方 (bot か webhook) を、標準出力に 1 語で出す。
# arata repo init が書き出したファイル (ADR 0059)。手で直さない。定時の監査・試しの送信・PR の検査の 3 つのワークフローが、
# 同じこのスクリプトを呼ぶ (判別のしかたを 1 か所にして、片方だけ直して食い違うのを防ぐ)。
#
#   使い方: arata-slack-method.sh <aratam.yaml>
#   出力:   bot | webhook (終了コード 0)。判別できなければ何も出さず、終了コード 1
#
#   使い方: arata-slack-method.sh --urgent-webhook <aratam.yaml>
#   出力:   true | false (終了コード 0)。緊急用の Webhook を別に持つか (.slack.urgent_webhook。slack.urgent_webhook_env が空でなければ true)。
#           ワークフローは、true のときだけ緊急用の Webhook の秘密を notify に渡す (使わない秘密は渡さない)。読めなければ終了コード 1
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

field=method
if [ "${1:-}" = --urgent-webhook ]; then
  field=urgent_webhook
  shift
fi
if [ "$#" -ne 1 ]; then
  echo "usage: arata-slack-method.sh [--urgent-webhook] <aratam.yaml>" >&2
  exit 1
fi
config="$1"

if [ "$field" = urgent_webhook ]; then
  # 真偽値でなければ空 (項目が無い = この項目を知らない古い aratam も、ここで止まる)
  urgent="$(aratam config check -c "$config" --format json 2>/dev/null | jq -r '.slack.urgent_webhook | booleans' 2>/dev/null)" || urgent=""
  case "$urgent" in
    true | false)
      printf '%s\n' "$urgent"
      exit 0
      ;;
  esac
  echo "::error::緊急用の Webhook を使う設定かを読めない (.slack.urgent_webhook が無い)。aratam config check の出力と、aratam の版 (ワークフローの ARATA_VERSION) を確かめる" >&2
  exit 1
fi

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

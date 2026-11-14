#!/usr/bin/env bash
# 秘密が「仮の値」のままなら、秘密の名前を出して止める。
# arata repo init が書き出したファイル (ADR 0059)。手で直さない。
#
#   使い方: arata-secret-check.sh <環境変数の名前>...
#   終了コード: 0 = どれも仮の値ではない / 1 = 仮の値が残っている (名前を出す) / 2 = 使い方の誤り
#
# 仮の値は、github/secrets の Terraform が秘密の箱を作るときに入れる、決まった 1 つの文字列 (下の PLACEHOLDER)。
# ARN・JSON・URL・トークンのどの形でもないので、使われれば失敗するが、形が合わずに偶然止まることに頼らず、ここで名前を出して止める。
# 確かめるのは「仮の値と同じか」だけ。空 (秘密が無い・渡されていない) は通す: 使う step が、それぞれの理由で止まる
# (使わない送り方の秘密は、空で渡される)。
# 値は出さない。出すのは名前だけ (名前は秘密ではない)。
set -euo pipefail

PLACEHOLDER='@@PLACEHOLDER@@'

if [ "$#" -eq 0 ]; then
  echo "usage: arata-secret-check.sh <環境変数の名前>..." >&2
  exit 2
fi

status=0
for name in "$@"; do
  # 名前は大文字の英数字と _ だけ (間接参照に渡すので、形を先に確かめる)
  if ! [[ "$name" =~ ^[A-Z][A-Z0-9_]*$ ]]; then
    echo "::error::秘密の名前に使えない文字がある" >&2
    exit 2
  fi
  if [ "${!name:-}" = "$PLACEHOLDER" ]; then
    echo "::error::秘密 $name が仮の値のまま。environment の secrets に本物の値を入れる (README.md の 4)" >&2
    status=1
  fi
done
exit "$status"

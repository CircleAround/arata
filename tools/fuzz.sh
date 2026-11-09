#!/usr/bin/env bash
# リポジトリのファズテスト (func Fuzz*) を 1 つずつ、決まった時間だけ回す (ADR 0041)。
# 使い方: tools/fuzz.sh [時間 (既定 30s)] [パッケージの絞り込み (例: internal/notify)]
# 失敗した入力は、そのパッケージの testdata/fuzz/<名前>/ に書き出される。コミットすれば `go test` の回帰テストになる。
set -euo pipefail

fuzztime="${1:-30s}"
only="${2:-}"
go="${GO:-go}"
failed=0

while IFS= read -r file; do
  dir="$(dirname "$file")"
  if [ -n "$only" ] && [ "$dir" != "$only" ]; then
    continue
  fi
  while IFS= read -r name; do
    echo "== ./$dir $name ($fuzztime)"
    if ! "$go" test "./$dir" -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime"; then
      failed=1
    fi
  done < <(grep -ohE '^func Fuzz[A-Za-z0-9_]+' "$file" | sed 's/^func //')
done < <(git ls-files -co --exclude-standard '*_test.go' | xargs grep -lE '^func Fuzz[A-Za-z0-9_]+\(' | sort)

exit "$failed"

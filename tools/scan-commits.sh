#!/usr/bin/env bash
# 指定したコミットの差分とコミットメッセージを gitleaks で読む。CI・make・pre-push フックで同じ読み方をする (ADR 0088、運用は docs/sensitive-scan.md)。
# 使い方:
#   tools/scan-commits.sh <git log の範囲の引数...>   例: main..HEAD、--all
#   tools/scan-commits.sh --unpushed                  上流があれば上流..HEAD、無ければ origin/main..HEAD
#   tools/scan-commits.sh --pre-push <リモート名>     git の pre-push フックから。送る参照を標準入力で受け、そのリモートに無いコミットを読む
# 環境変数 GITLEAKS: gitleaks のバイナリ (既定は bin/gitleaks。make bin/gitleaks で入る)
set -euo pipefail

top=$(git rev-parse --show-toplevel)
cd "$top"
gitleaks=${GITLEAKS:-bin/gitleaks}
if ! command -v "$gitleaks" >/dev/null; then
  echo "scan-commits: gitleaks がありません: $gitleaks (make bin/gitleaks で入ります)" >&2
  exit 2
fi
flags=(--no-banner --redact -c .gitleaks.toml)

scan() {
  # gitleaks は git log が失敗しても「0 件」で成功するので、範囲は先に git で確かめる
  git rev-list --count "$@" >/dev/null </dev/null
  "$gitleaks" git "${flags[@]}" --log-opts="$*" . </dev/null
  # コミットメッセージは gitleaks の git モードが読まない
  git log --format=%B "$@" </dev/null | "$gitleaks" stdin "${flags[@]}"
}

case "${1:-}" in
  "")
    echo "scan-commits: 範囲を指定してください" >&2
    exit 2
    ;;
  --unpushed)
    if git rev-parse --verify --quiet '@{upstream}' >/dev/null 2>&1; then
      scan '@{upstream}..HEAD'
    else
      scan origin/main..HEAD
    fi
    ;;
  --pre-push)
    remote=${2:?リモート名を指定してください}
    status=0
    while read -r _ local_sha _ _; do
      [[ $local_sha =~ ^0+$ ]] && continue # 参照の削除
      # set -e は || の左では効かないので、サブシェルの終了コードを受ける
      set +e
      (
        set -e
        scan "$local_sha" --not --remotes="$remote"
      )
      rc=$?
      set -e
      [ "$rc" -eq 0 ] || status=1
    done
    exit "$status"
    ;;
  *)
    scan "$@"
    ;;
esac

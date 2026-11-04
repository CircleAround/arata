#!/usr/bin/env bash
# GitHub 上の本文 (PR・Issue・コメント・レビュー・Release) を 1 件 1 ファイルで書き出す。tools/wordscan と gitleaks で読むため。
# API の応答そのものには作者のアカウント名が入るので、人が書いた本文だけを取り出す。
# Dependabot の PR の本文は上流の変更履歴の転載なので読まない (ADR 0036)。
# 使い方: GH_TOKEN=... tools/github-text.sh <owner/repo> <書き出し先のディレクトリ>
set -euo pipefail

repo=${1:?owner/repo を指定してください}
out=${2:?書き出し先のディレクトリを指定してください}
mkdir -p "$out"

# dump <API のパス> <ファイル名の jq 式> <本文の jq 式>
dump() {
  gh api --paginate "$1" | jq -c '.[] | select(.user.type != "Bot")' | while IFS= read -r item; do
    name=$(jq -r "$2" <<<"$item")
    jq -r "$3" <<<"$item" >"$out/$name.txt"
  done
}

dump "repos/$repo/pulls?state=all&per_page=100" '"pr-\(.number)"' '"\(.title)\n\(.body // "")"'
# issues の API は PR も返す。PR は上で読んだので除く
gh api --paginate "repos/$repo/issues?state=all&per_page=100" | jq -c '.[] | select(.pull_request | not)' | while IFS= read -r item; do
  jq -r '"\(.title)\n\(.body // "")"' <<<"$item" >"$out/issue-$(jq -r .number <<<"$item").txt"
done
dump "repos/$repo/issues/comments?per_page=100" '"comment-\(.id)"' '.body // ""'
dump "repos/$repo/pulls/comments?per_page=100" '"review-comment-\(.id)"' '.body // ""'
for number in $(gh api --paginate "repos/$repo/pulls?state=all&per_page=100" --jq '.[].number'); do
  dump "repos/$repo/pulls/$number/reviews?per_page=100" '"review-\(.id)"' '.body // ""'
done
# Release は作者が Bot のこともあるが、本文は公開の案内なので全部読む
gh api --paginate "repos/$repo/releases?per_page=100" | jq -c '.[]' | while IFS= read -r item; do
  jq -r '"\(.name // "")\n\(.body // "")"' <<<"$item" >"$out/release-$(jq -r .id <<<"$item").txt"
done
echo "書き出した件数: $(find "$out" -type f | wc -l)"

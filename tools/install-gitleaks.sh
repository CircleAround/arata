#!/usr/bin/env bash
# gitleaks を版とチェックサムを固定して入れる。CI とローカルで同じ版を使う (ADR 0036)。
# 使い方: tools/install-gitleaks.sh <置き場所のディレクトリ>
# 版を上げるときは、公開から 7 日以上の版を選び、公開の checksums.txt の値に合わせて下の 3 行を変える。
set -euo pipefail

version=8.30.1
sha256_arm64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
sha256_x64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

dest=${1:?置き場所のディレクトリを指定してください}
case "$(uname -m)" in
  aarch64 | arm64) arch=arm64 sha256=$sha256_arm64 ;;
  x86_64) arch=x64 sha256=$sha256_x64 ;;
  *) echo "対応していないアーキテクチャです: $(uname -m)" >&2; exit 2 ;;
esac

mkdir -p "$dest"
tarball="gitleaks_${version}_linux_${arch}.tar.gz"
curl -fsSL -o "$dest/$tarball" "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${tarball}"
echo "${sha256}  ${dest}/${tarball}" | sha256sum -c --quiet -
tar -xzf "$dest/$tarball" -C "$dest" gitleaks
"$dest/gitleaks" version

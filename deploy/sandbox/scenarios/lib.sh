# shellcheck shell=bash
# シナリオの共通部分。各スクリプトから source する。
#
# 必須の環境変数:
#   SANDBOX_ACCOUNT  sandbox を置いた開発用アカウントの ID。今の認証情報のアカウントと一致しなければ何もしない
#                    (顧客や本番のアカウントで誤って実行しないための確認)
# 任意:
#   SANDBOX_STACK    スタック名 (既定 arata-sandbox = config の prefix)
#   AWS_PROFILE / AWS_REGION  aws CLI の標準どおり
set -euo pipefail

: "${SANDBOX_ACCOUNT:?SANDBOX_ACCOUNT (sandbox を置いたアカウントの ID) を指定してください}"
SANDBOX_STACK="${SANDBOX_STACK:-arata-sandbox}"

# 今の認証情報が sandbox のアカウントであることを確かめる。
require_sandbox_account() {
  local actual
  actual="$(aws sts get-caller-identity --query Account --output text)"
  if [[ "$actual" != "$SANDBOX_ACCOUNT" ]]; then
    echo "中止: 今の認証情報のアカウント ($actual) が SANDBOX_ACCOUNT ($SANDBOX_ACCOUNT) と違います" >&2
    exit 2
  fi
}

# スタックの出力を 1 つ読む。
stack_output() {
  aws cloudformation describe-stacks --stack-name "$SANDBOX_STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

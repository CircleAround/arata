#!/usr/bin/env bash
# スタックの外で IAM ユーザーとアクセスキーを作る (「誰かが手でユーザーを作った」)。後で cleanup で消す。
# ユーザーにはポリシーを付けない。アクセスキーの秘密値は表示しない (ID だけ)。
#
#   SANDBOX_ACCOUNT=123456789012 ./03-iam-changes.sh create
#   SANDBOX_ACCOUNT=123456789012 ./03-iam-changes.sh cleanup
#
# arata で出るはず (daily): iam_changes (medium) が CreateUser と CreateAccessKey に 1 件ずつ (呼び出した主体が deploy タグなら info)。
#   cleanup の削除系 (DeleteUser など) は iam_changes の対象外。weekly の credential_hygiene は作ったキーが残っていれば
#   unused_days 経過後に unused_key を出す
# 書き込む: iam:CreateUser / CreateAccessKey / DeleteAccessKey / DeleteUser (この名前のユーザーだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

USER_NAME="${SANDBOX_STACK}-scenario-manual"

case "${1:-}" in
  create)
    aws iam create-user --user-name "$USER_NAME" --tags Key=arata:sandbox,Value=scenario --query 'User.Arn' --output text
    aws iam create-access-key --user-name "$USER_NAME" --query 'AccessKey.AccessKeyId' --output text
    echo "作った: $USER_NAME (片付けは $0 cleanup)"
    ;;
  cleanup)
    for k in $(aws iam list-access-keys --user-name "$USER_NAME" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$k"
    done
    aws iam delete-user --user-name "$USER_NAME"
    echo "消した: $USER_NAME"
    ;;
  *)
    echo "使い方: $0 create|cleanup" >&2
    exit 2
    ;;
esac

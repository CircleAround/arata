#!/usr/bin/env bash
# 外部アカウント (SaaS 役) から sandbox の外部用ロールを AssumeRole する。ロールは権限を持たないので、引き受けるだけで何もできない。
#
#   SANDBOX_ACCOUNT=123456789012 EXTERNAL_PROFILE=<外部アカウントの profile> [EXTERNAL_ID=...] ./02-external-assume-role.sh
#
# arata で出るはず: unknown_assume_role (high、「外部アカウント 111122223333」)。approve すると account 単位で承認される
#   (allowlist の principals に account: "111122223333")。次の run からは鳴らない
# 書き込む: なし (sts:AssumeRole だけ。得た一時認証情報は表示せず捨てる)
source "$(dirname "$0")/lib.sh"
: "${EXTERNAL_PROFILE:?EXTERNAL_PROFILE (外部アカウントの AWS profile) を指定してください}"
require_sandbox_account

ROLE_ARN="$(stack_output ExternalRoleArn)"
REGION="${AWS_REGION:-$(aws configure get region)}"

ext_account="$(aws sts get-caller-identity --profile "$EXTERNAL_PROFILE" --query Account --output text)"
if [[ "$ext_account" == "$SANDBOX_ACCOUNT" ]]; then
  echo "中止: EXTERNAL_PROFILE が sandbox と同じアカウントです (外部アカウントの profile を指定してください)" >&2
  exit 2
fi

args=(--profile "$EXTERNAL_PROFILE" --region "$REGION" --role-arn "$ROLE_ARN" --role-session-name arata-sandbox-scenario)
if [[ -n "${EXTERNAL_ID:-}" ]]; then args+=(--external-id "$EXTERNAL_ID"); fi
# 一時認証情報は出さない (AssumedRoleUser の ARN だけ)
aws sts assume-role "${args[@]}" --query 'AssumedRoleUser.Arn' --output text
echo "AssumeRole した: $ext_account → $ROLE_ARN (CloudTrail への記録は 5〜15 分遅れる)"

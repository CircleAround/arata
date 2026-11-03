#!/usr/bin/env bash
# 外部アカウント (SaaS 役) から外部用ロールを引き受け、権限の無い読み取り API を 8 種類呼ぶ (権限の列挙の真似)。
# ロールは権限を持たないので、どの呼び出しも拒否される。
#
#   SANDBOX_ACCOUNT=123456789012 EXTERNAL_PROFILE=<外部アカウントの profile> [EXTERNAL_ID=...] ./05-access-denied-enumeration.sh
#
# arata で出るはず (daily): access_denied medium (外部用ロールの ARN、`threshold: breadth`、distinct_apis 8)。
#   拒否の種類が既定の min_distinct_apis (5) 以上・high_distinct_apis (20) 未満なので medium。
#   外部用ロールを allowlist で承認しても出る (承認は主体が居ることを認めるだけで、列挙は止めない。止めるなら ack / snooze)
# 書き込む: なし (sts:AssumeRole と、拒否される読み取りだけ。一時認証情報は表示せず、このスクリプトのプロセスの中でだけ使う)
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

args=(--profile "$EXTERNAL_PROFILE" --region "$REGION" --role-arn "$ROLE_ARN" --role-session-name arata-sandbox-enumeration)
if [[ -n "${EXTERNAL_ID:-}" ]]; then args+=(--external-id "$EXTERNAL_ID"); fi
# 一時認証情報は変数に入れるだけで表示しない
read -r key secret token < <(aws sts assume-role "${args[@]}" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
if [[ -z "$key" || -z "$secret" || -z "$token" ]]; then
  echo "中止: AssumeRole で一時認証情報を得られませんでした" >&2
  exit 1
fi

# 引き受けたロールで呼ぶ。拒否されるのが期待どおりなので、エラーコードだけを表示する
as_role() {
  local out
  if out="$(env -u AWS_PROFILE AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret" AWS_SESSION_TOKEN="$token" \
    aws --region "$REGION" "$@" 2>&1 >/dev/null)"; then
    echo "  $1 $2: 成功 (拒否されるはず。外部用ロールに権限が付いていないか確かめる)"
  else
    echo "  $1 $2: $(grep -oE '\(([A-Za-z.]+)\)' <<<"$out" | head -1)"
  fi
}

echo "拒否される読み取りを呼ぶ ($ROLE_ARN):"
as_role iam list-users
as_role s3api list-buckets
as_role ec2 describe-instances
as_role secretsmanager list-secrets
as_role kms list-keys
as_role dynamodb list-tables
as_role lambda list-functions
as_role rds describe-db-instances
unset key secret token
echo "完了: 8 種類 (CloudTrail への記録は 5〜15 分遅れる。arata の CloudTrail ソースの regions に $REGION と us-east-1 が入っていること)"

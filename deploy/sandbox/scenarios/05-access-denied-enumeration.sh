#!/usr/bin/env bash
# 外部アカウント (SaaS 役) から外部用ロールを引き受け、権限の無い読み取り API を 8 種類呼ぶ (権限の列挙の真似)。
# ロールは権限を持たないので、どの呼び出しも拒否される。
#
#   SANDBOX_ACCOUNT=123456789012 EXTERNAL_PROFILE=<外部アカウントの profile> [EXTERNAL_ID=...] ./05-access-denied-enumeration.sh [--apis N]
#
#   --apis N  呼ぶ API の種類 (既定 8、最大 24)。どれも権限の無い読み取り (List / Describe) だけで、書き込みは含めない
#
# arata で出るはず (daily): access_denied medium (外部用ロールの ARN、`threshold: breadth`、distinct_apis 8)。
#   拒否の種類が既定の min_distinct_apis (5) 以上・high_distinct_apis (20) 未満なので medium。--apis 20 以上なら high。
#   外部用ロールを allowlist で承認しても出る (承認は主体が居ることを認めるだけで、列挙は止めない)。
#   想定内の拒否なら allowlist の expected_denied で除く (除いた件数は expected_denied_excluded)。ack しても high に上がれば changed で再報告
# 書き込む: なし (sts:AssumeRole と、拒否される読み取りだけ。一時認証情報は表示せず、このスクリプトのプロセスの中でだけ使う)
# 呼ぶ読み取り API (先頭から --apis 個)。すべて List / Describe
CALLS=(
  "iam list-users" "s3api list-buckets" "ec2 describe-instances" "secretsmanager list-secrets"
  "kms list-keys" "dynamodb list-tables" "lambda list-functions" "rds describe-db-instances"
  "iam list-roles" "ec2 describe-vpcs" "ec2 describe-security-groups" "sns list-topics"
  "sqs list-queues" "logs describe-log-groups" "cloudtrail describe-trails" "ssm describe-parameters"
  "ecr describe-repositories" "ecs list-clusters" "cloudformation list-stacks" "cloudwatch describe-alarms"
  "elbv2 describe-load-balancers" "route53 list-hosted-zones" "acm list-certificates" "kinesis list-streams"
)
n_apis=8
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apis)
      n_apis="${2:-}"
      shift 2 || { echo "中止: --apis に数を指定してください" >&2; exit 2; }
      ;;
    *) echo "中止: 不明な引数 $1 (使えるのは --apis N)" >&2; exit 2 ;;
  esac
done
if ! [[ "$n_apis" =~ ^[0-9]+$ ]] || (( n_apis < 1 || n_apis > ${#CALLS[@]} )); then
  echo "中止: --apis は 1〜${#CALLS[@]} (指定: $n_apis)" >&2
  exit 2
fi

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
for call in "${CALLS[@]:0:n_apis}"; do
  # shellcheck disable=SC2086 # "サービス 操作" を 2 語に分ける
  as_role $call
done
unset key secret token
echo "完了: $n_apis 種類 (CloudTrail への記録は 5〜15 分遅れる。arata の CloudTrail ソースの regions に $REGION と us-east-1 が入っていること)"

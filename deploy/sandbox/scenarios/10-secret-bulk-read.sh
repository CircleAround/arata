#!/usr/bin/env bash
# 試験用の読み手のロールで、試験用の秘匿値をまとめて読む (secret_access の一括読み出しと初めての読み手)。後片付けまでこのスクリプトで行う。
# config の secretAccess.enabled: true で deploy したときだけ使える (シークレット 3 つ (名前は CloudFormation が付ける。出力 ScenarioSecretArns) と
# 読み手のロール <stack>-secret-reader ができる)。
#
#   SANDBOX_ACCOUNT=123456789012 ./10-secret-bulk-read.sh
#
# 起こすこと:
#   1. (実行する主体で) SecureString のパラメータを 9 つ /<stack>/scenario-10/param-1..9 に作る (値は無意味な文字列。実際の秘密は入れない)
#   2. 読み手のロールを引き受け、次を読む (値は表示も保存もしない):
#      シークレット 3 つを ARN で GetSecretValue、同じ 3 つを BatchGetSecretValue、パラメータ 9 つを GetParameter (復号)、
#      /<stack>/scenario-10 を GetParametersByPath (再帰・復号) で 1 回
#   3. (実行する主体で) パラメータを消す
# arata で出るはず (daily): secret_access high (Key は arn:aws:iam::<アカウント>:role/<stack>-secret-reader)
#   - distinct_secrets 13 (シークレット 3 + パラメータ 9 + パス 1。GetParametersByPath はパス単位で 1 と数える) > min_distinct 10 → bulk: true
#   - paths に "/<stack>/scenario-10 (recursive)"。arata が CloudTrail を収集し終えた日が 7 日 (min_baseline_days) 以上あれば
#     new_secrets に 13 個、first_reader: true (読み手のロールが秘匿値を読むのは初めて)
#   - 読み手のロールは deploy で初めて現れた主体なので new_principal medium も出る (承認すれば止まる)
#   - パラメータの作成・削除 (ssm:PutParameter / DeleteParameter) はほかのチェックに出ない。run の stats の secret_read_events が増える
# 書き込む: ssm:PutParameter / DeleteParameter (/<stack>/scenario-10/ の下のこの名前のパラメータだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

ROLE_ARN="$(stack_output SecretReaderRoleArn)"
if [[ -z "$ROLE_ARN" || "$ROLE_ARN" == "None" ]]; then
  echo "中止: 読み手のロールがありません (config の secretAccess.enabled: true で deploy してください)" >&2
  exit 2
fi
IFS=, read -r -a SECRETS <<<"$(stack_output ScenarioSecretArns)"
PATH_ROOT="$(stack_output ScenarioParameterPath)" # /<stack>/scenario-10
# 読み手のロールの一時認証情報に切り替えると profile の設定を読まなくなるので、リージョンを先に決める
export AWS_REGION="${AWS_REGION:-$(aws configure get region)}"
PARAMS=()
for i in 1 2 3 4 5 6 7 8 9; do PARAMS+=("${PATH_ROOT}/param-${i}"); done

cleanup() {
  for p in "${PARAMS[@]}"; do
    aws ssm delete-parameter --name "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

# 1. SecureString のパラメータ (実行する主体で作る)
for p in "${PARAMS[@]}"; do
  aws ssm put-parameter --name "$p" --type SecureString --value "arata-sandbox-dummy" --overwrite >/dev/null
done
echo "パラメータを ${#PARAMS[@]} 個作った (${PATH_ROOT}/param-*)"

# 2. 読み手のロールで読む。一時認証情報はこのサブシェルの環境変数にだけ置き、表示しない
(
  read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN < <(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name arata-scenario-10 \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  unset AWS_PROFILE
  for id in "${SECRETS[@]}"; do
    aws secretsmanager get-secret-value --secret-id "$id" --query Name --output text >/dev/null
  done
  aws secretsmanager batch-get-secret-value --secret-id-list "${SECRETS[@]}" --query 'SecretValues[].Name' --output text >/dev/null
  for p in "${PARAMS[@]}"; do
    aws ssm get-parameter --name "$p" --with-decryption --query Parameter.Name --output text >/dev/null
  done
  aws ssm get-parameters-by-path --path "$PATH_ROOT" --recursive --with-decryption --query 'Parameters[].Name' --output text >/dev/null
)
echo "読み手のロール $ROLE_ARN で、シークレット 3 つ (個別と一括) とパラメータ 9 つ (個別と再帰のパス) を読んだ (値は表示していない)"

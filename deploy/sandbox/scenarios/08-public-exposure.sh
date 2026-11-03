#!/usr/bin/env bash
# 試験用のセキュリティグループを作り、22 を 0.0.0.0/0 に開けて、すぐ閉じて消す (public_exposure)。
# どのインスタンス・ネットワークインターフェースにも付けないので、実際に到達できる資源は無い。後片付けまでこのスクリプトで行う。
#
#   SANDBOX_ACCOUNT=123456789012 [VPC_ID=vpc-...] ./08-public-exposure.sh
#
#   VPC_ID  セキュリティグループを作る VPC (既定はリージョンのデフォルト VPC。無ければ指定する)
#
# arata で出るはず (daily): public_exposure high `ec2:AuthorizeSecurityGroupIngress|<作った sg の ID>|tcp/22 0.0.0.0/0`
#   (22 は既定の sensitive_ports に入る)。呼び出した主体を allowlist で `tags: [deploy]` にしても下がらない (Data の known_deploy_principal が true になる)。
#   すぐ閉じても報告される (開いていた事実を伝える)。CreateSecurityGroup・RevokeSecurityGroupIngress・DeleteSecurityGroup は対象外
# 書き込む: ec2:CreateSecurityGroup / AuthorizeSecurityGroupIngress / RevokeSecurityGroupIngress / DeleteSecurityGroup (作ったグループだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

GROUP_NAME="${SANDBOX_STACK}-scenario-08"
if [[ -z "${VPC_ID:-}" ]]; then
  VPC_ID="$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)"
fi
if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
  echo "中止: デフォルト VPC が無いので VPC_ID を指定してください" >&2
  exit 2
fi

SG_ID=""
cleanup() {
  if [[ -n "$SG_ID" ]]; then
    aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
    aws ec2 delete-security-group --group-id "$SG_ID" || echo "警告: $SG_ID を消せませんでした。手で消してください" >&2
  fi
}
trap cleanup EXIT

SG_ID="$(aws ec2 create-security-group --group-name "$GROUP_NAME" --description "arata sandbox scenario 08 (not attached)" --vpc-id "$VPC_ID" \
  --tag-specifications "ResourceType=security-group,Tags=[{Key=arata:sandbox,Value=scenario}]" --query GroupId --output text)"
echo "作った: $SG_ID ($GROUP_NAME、$VPC_ID。どこにも付けない)"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
echo "開けた: tcp/22 0.0.0.0/0"
aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
echo "閉じた: tcp/22 0.0.0.0/0"
aws ec2 delete-security-group --group-id "$SG_ID"
echo "消した: $SG_ID"
SG_ID=""

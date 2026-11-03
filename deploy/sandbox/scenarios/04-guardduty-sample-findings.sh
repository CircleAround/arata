#!/usr/bin/env bash
# GuardDuty のサンプル finding を作る (タイトルに [SAMPLE] が付く。実際の脅威ではない)。config の guardDuty.enabled が true のときだけ。
#
#   SANDBOX_ACCOUNT=123456789012 ./04-guardduty-sample-findings.sh [finding の種類 ...]
#
# arata で出るはず (weekly): guardduty_findings。GuardDuty の重大度 7 以上 → high、4 以上 → medium、他は low
#   (既定の 2 種類は high と medium)。片付けは GuardDuty のコンソールでアーカイブするか、cdk destroy で detector ごと消える
# 書き込む: guardduty:CreateSampleFindings
source "$(dirname "$0")/lib.sh"
require_sandbox_account

DETECTOR="$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)"
if [[ -z "$DETECTOR" || "$DETECTOR" == "None" ]]; then
  echo "中止: このリージョンに GuardDuty の detector がありません (config の guardDuty.enabled を true にして deploy)" >&2
  exit 2
fi
if [[ $# -eq 0 ]]; then
  set -- 'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS' 'Recon:IAMUser/MaliciousIPCaller'
fi
aws guardduty create-sample-findings --detector-id "$DETECTOR" --finding-types "$@"
echo "サンプル finding を作った: $*"

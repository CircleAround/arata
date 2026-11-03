#!/usr/bin/env bash
# 既知の主体 (このスクリプトを実行する主体) が、ふだん書き込まないリージョンで書き込む (principal_new_source の新しいリージョン)。
# 後片付けまでこのスクリプトで行う。
#
#   SANDBOX_ACCOUNT=123456789012 ./09-new-source-region.sh <リージョン>
#
# 前提:
#   - 実行する主体が arata にとって既知 (init のベースライン・承認済み) で、過去 30 日 (baseline_days) に CloudTrail に活動がある
#     (ふだんシナリオや deploy を行っている開発者の主体)。新しく作ったロールは「現れたばかりの主体」として報告されないので使わない
#   - <リージョン> は arata の cloudtrail-lookup の regions に入っていて、実行する主体が過去 30 日に書き込みをしていないリージョン
#     (IAM の変更は us-east-1 に記録されるので、deploy や 03 を行っていれば us-east-1 は既知になっていることが多い)
#   - arata のストアに CloudTrail のデータのある日が 15 日 (min_baseline_days) 以上ある (無ければ導入直後として報告しない)
# 起こすこと: <リージョン> に String のパラメータ /<stack>/scenario-09 を作り (ssm:PutParameter)、消す (ssm:DeleteParameter)。値は無意味な文字列
# arata で出るはず (daily): principal_new_source medium (Key は実行した主体の ARN、reasons に new_region、new_regions に <リージョン> と書き込み 2 件)
#   送信元はいつもと同じなので new_sources は無い。送信元の初出も試すなら、このスクリプトを AWS CloudShell など別の送信元から実行する
#   (新しい送信元 + 書き込み 2 件は min_writes 5 未満なので、新しい送信元の分は low の理由として reasons に new_source が加わる。重大度は medium のまま)
#   ほかのチェック (iam_changes・defense_evasion・public_exposure など) には出ない
# 書き込む: ssm:PutParameter / DeleteParameter (<リージョン> のこの名前のパラメータだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

REGION="${1:?書き込むリージョンを指定してください (arata の cloudtrail-lookup の regions のうち、ふだん書き込まないもの)}"
PARAM="/${SANDBOX_STACK}/scenario-09"

cleanup() {
  if [[ "${created:-}" == 1 ]]; then
    aws ssm delete-parameter --region "$REGION" --name "$PARAM" 2>/dev/null || true
  fi
}
trap cleanup EXIT

aws sts get-caller-identity --query Arn --output text | sed 's/^/実行する主体: /'
aws ssm put-parameter --region "$REGION" --name "$PARAM" --type String --value "arata-sandbox-scenario-09" --overwrite >/dev/null
created=1
aws ssm delete-parameter --region "$REGION" --name "$PARAM"
created=0
echo "リージョン $REGION: パラメータ $PARAM を作って消した (書き込み 2 件)"

#!/usr/bin/env bash
# ふだん使わないリージョン (arata の cloudtrail-lookup の regions に入っていない、有効なリージョン) で書き込む (unused_region_activity)。
# 計算資源は作らない (SSM の String パラメータを作って消すだけ)。後片付けまでこのスクリプトで行う。
#
#   SANDBOX_ACCOUNT=123456789012 ./12-unused-region-write.sh <リージョン>
#
# 前提:
#   - arata の設定に cloudtrail-unused-regions のソースがあり、daily に unused_region_activity が入っている (雛形のまま)
#   - <リージョン> はアカウントで有効 (opt-in 済みか既定で有効) で、arata の cloudtrail-lookup の regions に入っていないもの (例 eu-west-1)。
#     arata doctor の cloudtrail-unused-regions の行に「ふだん使うリージョン … を除く N: …」として対象が出る
# 起こすこと: <リージョン> に String のパラメータ /<stack>/scenario-12 を作り (ssm:PutParameter)、消す (ssm:DeleteParameter)。値は無意味な文字列
# arata で出るはず (daily): unused_region_activity high (Key は <リージョン>|<実行した主体の ARN>、apis に ssm:PutParameter と ssm:DeleteParameter、
#   compute_apis は空 (計算資源の作成ではないので critical にはならない)、count 2)。実行した主体を allowlist で tags: [deploy] にすると medium
#   ほかのチェック (defense_evasion・public_exposure・access_denied・principal_new_source・new_principal など) には出ない
#   (未使用リージョンのイベントは unused_region_activity だけが見る)。run の stats の unused_region_events が 2 増え、unused_regions_scanned に <リージョン> が入る
# 書き込む: ssm:PutParameter / DeleteParameter (<リージョン> のこの名前のパラメータだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

REGION="${1:?書き込むリージョンを指定してください (アカウントで有効で、arata の cloudtrail-lookup の regions に入っていないもの)}"
PARAM="/${SANDBOX_STACK}/scenario-12"

# 有効なリージョンか確かめる (opt-in していないリージョンには書けない)
status="$(aws account get-region-opt-status --region-name "$REGION" --query RegionOptStatus --output text 2>/dev/null || echo UNKNOWN)"
case "$status" in
  ENABLED | ENABLED_BY_DEFAULT) ;;
  *)
    echo "中止: リージョン $REGION の状態が $status です (有効なリージョンを指定してください)" >&2
    exit 2
    ;;
esac

cleanup() {
  if [[ "${created:-}" == 1 ]]; then
    aws ssm delete-parameter --region "$REGION" --name "$PARAM" 2>/dev/null || true
  fi
}
trap cleanup EXIT

aws sts get-caller-identity --query Arn --output text | sed 's/^/実行する主体: /'
aws ssm put-parameter --region "$REGION" --name "$PARAM" --type String --value "arata-sandbox-scenario-12" --overwrite >/dev/null
created=1
aws ssm delete-parameter --region "$REGION" --name "$PARAM"
created=0
echo "リージョン $REGION: パラメータ $PARAM を作って消した (書き込み 2 件)。15 分ほど待って arata run --profile daily"

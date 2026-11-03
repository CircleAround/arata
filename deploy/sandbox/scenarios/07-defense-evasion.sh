#!/usr/bin/env bash
# 監査・検知の仕組みを弱める操作を、sandbox 専用の資源にだけ起こす (defense_evasion)。後片付けまでこのスクリプトで行う。
# CloudTrail の証跡は止めない (開発用アカウントの証跡を止めないため。StopLogging はユニットテストで確かめる)。
#
#   SANDBOX_ACCOUNT=123456789012 ./07-defense-evasion.sh
#
# 起こすこと:
#   1. 試験用のロググループ <stack>-scenario-07 を作り、保持期間を 1 日にして (PutRetentionPolicy)、消す (DeleteLogGroup)
#   2. sandbox のアナライザー (config の accessAnalyzer.enabled: true のとき。名前は prefix) にアーカイブルール
#      arata-scenario-07 を作って (CreateArchiveRule)、消す。ルールの条件は存在しないバケットだけに一致させ、既存の findings をアーカイブしない
# arata で出るはず (daily): defense_evasion
#   - high `logs:PutRetentionPolicy|<呼び出した主体>|<stack>-scenario-07` (保持期間 1 日 < 既定の min_log_retention_days 90)
#   - high `logs:DeleteLogGroup|<呼び出した主体>|<stack>-scenario-07`
#   - high `access-analyzer:CreateArchiveRule|<呼び出した主体>|<prefix>/arata-scenario-07` (アナライザーがあるとき)
#   呼び出した主体を allowlist で `tags: [deploy]` にすると、どれも medium に下がる (info にはならない)。
#   試験用のロググループは arata の監査対象 (cloudwatch-logs のソース) ではないので critical にはならない
#   (監査対象のロググループの critical はユニットテストと engine のテストで確かめる)。
#   CreateLogGroup・DeleteArchiveRule は対象外 (弱める操作ではない)
# 書き込む: logs:CreateLogGroup / PutRetentionPolicy / DeleteLogGroup (この名前のロググループだけ)、
#           access-analyzer:CreateArchiveRule / DeleteArchiveRule (sandbox のアナライザーのこの名前のルールだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

LOG_GROUP="${SANDBOX_STACK}-scenario-07"
ANALYZER="${SANDBOX_STACK}"
RULE="arata-scenario-07"

cleanup() {
  if [[ "${log_created:-}" == 1 ]]; then
    aws logs delete-log-group --log-group-name "$LOG_GROUP" 2>/dev/null || true
  fi
  if [[ "${rule_created:-}" == 1 ]]; then
    aws accessanalyzer delete-archive-rule --analyzer-name "$ANALYZER" --rule-name "$RULE" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# 1. ログの保持期間の短縮と削除
aws logs create-log-group --log-group-name "$LOG_GROUP" --tags arata:sandbox=scenario
log_created=1
aws logs put-retention-policy --log-group-name "$LOG_GROUP" --retention-in-days 1
aws logs delete-log-group --log-group-name "$LOG_GROUP"
log_created=0
echo "ロググループ $LOG_GROUP: 保持期間を 1 日にして消した"

# 2. Access Analyzer のアーカイブルール
if aws accessanalyzer get-analyzer --analyzer-name "$ANALYZER" >/dev/null 2>&1; then
  # 存在しないバケットにだけ一致する条件 (既存の findings をアーカイブしない)
  aws accessanalyzer create-archive-rule --analyzer-name "$ANALYZER" --rule-name "$RULE" \
    --filter "{\"resource\":{\"eq\":[\"arn:aws:s3:::${SANDBOX_STACK}-scenario-07-nonexistent\"]}}"
  rule_created=1
  aws accessanalyzer delete-archive-rule --analyzer-name "$ANALYZER" --rule-name "$RULE"
  rule_created=0
  echo "アナライザー $ANALYZER: アーカイブルール $RULE を作って消した"
else
  echo "アナライザー $ANALYZER が無いので、アーカイブルールは飛ばした (config の accessAnalyzer.enabled: true で deploy すると試せる)"
fi

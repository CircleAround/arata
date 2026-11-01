#!/usr/bin/env bash
# nginx のロググループに「総当たりログイン」と「機密パスの探索」に当たる行を入れる。
# 送信元は文書用のアドレス (RFC 5737)。実際の通信は起きない (ログの行を書くだけ)。
#
#   SANDBOX_ACCOUNT=123456789012 ./01-nginx-bruteforce.sh [ログイン失敗の行数 (既定 50)] [探索の行数 (既定 30)]
#
# arata で出るはず (daily): login_bruteforce (medium, 203.0.113.10, above_baseline)、probe_paths (low, 198.51.100.7)
# 書き込む: logs:CreateLogStream / logs:PutLogEvents (sandbox のロググループだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

FAILURES="${1:-50}"
PROBES="${2:-30}"
LOG_GROUP="$(stack_output NginxLogGroupName)"
STREAM="scenario-$(date -u +%Y%m%dT%H%M%SZ)"

now_ms=$(( $(date -u +%s) * 1000 ))
time_local="$(LC_ALL=C date -u +'%d/%b/%Y:%H:%M:%S +0000')"

line() { # ip method path status
  printf '%s - - [%s] "%s %s HTTP/1.1" %s 0 "-" "Mozilla/5.0 (arata-sandbox-scenario)"' "$1" "$time_local" "$2" "$3" "$4"
}

events="$(mktemp)"
trap 'rm -f "$events"' EXIT
{
  echo '['
  sep=''
  i=0
  emit() {
    # PutLogEvents は時刻順が要るので 1 ms ずつずらす
    printf '%s{"timestamp":%d,"message":"%s"}\n' "$sep" "$((now_ms + i))" "$(line "$@" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    sep=','
    i=$((i + 1))
  }
  for _ in $(seq "$FAILURES"); do emit 203.0.113.10 POST /users/sign_in 401; done
  for n in $(seq "$PROBES"); do
    case $((n % 3)) in
      0) emit 198.51.100.7 GET /.env 404 ;;
      1) emit 198.51.100.7 GET /.git/config 404 ;;
      2) emit 198.51.100.7 GET /wp-login.php 404 ;;
    esac
  done
  # 正常な行 (解釈率の確認用)
  for _ in $(seq 20); do emit 192.0.2.20 GET / 200; done
  echo ']'
} > "$events"

aws logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name "$STREAM"
aws logs put-log-events --log-group-name "$LOG_GROUP" --log-stream-name "$STREAM" \
  --log-events "file://$events" --query 'rejectedLogEventsInfo' --output json
echo "入れた: $LOG_GROUP / $STREAM (ログイン失敗 $FAILURES 行、探索 $PROBES 行、正常 20 行)"

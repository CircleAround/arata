#!/usr/bin/env bash
# nginx のロググループに「多数の IP からの会員登録の集中」と「その一部の IP が直後にメッセージ送信」に当たる行を入れる (endpoint_abuse)。
# 送信元は文書用のアドレス (RFC 5737)。実際の通信は起きない (ログの行を書くだけ)。パス (/signup・/messages) は架空。
#
#   SANDBOX_ACCOUNT=123456789012 ./11-endpoint-abuse.sh [登録の IP 数 (既定 25)] [メッセージを送る IP 数 (既定 8)]
#
# arata の設定 (checks.endpoint_abuse) に次を書いてから daily を回す (README の「11 の期待」):
#   endpoints: [{ name: signup, paths: [/signup], methods: [POST] }, { name: message, paths: [/messages], methods: [POST] }]
#   follow_ups: [{ from: signup, to: message, within: 30m, min_ips: 5 }]
# arata で出るはず (daily): endpoint_abuse medium (signup。distributed_burst、same_user_agent) と medium (signup>message。follow_up)
# 書き込む: logs:CreateLogStream / logs:PutLogEvents (sandbox のロググループだけ)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

SIGNUPS="${1:-25}"
FOLLOWERS="${2:-8}"
if (( SIGNUPS < 1 || SIGNUPS > 200 || FOLLOWERS > SIGNUPS )); then
  echo "登録の IP 数は 1〜200、メッセージを送る IP 数は登録の IP 数以下にしてください" >&2
  exit 2
fi
LOG_GROUP="$(stack_output NginxLogGroupName)"
STREAM="scenario-11-$(date -u +%Y%m%dT%H%M%SZ)"

# 登録は 20 分前から 3 秒おき (25 IP で約 1 分 15 秒。10 分幅の境目をまたいでも片方に 10 IP 以上が残る)、
# メッセージは登録の 5 分後から 10 秒おき。PutLogEvents は時刻順が要るので、時刻順に並べて書く
base=$(( $(date -u +%s) - 20 * 60 ))
BOT_UA="Mozilla/5.0 (arata-sandbox-scenario-11)"

time_local() { # epoch 秒 → nginx の $time_local (GNU date と BSD date の両方)
  LC_ALL=C date -u -d "@$1" +'%d/%b/%Y:%H:%M:%S +0000' 2>/dev/null || LC_ALL=C date -u -r "$1" +'%d/%b/%Y:%H:%M:%S +0000'
}

line() { # 秒 ip method path status ua
  printf '%s - - [%s] "%s %s HTTP/1.1" %s 0 "-" "%s"' "$2" "$(time_local "$1")" "$3" "$4" "$5" "$6"
}

events="$(mktemp)"
trap 'rm -f "$events"' EXIT
{
  echo '['
  sep=''
  emit() { # 秒 ip method path status ua
    printf '%s{"timestamp":%d,"message":"%s"}\n' "$sep" "$(( $1 * 1000 ))" "$(line "$@" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    sep=','
  }
  # 正常な行 (解釈率の確認用。ふだんの登録 1 件を含む)
  for n in $(seq 10); do emit $(( base - 600 + n )) 192.0.2.20 GET / 200 "Mozilla/5.0 (arata-sandbox-normal)"; done
  emit $(( base - 500 )) 192.0.2.21 POST /signup 302 "Mozilla/5.0 (arata-sandbox-normal)"
  # 登録の集中: 203.0.113.11 から 1 IP 1 件。最後の 3 IP だけ UA が違う
  for n in $(seq "$SIGNUPS"); do
    ua="$BOT_UA"
    if (( n > SIGNUPS - 3 )); then ua="Mozilla/5.0 (arata-sandbox-variant-$n)"; fi
    emit $(( base + n * 3 )) "203.0.113.$(( 10 + n ))" POST /signup 302 "$ua"
  done
  # 先頭の FOLLOWERS 個の IP が 5 分後からメッセージ送信
  for n in $(seq "$FOLLOWERS"); do
    emit $(( base + 300 + n * 10 )) "203.0.113.$(( 10 + n ))" POST /messages 200 "$BOT_UA"
  done
  echo ']'
} > "$events"

aws logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name "$STREAM"
aws logs put-log-events --log-group-name "$LOG_GROUP" --log-stream-name "$STREAM" \
  --log-events "file://$events" --query 'rejectedLogEventsInfo' --output json
echo "入れた: $LOG_GROUP / $STREAM (登録 $SIGNUPS IP、うちメッセージ送信 $FOLLOWERS IP、正常 11 行。時刻は約 20 分前から)"

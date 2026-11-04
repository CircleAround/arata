package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// InsightsUSDPerGB は Logs Insights のスキャン量の単価 (ap-northeast-1、USD/GB)。doctor の費用の概算に使う。
// 決定 (ADR 0028): 単価はリージョンで違い、改定もあるので設定にはせず、表示に「東京の単価」と明記する (概算であることを示す)。
const InsightsUSDPerGB = 0.0076

// maxScanMargin は max_scan_gb の推奨値を 1 回の見積もりの何倍にするか (日による量の揺れの余裕)。
const maxScanMargin = 1.5

// wafCost は wafv2 のソースの Insights の費用を見積もり、max_scan_gb が無ければ warn にする (ADR 0028)。
//
// 決定:
//   - 1 日のログの量は、直近 24h に解釈率の集計 (stats) を流して実測する (1 日分のスキャンの費用がかかる。実測した範囲・読み取り量・その費用を出す)。
//     --no-measure-scan なら解釈率のサンプルのクエリ (直近 --window) のスキャン量から推定する (追加の費用なし。sandbox で約 75% に少なく出た)
//   - 1 回の run のスキャン = 1 日の量 × 範囲の日数 × クエリの本数。範囲は窓 + ingest_delay + 日の頭への寄せ (最大 24h) で、上限側で見積もる
//   - 決定 (ADR 0031): 日の頭への寄せは実行時刻で決まる (範囲の始まり To - 窓 - ingest_delay の UTC の時刻の分)。最小になる時刻
//     (UTC 0 時 + 窓 + ingest_delay + 余裕 15 分) と、その時の量を案内する。直近の run の時刻は保存したレポート (reports/<profile>.json の窓の終わり) から読み、
//     あればその範囲も出す (doctor はストアを開かない。レポートのファイルを読むだけ)
//   - プロファイルごとに、wafv2 を引くプロファイル (チェックが waf_action を必要とする) だけを、1 日の run 数 (24h / 窓) を掛けて足す
func (d *doctor) wafCost(ctx context.Context, src config.Source, c *cwlogs.Collector) {
	var daily float64
	how := ""
	if !d.opts.EstimateScan {
		before := c.Scanned()
		if _, err := c.Query(ctx, cwlogs.LinesQuery(c.Profile()), d.now.Add(-24*time.Hour), d.now); err != nil {
			d.addErr(src, "cost", err)
			return
		}
		daily = c.Scanned() - before
		how = fmt.Sprintf("実測: 直近 24h (%s〜%s UTC) に解釈率の集計を流し、読み取り %.2f GB、その費用 約 %.2f USD", d.now.Add(-24*time.Hour).UTC().Format("01-02 15:04"),
			d.now.UTC().Format("01-02 15:04"), daily/1e9, daily/1e9*InsightsUSDPerGB)
	} else if d.window > 0 {
		daily = c.Scanned() * float64(24*time.Hour) / float64(d.window)
		how = fmt.Sprintf("推定: 解釈率のサンプルのクエリの直近 %s のスキャン量から。少なく出ることがある (sandbox で約 75%%)", d.window)
	}
	n := c.QueryCount()
	var parts []string
	perRunMax, perDayUSD := 0.0, 0.0
	for _, name := range sortedProfiles(d.cfg) {
		prof := d.cfg.Profiles[name]
		if !d.profileNeeds(prof, record.KindWAFAction) || prof.Window <= 0 {
			continue
		}
		span := prof.Window + src.IngestDelay + 24*time.Hour
		perRun := daily / 1e9 * span.Hours() / 24 * float64(n)
		runs := math.Max(1, math.Floor(float64(24*time.Hour)/float64(prof.Window)))
		perRunMax = math.Max(perRunMax, perRun)
		perDayUSD += perRun * runs * InsightsUSDPerGB
		part := fmt.Sprintf("%s: 1 回最大 %.2f GB (クエリ %d 本 × 範囲最大 %.1f 時間) × 1 日 %.0f 回", name, perRun, n, span.Hours(), runs)
		gb := func(h float64) float64 { return daily / 1e9 * h / 24 * float64(n) }
		if to, ok := d.lastRunTo(ctx, name); ok {
			cur := scanSpan(to, prof.Window, src.IngestDelay)
			part += fmt.Sprintf("。直近の run (UTC %s、JST %s) では範囲 約 %.1f 時間 (1 回 %.2f GB)", to.UTC().Format("15:04"), to.In(jst).Format("15:04"), cur.Hours(), gb(cur.Hours()))
		}
		best := prof.Window + src.IngestDelay + scheduleMargin
		at := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(best % (24 * time.Hour))
		part += fmt.Sprintf("。範囲は実行時刻で決まり、UTC %s (JST %s) に回すと約 %.1f 時間 (1 回 %.2f GB、約 %.2f USD/30 日)",
			at.Format("15:04"), at.In(jst).Format("15:04"), best.Hours(), gb(best.Hours()), gb(best.Hours())*runs*InsightsUSDPerGB*30)
		parts = append(parts, part)
	}
	detail := fmt.Sprintf("1 日のログ 約 %.2f GB (%s)", daily/1e9, how)
	if len(parts) == 0 {
		detail += "。wafv2 を引くプロファイルが無い"
	} else {
		detail += "。" + strings.Join(parts, "、") + fmt.Sprintf(" → 約 %.2f USD/日・%.2f USD/30 日 (Logs Insights の東京の単価 %.4f USD/GB)", perDayUSD, perDayUSD*30, InsightsUSDPerGB)
	}
	status := DoctorOK
	switch {
	case src.MaxScanGB <= 0:
		status = DoctorWarn
		detail += "。max_scan_gb が未設定: WAF のような大きなロググループでは必ず設定する"
		if perRunMax > 0 {
			detail += fmt.Sprintf(" (推奨 %.0f)", math.Ceil(perRunMax*maxScanMargin))
		}
	case perRunMax > src.MaxScanGB:
		status = DoctorWarn
		detail += fmt.Sprintf("。max_scan_gb %.0f が 1 回の見積もり %.2f GB より小さい: 集計が QUERY_LIMIT で欠けることがある (推奨 %.0f)", src.MaxScanGB, perRunMax, math.Ceil(perRunMax*maxScanMargin))
	default:
		detail += fmt.Sprintf("。max_scan_gb %.0f", src.MaxScanGB)
	}
	// 決定 (ADR 0038): 収集に失敗した期間は次の run で引き直すので、その分だけスキャン量が増える
	d.add(src, "cost", status, "", detail+"。収集に失敗した期間は次の run で追いつくので、その分スキャン量が増える (max_scan_gb で止まり、coverage に出る)")
}

// scheduleMargin は範囲が最小になる実行時刻に足す余裕 (cron の揺れで範囲の始まりが 0 時の前に出ると、前日の 0 時からになり範囲が 24h 増える)。
const scheduleMargin = 15 * time.Minute

var jst = time.FixedZone("JST", 9*60*60)

// scanSpan は窓の終わり to の run が Insights に問い合わせる範囲の長さ (cwlogs.Collect と同じく、範囲の始まりを含む UTC の日の 0 時から to まで)。
func scanSpan(to time.Time, window, delay time.Duration) time.Duration {
	return to.Sub(cwlogs.DayStart(to.Add(-window - delay)))
}

// lastRunTo は保存した profile のレポートの窓の終わり (直近の run の時刻)。無い・読めなければ ok = false。
func (d *doctor) lastRunTo(ctx context.Context, profile string) (time.Time, bool) {
	b, err := d.savedReport(ctx, profile)
	if err != nil {
		return time.Time{}, false
	}
	var rep struct {
		Window struct {
			To string `json:"to"`
		} `json:"window"`
	}
	if json.Unmarshal(b, &rep) != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, rep.Window.To)
	return t, err == nil
}

// maxSavedReportBytes は doctor が S3 から読むレポートの上限。
const maxSavedReportBytes = 64 << 20

// savedReport は保存した profile のレポート。doctor はストアを開かないので、s3:// ではそのオブジェクトだけを読む。
func (d *doctor) savedReport(ctx context.Context, profile string) ([]byte, error) {
	rel := filepath.Join("reports", profile+".json")
	if d.cfg.Store.Scheme != "s3" {
		if d.cfg.Store.Dir == "" {
			return nil, os.ErrNotExist
		}
		return os.ReadFile(filepath.Join(d.cfg.Store.Dir, rel))
	}
	api, err := d.deps.S3Store(ctx, d.cfg)
	if err != nil {
		return nil, err
	}
	key := s3Location(d.cfg).Key(rel)
	out, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.cfg.Store.Bucket, Key: &key})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	// 上限を超えたら途中までになり、解釈できずに「無い」扱いになる
	return io.ReadAll(io.LimitReader(out.Body, maxSavedReportBytes))
}

func sortedProfiles(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Profiles))
	for n := range cfg.Profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// profileNeeds はプロファイルのチェックが k を収集させるか (保存済みだけを読む StoredNeeds は数えない)。
func (d *doctor) profileNeeds(prof config.Profile, k record.Kind) bool {
	for _, name := range prof.ExpandChecks(d.deps.Registry.Defaults()) {
		if c, ok := d.deps.Registry.Get(name); ok {
			for _, n := range c.Needs() {
				if n == k {
					return true
				}
			}
		}
	}
	return false
}

// wafResources は wafv2 のソースの resources を、ログの宛先がこのロググループの WebACL の資源 (ListResourcesForWebACL) と突き合わせる (ADR 0028)。
//
// 決定:
//   - waf-config のソースが設定に無くても、wafv2 のソースのリージョンで waf-config の collector を一時的に作って読む (読み取りだけ)
//   - ログの httpSourceId と資源の ARN の対応は公式文書の説明と例で食い違う (ALB は load-balancer-id、API Gateway は説明が api-id で
//     例が <アカウント>:<api-id>:<ステージ>)。両方の形を候補にして照合し、どれにも当たらなければ warn (照合は推定なので ng にしない)
func (d *doctor) wafResources(ctx context.Context, src config.Source) {
	if len(src.Resources) == 0 {
		return
	}
	e := &Engine{cfg: d.cfg, deps: d.deps, log: d.deps.Logger}
	wsrc := config.Source{ID: src.ID, Kind: config.KindWAFConfig, Regions: src.Regions}
	c, err := e.collector(ctx, wsrc)
	if err != nil {
		d.add(src, "resources", DoctorWarn, "", "WebACL の資源を読めない: "+err.Error())
		return
	}
	var items []record.SnapshotItem
	sink := collect.SinkFunc(func(_ context.Context, rec record.Record) error {
		switch it := rec.(type) {
		case record.SnapshotItem:
			items = append(items, it)
		case *record.SnapshotItem:
			items = append(items, *it)
		}
		return nil
	})
	if err := c.Collect(ctx, collect.Window{From: d.now.Add(-time.Hour), To: d.now}, sink); err != nil {
		ce := collect.Classify(src.ID, "", err)
		d.add(src, "resources", DoctorWarn, "", "WebACL の資源を読めない (waf-config と同じ wafv2 の読み取りが要る): "+ce.Err.Error())
		return
	}
	var acls, unknown []string
	candidates := map[string]bool{}
	for _, it := range items {
		if it.String("item") != "web_acl" || !contains(strings.Split(it.String("log_destinations"), ","), src.LogGroup) {
			continue
		}
		acls = append(acls, it.String("acl"))
		account := arnAccount(it.String("arn"))
		for _, arn := range strings.Split(it.String("resources"), ",") {
			for _, id := range sourceIDCandidates(arn, account) {
				candidates[id] = true
			}
		}
		if u := it.String("resources_unknown"); u != "" {
			unknown = append(unknown, u)
		}
	}
	if len(acls) == 0 {
		d.add(src, "resources", DoctorWarn, "", "ログの宛先が "+src.LogGroup+" の WebACL が見つからない ("+strings.Join(src.Regions, ",")+")。resources を突き合わせられない")
		return
	}
	var missing []string
	for _, pat := range src.Resources {
		re := regexp.MustCompile("^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pat)) + "$")
		found := false
		for id := range candidates {
			if re.MatchString(id) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, pat)
		}
	}
	detail := "WebACL " + strings.Join(acls, ", ")
	if len(unknown) > 0 {
		detail += " (読めなかった資源の種類: " + strings.Join(unknown, "; ") + ")"
	}
	if len(missing) > 0 {
		d.add(src, "resources", DoctorWarn, "", "resources の "+strings.Join(missing, ", ")+" が "+detail+" の資源に見当たらない "+
			"(ログの httpSourceId の形は推定で照合している。doctor の解釈率のサンプルか Insights で httpSourceId を確かめる)")
		return
	}
	d.add(src, "resources", DoctorOK, "", "resources がすべて "+detail+" の資源に一致")
}

// arnAccount は ARN のアカウント ID (5 番目の欄)。
func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// sourceIDCandidates は資源の ARN から、WAF のログの httpSourceId になり得る値を作る (公式文書の説明と例の両方の形)。
func sourceIDCandidates(arn, account string) []string {
	if arn == "" {
		return nil
	}
	out := []string{arn}
	_, res, _ := strings.Cut(arn, ":loadbalancer/")
	switch {
	case res != "": // ALB: loadbalancer/app/<name>/<id>
		segs := strings.Split(res, "/")
		if len(segs) == 3 {
			out = append(out, segs[2], segs[1]+"/"+segs[2], res, account+"-"+res)
		}
	case strings.Contains(arn, ":apigateway:"): // REST API: /restapis/<api-id>/stages/<stage>
		segs := strings.Split(arn, "/")
		if len(segs) >= 5 && segs[1] == "restapis" && segs[3] == "stages" {
			api, stage := segs[2], segs[4]
			out = append(out, api, api+":"+stage, account+":"+api+":"+stage)
		}
	default:
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			out = append(out, arn[i+1:])
		}
	}
	return out
}

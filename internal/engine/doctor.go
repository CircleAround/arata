package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/checks"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// doctor の検査結果の状態。ng が 1 つでもあれば終了コード 2。
const (
	DoctorOK   = "ok"
	DoctorWarn = "warn"
	DoctorNG   = "ng"
)

// DoctorSampleLines は解釈率を見る直近の行数 (設計書 2 章)。
const DoctorSampleLines = 100

// DoctorRow は検査 1 項目。
type DoctorRow struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Item   string `json:"item"` // config / permission / log_group / match_rate / queries / check
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail"`
	// Samples は解釈できなかった行の例 (マスク済み、sample_lines: false なら空)。
	Samples []string `json:"samples,omitempty"`
}

// DoctorResult は doctor の結果。
type DoctorResult struct {
	Rows []DoctorRow `json:"rows"`
	// RequiredActions は設定のソースに必要な IAM action (読み取りロールに付ける)。
	RequiredActions []string `json:"required_actions"`
	// StoreActions は s3:// のストアのバケットに必要な IAM action。監査対象の読み取りロールには付けない (ADR 0034)。
	StoreActions []string `json:"store_actions,omitempty"`
}

// Problems は ng の項目があるか。
func (r *DoctorResult) Problems() bool {
	for _, row := range r.Rows {
		if row.Status == DoctorNG {
			return true
		}
	}
	return false
}

// Doctor は設定のソースごとに権限・ロググループ・形式プロファイルの解釈率を実際に問い合わせて検査する (設計書 2 / 8 章)。
// ストアは開かない (run と並行して実行でき、ロックを取らない)。s3:// のストアはバケットを読めるかだけを確かめる。window は解釈率のサンプルを取る範囲 (直近 100 行)。
//
// 決定: 集計クエリのテンプレートは StartQuery して直ちに StopQuery し、Insights の構文検査 (MalformedQueryException) だけを受ける。
// スキャンはほぼ発生しない。
func Doctor(ctx context.Context, cfg *config.Config, deps Deps, window time.Duration, opts ...DoctorOptions) *DoctorResult {
	deps.fill(cfg)
	d := &doctor{cfg: cfg, deps: deps, now: deps.Now(), window: window, res: &DoctorResult{Rows: []DoctorRow{}}}
	if len(opts) > 0 {
		d.opts = opts[0]
	}
	d.allowlist()
	d.store(ctx)
	actions := map[string]bool{}
	for _, src := range cfg.Sources {
		switch src.Kind {
		case config.KindCloudTrailLookup:
			actions["cloudtrail:LookupEvents"] = true
			d.cloudtrail(ctx, src)
		case config.KindCloudWatchLogs:
			for _, a := range cwlogs.RequiredActions {
				actions[a] = true
			}
			d.logs(ctx, src)
		case config.KindCloudTrailUnusedRegions:
			for _, a := range account.RequiredActions[src.Kind] {
				actions[a] = true
			}
			d.unusedRegions(ctx, src)
		default:
			for _, a := range account.RequiredActions[src.Kind] {
				actions[a] = true
			}
			d.probe(ctx, src)
			if src.Kind == config.KindCostAnomaly {
				d.costAnomalyCost(src)
			}
		}
	}
	d.checks()
	for a := range actions {
		d.res.RequiredActions = append(d.res.RequiredActions, a)
	}
	sort.Strings(d.res.RequiredActions)
	for _, row := range d.res.Rows {
		if row.Status != DoctorNG {
			continue
		}
		attrs := []any{"code", row.Code, "source", row.Source, "item", row.Item, "detail", row.Detail}
		deps.Logger.Error("doctor found a problem", attrs...)
	}
	for _, row := range d.res.Rows {
		if row.Status == DoctorWarn && row.Code == CodeCheckUnused {
			deps.Logger.Warn("doctor found unused checks", "code", row.Code, "item", row.Item, "detail", row.Detail)
		}
	}
	return d.res
}

// DoctorOptions は doctor の任意の動き。
type DoctorOptions struct {
	// EstimateScan は wafv2 のソースの 1 日のスキャン量を、解釈率のサンプルのクエリのスキャン量から推定する (追加の費用なし)。
	// 既定 (false) は直近 24h に解釈率の集計 (stats) を流して実測する (1 日分のスキャンの費用がかかる)。
	// 決定 (ADR 0028): sandbox で sort+limit のスキャン量は stats の約 75% に少なく出た (途中で読むのをやめることがある) ので、実測を既定にする。
	EstimateScan bool
}

type doctor struct {
	opts   DoctorOptions
	cfg    *config.Config
	deps   Deps
	now    time.Time
	window time.Duration
	res    *DoctorResult
}

func (d *doctor) add(src config.Source, item, status, code, detail string) {
	d.res.Rows = append(d.res.Rows, DoctorRow{Source: src.ID, Kind: src.Kind, Item: item, Status: status, Code: code, Detail: detail})
}

func (d *doctor) addErr(src config.Source, item string, err error) {
	ce := collect.Classify(src.ID, "", err)
	detail := ce.Err.Error()
	if ce.Action != "" {
		detail = ce.Action + " が拒否された: " + detail
	}
	d.add(src, item, DoctorNG, ce.Code, detail)
}

func (d *doctor) allowlist() {
	if _, err := allowlist.Load(d.cfg.Allowlist); err != nil {
		d.res.Rows = append(d.res.Rows, DoctorRow{Source: "-", Kind: "-", Item: "config", Status: DoctorNG, Code: CodeConfigInvalid, Detail: err.Error()})
	}
}

func (d *doctor) cloudtrail(ctx context.Context, src config.Source) {
	for _, region := range src.Regions {
		api, err := d.deps.CloudTrail(ctx, d.cfg, src, region)
		if err == nil {
			err = d.deps.Limiter.Wait(ctx)
		}
		if err == nil {
			_, err = api.LookupEvents(ctx, &ct.LookupEventsInput{StartTime: aws.Time(d.now.Add(-time.Hour)), EndTime: aws.Time(d.now), MaxResults: aws.Int32(1)})
		}
		if err != nil {
			d.addErr(src, "permission", fmt.Errorf("%s: %w", region, wrapAction(err, "cloudtrail:LookupEvents")))
			continue
		}
		d.add(src, "permission", DoctorOK, "", "cloudtrail:LookupEvents ("+region+")")
	}
}

// wrapAction は ACCESS_DENIED に action を添える。
func wrapAction(err error, action string) error {
	ce := collect.Classify("", action, err)
	if ce.Code == collect.CodeAccessDenied {
		return ce
	}
	return err
}

// probe はアカウント単位のソースの権限を、collector の読み取り API で 1 回ずつ試す (書き込み系の GenerateCredentialReport は試さない)。
// 決定: 拒否された action は ng (ACCESS_DENIED)。そのソースのチェックは run で skip され (posture は取れた項目だけで評価)、他のソースは続行する。
func (d *doctor) probe(ctx context.Context, src config.Source) {
	e := &Engine{cfg: d.cfg, deps: d.deps, log: d.deps.Logger}
	c, err := e.collector(ctx, src)
	if err != nil {
		d.addErr(src, "permission", err)
		return
	}
	p, ok := c.(collect.Prober)
	if !ok {
		return
	}
	for _, r := range p.Probe(ctx) {
		detail := r.Action
		if r.Detail != "" {
			detail += " (" + r.Detail + ")"
		}
		if r.Err != nil {
			d.addErr(src, "permission", wrapAction(fmt.Errorf("%s: %w", detail, r.Err), r.Action))
			continue
		}
		if r.Warn != "" {
			d.add(src, "permission", DoctorWarn, "", detail+": "+r.Warn)
			continue
		}
		d.add(src, "permission", DoctorOK, "", detail)
	}
}

// unusedRegions は有効なリージョンの一覧と、ふだん使わない各リージョンの LookupEvents (1 件) を試す (ADR 0032)。
func (d *doctor) unusedRegions(ctx context.Context, src config.Source) {
	e := &Engine{cfg: d.cfg, deps: d.deps, log: d.deps.Logger}
	c, err := e.collector(ctx, src)
	if err != nil {
		d.addErr(src, "permission", err)
		return
	}
	ur := c.(*cloudtrail.UnusedRegions)
	enabled, targets, results := ur.Probe(ctx, d.now)
	for _, r := range results {
		switch {
		case r.Err != nil && r.Detail != "":
			d.addErr(src, "permission", wrapAction(fmt.Errorf("%s (%s): %w", r.Action, r.Detail, r.Err), r.Action))
		case r.Err != nil:
			d.addErr(src, "permission", wrapAction(r.Err, r.Action))
		case r.Action == cloudtrail.ActionListRegions:
			detail := fmt.Sprintf("%s (有効なリージョン %d、ふだん使うリージョン %s を除く %d", r.Action, len(enabled), strings.Join(d.cfg.ActiveRegions(), ", "), len(targets))
			if len(targets) > 0 {
				detail += ": " + strings.Join(targets, ", ")
			}
			d.add(src, "permission", DoctorOK, "", detail+")")
		default:
			d.add(src, "permission", DoctorOK, "", r.Action+" ("+r.Detail+")")
		}
	}
	if len(results) > 0 && results[0].Err == nil {
		d.add(src, "cost", DoctorOK, "", fmt.Sprintf("LookupEvents は無料。1 回の run でリージョン %d × 1〜数回 (使っていないリージョンはふつう 1 回)", len(targets)))
	}
}

// costAnomalyCost は Cost Explorer の API の費用の見込みを出す (1 回の run で GetAnomalyMonitors 1 回 + GetAnomalies 1 ページ。ADR 0032)。
func (d *doctor) costAnomalyCost(src config.Source) {
	const perRun = 2
	var parts []string
	perDay := 0.0
	for _, name := range sortedProfiles(d.cfg) {
		prof := d.cfg.Profiles[name]
		if !d.profileNeeds(prof, record.KindCostAnomaly) || prof.Window <= 0 {
			continue
		}
		runs := math.Max(1, math.Floor(float64(24*time.Hour)/float64(prof.Window)))
		perDay += runs * perRun * account.CostExplorerUSDPerRequest
		parts = append(parts, fmt.Sprintf("%s: 1 日 %.0f 回 × %d リクエスト", name, runs, perRun))
	}
	detail := fmt.Sprintf("Cost Explorer の API 1 リクエスト %.2f USD。", account.CostExplorerUSDPerRequest)
	if len(parts) == 0 {
		detail += "cost_anomaly を入れたプロファイルが無い"
	} else {
		detail += strings.Join(parts, "、") + fmt.Sprintf(" → 約 %.2f USD/日・%.2f USD/30 日 (異常が多くページが増えればその分増える。doctor 自身も約 %.2f USD)",
			perDay, perDay*30, perRun*account.CostExplorerUSDPerRequest)
	}
	d.add(src, "cost", DoctorOK, "", detail)
}

func (d *doctor) logs(ctx context.Context, src config.Source) {
	api, err := d.deps.CloudWatchLogs(ctx, d.cfg, src, src.Regions[0])
	if err != nil {
		d.addErr(src, "permission", err)
		return
	}
	c, err := cwlogs.New(src, d.cfg.Checks, api)
	if err != nil {
		d.add(src, "config", DoctorNG, CodeConfigInvalid, err.Error())
		return
	}
	c.Logger = d.deps.Logger
	c.Now = func() time.Time { return d.now }
	if d.deps.Sleep != nil {
		c.Sleep = d.deps.Sleep
	}
	// ロググループの存在 (名前の前方一致で引き、完全一致を探す)
	out, err := api.DescribeLogGroups(ctx, &cwl.DescribeLogGroupsInput{LogGroupNamePrefix: aws.String(src.LogGroup)})
	if err != nil {
		d.addErr(src, "log_group", wrapAction(err, cwlogs.ActionDescribeLogGroups))
		return
	}
	found := false
	for _, g := range out.LogGroups {
		if aws.ToString(g.LogGroupName) == src.LogGroup {
			found = true
			c.SetLogGroup(g) // 作成時刻と保持期間で問い合わせ範囲を判定する (cwlogs.queryRange)
		}
	}
	if !found {
		d.add(src, "log_group", DoctorNG, collect.CodeLogGroupMissing, src.LogGroup+" が "+src.Regions[0]+" に無い")
		return
	}
	d.add(src, "log_group", DoctorOK, "", src.LogGroup+" ("+src.Regions[0]+")")

	prof := c.Profile()

	// クエリのテンプレートが Insights に受け付けられるか。決定: 集計だけでなく、サンプル (FORMAT_MISMATCH 時) と doctor 自身のクエリも検査する
	queries := map[string]string{
		"lines":  cwlogs.LinesQuery(prof),
		"sample": cwlogs.SampleQuery(prof, cwlogs.SampleLines),
		"doctor": cwlogs.DoctorQuery(prof, DoctorSampleLines),
	}
	for n, q := range c.Queries() {
		queries[n] = q
	}
	names := make([]string, 0, len(queries))
	for n := range queries {
		names = append(names, n)
	}
	sort.Strings(names)
	var bad []string
	for _, n := range names {
		if err := c.Validate(ctx, queries[n], d.now.Add(-time.Minute), d.now); err != nil {
			ce := collect.Classify(src.ID, "", err)
			bad = append(bad, n)
			d.add(src, "queries", DoctorNG, ce.Code, n+": "+ce.Err.Error())
		}
	}
	if len(bad) == 0 {
		d.add(src, "queries", DoctorOK, "", fmt.Sprintf("%d 本のクエリを Insights が受理 (%s)", len(names), strings.Join(names, ", ")))
	}

	// 解釈率: 直近 100 行を形式プロファイルで解釈する
	rows, err := c.Query(ctx, cwlogs.DoctorQuery(prof, DoctorSampleLines), d.now.Add(-d.window), d.now)
	if err != nil {
		d.addErr(src, "match_rate", err)
	} else {
		d.matchRate(src, prof, rows)
	}
	if prof.Yields == record.KindWAFAction {
		d.wafCost(ctx, src, c)
		d.wafResources(ctx, src)
	}
}

func (d *doctor) matchRate(src config.Source, prof cwlogs.Profile, rows []map[string]string) {
	total, matched := len(rows), 0
	var samples []string
	for _, r := range rows {
		if cwlogs.Matched(prof, r) {
			matched++
		} else if src.SampleLines && len(samples) < cwlogs.SampleLines {
			samples = append(samples, cwlogs.MaskSample(r["@message"]))
		}
	}
	if total == 0 {
		d.add(src, "match_rate", DoctorWarn, "", fmt.Sprintf("直近 %s に行が無い (stream_prefix とロググループを確認)", d.window))
		return
	}
	rate := float64(matched) / float64(total)
	detail := fmt.Sprintf("%.2f (%d/%d 行、閾値 %.2f、形式 %s)", rate, matched, total, src.ExpectedMatchRate, src.Format)
	if rate < src.ExpectedMatchRate {
		d.res.Rows = append(d.res.Rows, DoctorRow{Source: src.ID, Kind: src.Kind, Item: "match_rate", Status: DoctorNG, Code: collect.CodeFormatMismatch, Detail: detail, Samples: samples})
		return
	}
	d.add(src, "match_rate", DoctorOK, "", detail)
}

// checks は各プロファイルのチェックのうち、必要なレコードを出すソースが無いものを警告する。
func (d *doctor) checks() {
	available := map[record.Kind]bool{}
	for _, src := range d.cfg.Sources {
		for _, k := range kindsOf(src) {
			available[k] = true
		}
	}
	missing := map[string]map[string]bool{} // check → profiles
	reasons := map[string]string{}
	profiles := make([]string, 0, len(d.cfg.Profiles))
	for p := range d.cfg.Profiles {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, pname := range profiles {
		for _, name := range d.cfg.Profiles[pname].ExpandChecks(d.deps.Registry.Defaults()) {
			c, ok := d.deps.Registry.Get(name)
			if !ok {
				d.res.Rows = append(d.res.Rows, DoctorRow{Source: "-", Kind: "-", Item: "check", Status: DoctorNG, Code: CodeConfigInvalid, Detail: fmt.Sprintf("profile %s: unknown check %q", pname, name)})
				continue
			}
			needs := c.Needs()
			if sn, ok := c.(checks.StoredNeeder); ok {
				needs = append(append([]record.Kind{}, needs...), sn.StoredNeeds()...)
			}
			for _, k := range needs {
				if !available[k] {
					if missing[name] == nil {
						missing[name] = map[string]bool{}
					}
					missing[name][pname] = true
					reasons[name] = fmt.Sprintf("no %s source", k)
				}
			}
		}
	}
	if unused := UnusedChecks(d.cfg, d.deps.Registry); len(unused) > 0 {
		d.res.Rows = append(d.res.Rows, DoctorRow{Source: "-", Kind: "-", Item: "check", Status: DoctorWarn, Code: CodeCheckUnused,
			Detail: fmt.Sprintf("どのプロファイルにも入っていない (実行されない): %s", strings.Join(unused, ", "))})
	}
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ps := make([]string, 0, len(missing[n]))
		for p := range missing[n] {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		d.res.Rows = append(d.res.Rows, DoctorRow{Source: "-", Kind: "-", Item: "check", Status: DoctorWarn,
			Detail: fmt.Sprintf("%s は skip される: %s (profile %s)", n, reasons[n], strings.Join(ps, ", "))})
	}
}

// WriteTable は人向けの表を書く。
func (r *DoctorResult) WriteTable(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tKIND\tITEM\tSTATUS\tCODE\tDETAIL")
	for _, row := range r.Rows {
		code := row.Code
		if code == "" {
			code = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Source, row.Kind, row.Item, row.Status, code, row.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, row := range r.Rows {
		for _, s := range row.Samples {
			fmt.Fprintf(w, "  %s: 解釈できなかった行の例: %s\n", row.Source, s)
		}
	}
	fmt.Fprintf(w, "\n必要な IAM action: %s\n", strings.Join(r.RequiredActions, ", "))
	for _, a := range r.RequiredActions {
		if a == account.ActionGenerateCredentialReport {
			fmt.Fprintf(w, "  (%s だけは書き込み系: 認証情報レポートの生成のみ。拒否されても 4 時間以内に生成済みのレポートがあれば使う)\n", a)
		}
	}
	if len(r.StoreActions) > 0 {
		fmt.Fprintf(w, "ストアのバケットに必要な IAM action (監査対象の読み取りロールとは別): %s\n", strings.Join(r.StoreActions, ", "))
	}
	ng, warn := 0, 0
	for _, row := range r.Rows {
		switch row.Status {
		case DoctorNG:
			ng++
		case DoctorWarn:
			warn++
		}
	}
	fmt.Fprintf(w, "結果: ng %d / warn %d\n", ng, warn)
	return nil
}

// ErrDoctorProblems は doctor が ng を見つけたことを表す (終了コード 2)。
var ErrDoctorProblems = errors.New("doctor found problems")

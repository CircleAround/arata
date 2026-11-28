package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CircleAround/arata/internal/collect/cwlogs"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

// doctorIPUsersTop は ip_users の行で突き合わせる IP の数。
const doctorIPUsersTop = 20

// doctorIPUsersMinShare は ok にする割合の下限 (上位の IP のうち http_access のソースに現れたもの)。
const doctorIPUsersMinShare = 0.5

// ipUsers は rate_limited_ip.user_sources のソースについて、ログインできた利用者の多い IP (U3 の上位) が、http_access のほかのソースの IP に現れる割合を出す
// (ADR 0094 の「確かめが要る点」の 1)。
//
// 決定: request_lines の最初の行の ip は、アプリが信頼するプロキシの設定 (Rails の remote_ip) 次第で ALB の内側の IP になりうる。
// そうなると ip_users は 429 の IP (ALB のログの client の IP) と突き合わせられない。そこで直近の window に U3 を 1 本流し、上位 20 の IP を、
// ほかの http_access の cloudwatch-logs のソースで探す (IP を入れた filter の 1 本ずつ。読む量はそのソースの window の分)。
// 半分以上が現れれば ok、下回れば warn (同じリクエストは入口のログにも残るので、値が同じなら全部近くが現れる)。比べるソースが無ければ warn。
func (d *doctor) ipUsers(ctx context.Context, src config.Source, c *cwlogs.Collector) {
	before := c.Scanned()
	from := d.now.Add(-d.window)
	top, err := c.IPUsersTop(ctx, from, d.now, doctorIPUsersTop)
	if err != nil {
		d.addErr(src, "ip_users", err)
		return
	}
	scanned := c.Scanned() - before
	if len(top) == 0 {
		d.add(src, "ip_users", DoctorWarn, "", fmt.Sprintf("直近 %s にログインした利用者の IP が無い (request.user_id と、最初の行の ip を確認)", d.window))
		return
	}
	seen := map[string]bool{}
	var others []string
	for _, o := range d.cfg.Sources {
		if o.ID == src.ID || o.Kind != config.KindCloudWatchLogs || o.Yields != string(record.KindHTTPAccess) {
			continue
		}
		api, err := d.deps.CloudWatchLogs(ctx, d.cfg, o, o.Regions[0])
		if err != nil {
			d.addErr(src, "ip_users", err)
			return
		}
		oc, err := cwlogs.New(o, d.cfg.Checks, api)
		if err != nil {
			continue // そのソースの config の行が ng にする
		}
		oc.Logger, oc.Now = d.deps.Logger, func() time.Time { return d.now }
		if d.deps.Sleep != nil {
			oc.Sleep = d.deps.Sleep
		}
		got, err := oc.IPsPresent(ctx, top, from, d.now)
		if err != nil {
			d.addErr(src, "ip_users", err)
			return
		}
		scanned += oc.Scanned()
		for ip := range got {
			seen[ip] = true
		}
		others = append(others, o.ID)
	}
	if len(others) == 0 {
		d.add(src, "ip_users", DoctorWarn, "", fmt.Sprintf("ログインできた利用者の多い IP %d 個を突き合わせる http_access のほかのソース (ALB のアクセスログなど) が無い。"+
			"rate_limited_ip は 429 を http_access のソースで数えるので、ip_users はそのソースの IP と同じ値である必要がある", len(top)))
		return
	}
	share := float64(len(seen)) / float64(len(top))
	detail := fmt.Sprintf("直近 %s のログインできた利用者の多い IP %d 個のうち %d 個 (%.2f) が %s の IP に現れる。スキャン %.1f MB",
		d.window, len(top), len(seen), share, strings.Join(others, ", "), scanned/1e6)
	if share < doctorIPUsersMinShare {
		d.add(src, "ip_users", DoctorWarn, "", detail+fmt.Sprintf("。%.2f 未満: アプリのログの ip が入口の client の IP と違う (ALB の内側の IP など) と、ip_users は 429 の IP と突き合わせられない。"+
			"アプリが信頼するプロキシの設定 (Rails の remote_ip) を確かめる", doctorIPUsersMinShare))
		return
	}
	d.add(src, "ip_users", DoctorOK, "", detail)
}

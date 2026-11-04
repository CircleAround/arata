package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// PublicExposure は資源を外部に開く設定変更 (セキュリティグループ・S3・RDS・スナップショット・Lambda) を報告する (ADR 0026)。
//
// 決定:
//   - 成功したもの (errorCode なし) だけ。判定は collector が requestParameters から取り出した値で行う (ポリシー全文は残さない)
//   - Key は「操作 | 資源 | 開いた中身」。同じ資源を同じように開いた呼び出しは主体をまとめて 1 件 (主体は Data の principals)
//   - deploy タグの主体でも下げない (公開は意図していても毎回見るべき)。止めたいときは ack (重大度が上がれば再報告される)。
//     deploy の主体だったことは Data の known_deploy_principal に残す
//   - ModifySecurityGroupRules は記録に向き (ingress / egress) が無いので 1 段下げ、Data に direction_unknown を残す
//     (既定の egress の 0.0.0.0/0 全ポートの編集を high にしないため)
type PublicExposure struct {
	Config config.PublicExposure
}

func (PublicExposure) Name() string         { return "public_exposure" }
func (PublicExposure) Cadence() Cadence     { return Daily }
func (PublicExposure) Mode() Mode           { return ModeEvent }
func (PublicExposure) Needs() []record.Kind { return []record.Kind{record.KindTrailEvent} }

var publicExposureAPIs = concatAPIs(
	apisOf(srcEC2, "AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules", "ModifySnapshotAttribute", "ModifyImageAttribute"),
	apisOf(srcS3, "PutBucketPolicy", "PutBucketAcl", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutPublicAccessBlock", "DeletePublicAccessBlock", "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"),
	apisOf(srcRDS, "ModifyDBInstance", "CreateDBInstance", "ModifyDBCluster", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"),
	[]API{{Source: srcLambda, Name: "AddPermission", Prefix: true}},
)

// PublicExposureAPIs は public_exposure が見る操作。
func PublicExposureAPIs() []API { return append([]API(nil), publicExposureAPIs...) }

func (c PublicExposure) Evaluate(ctx context.Context, q store.Query, w collect.Window, al *allowlist.List) ([]Observation, error) {
	evs, err := windowEvents(ctx, q, w, store.EventFilter{EventSources: apiSources(publicExposureAPIs), WriteOnly: true})
	if err != nil {
		return nil, err
	}
	sensitive := map[int]bool{}
	for _, p := range c.Config.SensitivePorts {
		sensitive[p] = true
	}
	aggs := map[string]*eventAgg{}
	sev := map[string]Severity{}
	principals := map[string]map[string]bool{}
	for _, e := range evs {
		if e.ErrorCode != "" {
			continue
		}
		api, ok := findAPI(publicExposureAPIs, e)
		if !ok {
			continue
		}
		x := exposureOf(api, e, sensitive)
		if x.sev == "" {
			continue
		}
		label := apiLabel(api)
		k := label + "|" + x.target + "|" + x.what
		a, ok := aggs[k]
		if !ok {
			a = newEventAgg()
			a.extra["api"] = label
			a.extra["target"] = x.target
			a.extra["exposure"] = x.what
			a.extra["principal"] = e.PrincipalARN
			a.extra["principal_kind"] = string(e.PrincipalKind)
			for dk, dv := range x.data {
				a.extra[dk] = dv
			}
			aggs[k] = a
			principals[k] = map[string]bool{}
		}
		if sev[k].Rank() < x.sev.Rank() {
			sev[k] = x.sev
		}
		principals[k][e.PrincipalARN] = true
		if knownDeploy(al, e.PrincipalARN, w.To) {
			a.extra["known_deploy_principal"] = true
		}
		a.add(e.Time, e.Name, e.IP)
	}
	obs := map[string]Observation{}
	for k, a := range aggs {
		ps := sortedKeys(principals[k])
		a.extra["principals"] = ps
		who := record.PrincipalLabel(a.extra["principal"].(string), record.PrincipalKind(a.extra["principal_kind"].(string)))
		if len(ps) > 1 {
			who += fmt.Sprintf(" ほか %d 主体", len(ps)-1)
		}
		summary := fmt.Sprintf("公開設定の変更 %s: %s を %s (%s、%d 件)", a.extra["api"], a.extra["target"], describeExposure(a.extra), who, a.count)
		obs[k] = Observation{Check: c.Name(), Key: k, Severity: sev[k], Summary: summary, Data: a.data(),
			Fingerprint: fingerprint(sev[k], a.ips, a.extra["target"], a.extra["exposure"])}
	}
	return sortedObs(obs), nil
}

type exposure struct {
	sev    Severity
	target string
	what   string // Key の「開いた中身」
	data   map[string]any
}

func exposureOf(api API, e record.TrailEvent, sensitive map[int]bool) exposure {
	d := e.Data
	x := exposure{data: map[string]any{}}
	switch {
	case api.Source == srcEC2 && (api.Name == "AuthorizeSecurityGroupIngress" || api.Name == "ModifySecurityGroupRules"):
		rules := dataMaps(d, "public_ingress")
		if len(rules) == 0 {
			return exposure{}
		}
		x.target = dataStr(d, "group_id")
		x.sev = Low
		var opens []string
		sens := false
		for _, r := range rules {
			o, s := sgOpening(r, sensitive)
			opens = append(opens, o)
			sens = sens || s
		}
		if sens {
			x.sev = High
			x.data["sensitive"] = true
		}
		if api.Name == "ModifySecurityGroupRules" {
			x.sev = lowerOne(x.sev)
			x.data["direction_unknown"] = true
		}
		x.what = strings.Join(uniqSorted(opens), ",")
	case api.Source == srcEC2 || api.Name == "ModifyDBSnapshotAttribute" || api.Name == "ModifyDBClusterSnapshotAttribute":
		if v, _ := dataBool(d, "shared_public"); !v {
			return exposure{}
		}
		for _, k := range []string{"snapshot_id", "image_id", "db_snapshot", "db_cluster_snapshot"} {
			if t := dataStr(d, k); t != "" {
				x.target = t
				break
			}
		}
		x.sev, x.what = High, "all"
	case api.Source == srcS3:
		x.target = dataStr(d, "bucket")
		if strings.Contains(api.Name, "Account") {
			x.target = "account"
		}
		switch api.Name {
		case "PutBucketPolicy":
			if v, _ := dataBool(d, "policy_public"); !v {
				return exposure{}
			}
			x.sev, x.what = High, "public_policy"
			if st := dataStrings(d, "public_statements"); len(st) > 0 {
				x.data["public_statements"] = st
			}
		case "PutBucketAcl":
			g := dataStrings(d, "acl_public_grants")
			if len(g) == 0 {
				return exposure{}
			}
			x.sev, x.what = High, strings.Join(g, ",")
		case "PutBucketPublicAccessBlock", "PutPublicAccessBlock", "PutAccountPublicAccessBlock":
			off := dataStrings(d, "pab_disabled")
			if len(off) == 0 {
				return exposure{}
			}
			for i := range off {
				off[i] += "=false"
			}
			x.sev, x.what = High, strings.Join(off, ",")
		default: // Delete*PublicAccessBlock
			x.sev, x.what = High, "deleted"
		}
	case api.Source == srcRDS:
		if v, _ := dataBool(d, "publicly_accessible"); !v {
			return exposure{}
		}
		x.target = dataStr(d, "db_instance")
		if x.target == "" {
			x.target = dataStr(d, "db_cluster")
		}
		x.sev, x.what = High, "publicly_accessible"
	case api.Source == srcLambda:
		if dataStr(d, "lambda_principal") != "*" {
			return exposure{}
		}
		x.target = dataStr(d, "function")
		switch {
		case dataStr(d, "function_url_auth_type") == "NONE":
			x.what = "principal=* auth=NONE"
		case len(dataStrings(d, "lambda_conditions")) == 0:
			x.what = "principal=* no_condition"
		default:
			return exposure{}
		}
		x.sev = Medium
	default:
		return exposure{}
	}
	return x
}

// sgOpening は公開した ingress 1 件を "tcp/22 0.0.0.0/0" の形にし、機微なポートに当たるかを返す。全ポート (protocol -1) は常に機微。
func sgOpening(r map[string]any, sensitive map[int]bool) (string, bool) {
	proto := protoName(fmt.Sprint(r["protocol"]))
	cidr, _ := r["cidr"].(string)
	if proto == "all" {
		return "all " + cidr, true
	}
	if proto != "tcp" && proto != "udp" {
		return proto + " " + cidr, false
	}
	from, ok1 := dataInt(r, "from_port")
	to, ok2 := dataInt(r, "to_port")
	if !ok1 || !ok2 || from < 0 || to < 0 {
		return proto + "/all " + cidr, true
	}
	if to < from {
		from, to = to, from
	}
	ports := fmt.Sprintf("%s/%d", proto, from)
	if to != from {
		ports = fmt.Sprintf("%s/%d-%d", proto, from, to)
	}
	hit := from == 0 && to == 65535
	for p := range sensitive {
		if p >= from && p <= to {
			hit = true
		}
	}
	return ports + " " + cidr, hit
}

func protoName(p string) string {
	switch strings.ToLower(p) {
	case "-1", "all":
		return "all"
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "58", "icmpv6":
		return "icmpv6"
	}
	return strings.ToLower(p)
}

func describeExposure(d map[string]any) string {
	what, _ := d["exposure"].(string)
	switch what {
	case "public_policy":
		return "誰でも読めるバケットポリシーに"
	case "deleted":
		return "Public Access Block の削除で公開を許す状態に"
	case "publicly_accessible":
		return "インターネットから到達できる設定 (PubliclyAccessible) に"
	case "all":
		return "全員に共有 (公開)"
	}
	if d["sensitive"] == true {
		return what + " で開けた (機微なポート)"
	}
	return what + " で開けた"
}

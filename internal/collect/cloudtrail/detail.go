package cloudtrail

import (
	"encoding/json"
	"sort"
	"strings"
)

// 決定 (ADR 0026): defense_evasion / public_exposure の判定に要る値だけを requestParameters から Data に取り出す。
// ポリシー全文・フィルタの条件などの大きな値は残さない (events は 90 日残り、report の根拠にもなるため)。
// 取り出すのは該当する操作だけ。形が想定と違えば取り出さない (判定は「分からない」側に倒れ、報告しないか重大度を上げない)。

const (
	maxDetailItems = 20 // 一覧の値 (公開した ingress・ステートメントなど) の上限
	maxActions     = 5  // ステートメント 1 つあたりに残す action の数
)

func extractDetail(source, name string, rp map[string]any, d map[string]any) {
	if rp == nil {
		return
	}
	switch source {
	case "cloudtrail.amazonaws.com":
		cloudTrailDetail(name, rp, d)
	case "guardduty.amazonaws.com":
		putStr(d, "detector_id", rp["detectorId"])
		if v, ok := rp["enable"].(bool); ok {
			d["enable"] = v
		}
		var off []string
		for _, f := range objects(rp["features"]) {
			if s, _ := f["status"].(string); s == "DISABLED" {
				if n, _ := f["name"].(string); n != "" {
					off = append(off, n)
				}
			}
		}
		putList(d, "features_disabled", off)
		if name == "CreateFilter" || name == "UpdateFilter" {
			putStr(d, "filter_action", rp["action"])
		}
	case "access-analyzer.amazonaws.com":
		putStr(d, "analyzer", rp["analyzerName"])
		putStr(d, "rule", rp["ruleName"])
	case "logs.amazonaws.com":
		putStr(d, "log_group", rp["logGroupName"])
		putStr(d, "filter_name", rp["filterName"])
		if n, ok := num(rp["retentionInDays"]); ok {
			d["retention_days"] = n
		}
	case "ec2.amazonaws.com":
		ec2Detail(name, rp, d)
	case "config.amazonaws.com":
		putStr(d, "recorder", rp["configurationRecorderName"])
		putStr(d, "delivery_channel", rp["deliveryChannelName"])
	case "securityhub.amazonaws.com":
		putList(d, "standards", strs(rp["StandardsSubscriptionArns"]))
	case "wafv2.amazonaws.com":
		putStr(d, "resource_arn", rp["ResourceArn"])
		if lc, ok := rp["LoggingConfiguration"].(map[string]any); ok {
			putStr(d, "resource_arn", lc["ResourceArn"])
			if f, ok := lc["LoggingFilter"]; ok && f != nil {
				d["logging_filter"] = true
			}
		}
	case "s3.amazonaws.com":
		s3Detail(name, rp, d)
	case "rds.amazonaws.com":
		putStr(d, "db_cluster", rp["dBClusterIdentifier"])
		putStr(d, "db_snapshot", rp["dBSnapshotIdentifier"])
		putStr(d, "db_cluster_snapshot", rp["dBClusterSnapshotIdentifier"])
		if v, ok := rp["publiclyAccessible"].(bool); ok {
			d["publicly_accessible"] = v
		}
		if a, _ := rp["attributeName"].(string); a == "restore" && contains(strs(rp["valuesToAdd"]), "all") {
			d["shared_public"] = true
		}
	case "lambda.amazonaws.com":
		if !strings.HasPrefix(name, "AddPermission") {
			return
		}
		putStr(d, "function", rp["functionName"])
		putStr(d, "lambda_principal", rp["principal"])
		putStr(d, "function_url_auth_type", rp["functionUrlAuthType"])
		var conds []string
		for _, k := range []string{"principalOrgID", "sourceAccount", "sourceArn"} {
			if s, _ := rp[k].(string); s != "" {
				conds = append(conds, k)
			}
		}
		sort.Strings(conds)
		putList(d, "lambda_conditions", conds)
	}
}

func cloudTrailDetail(name string, rp map[string]any, d map[string]any) {
	putStr(d, "trail", rp["trailName"])
	switch name {
	case "CreateTrail", "UpdateTrail":
		if v, ok := rp["isMultiRegionTrail"].(bool); ok {
			d["multi_region"] = v
		}
		if v, ok := rp["enableLogFileValidation"].(bool); ok {
			d["log_validation"] = v
		}
		putStr(d, "s3_bucket", rp["s3BucketName"])
	case "PutEventSelectors":
		putList(d, "selectors_reduced", reducedSelectors(rp))
	case "PutInsightSelectors":
		if v, ok := rp["insightSelectors"].([]any); ok && len(v) == 0 {
			d["insights_cleared"] = true
		}
	}
}

// reducedSelectors は PutEventSelectors が管理イベントの記録を減らす点を返す (前の設定は分からないので、要求の内容だけで判断する)。
// データイベントの追加だけなら空。
func reducedSelectors(rp map[string]any) []string {
	var out []string
	if adv, ok := rp["advancedEventSelectors"].([]any); ok {
		mgmt := false
		for _, s := range adv {
			fs := objects(objectOf(s)["fieldSelectors"])
			isMgmt := false
			for _, f := range fs {
				if f["field"] == "eventCategory" && contains(strs(f["equals"]), "Management") {
					isMgmt = true
				}
			}
			if !isMgmt {
				continue
			}
			mgmt = true
			for _, f := range fs {
				if field, _ := f["field"].(string); field != "eventCategory" {
					out = append(out, "management_filtered="+field)
				}
			}
		}
		if !mgmt {
			out = append(out, "no_management_selector")
		}
		return dedupStrings(out)
	}
	sels := objects(rp["eventSelectors"])
	if len(sels) == 0 {
		return nil
	}
	var mgmt []map[string]any
	for _, s := range sels {
		if v, ok := s["includeManagementEvents"].(bool); ok && !v {
			continue
		}
		mgmt = append(mgmt, s)
	}
	if len(mgmt) == 0 {
		return []string{"include_management_events=false"}
	}
	for _, s := range mgmt {
		if rw, _ := s["readWriteType"].(string); rw != "" && rw != "All" {
			out = append(out, "read_write_type="+rw)
		}
		if ex := strs(s["excludeManagementEventSources"]); len(ex) > 0 {
			out = append(out, "exclude_management_event_sources="+strings.Join(ex, ","))
		}
	}
	return dedupStrings(out)
}

func ec2Detail(name string, rp map[string]any, d map[string]any) {
	switch name {
	case "AuthorizeSecurityGroupIngress":
		var rules []any
		for _, p := range items(rp["ipPermissions"]) {
			proto := protoOf(p["ipProtocol"])
			from, to := portOf(p["fromPort"]), portOf(p["toPort"])
			var cidrs []string
			for _, r := range items(p["ipRanges"]) {
				if s, _ := r["cidrIp"].(string); s != "" {
					cidrs = append(cidrs, s)
				}
			}
			for _, r := range items(p["ipv6Ranges"]) {
				if s, _ := r["cidrIpv6"].(string); s != "" {
					cidrs = append(cidrs, s)
				}
			}
			for _, c := range cidrs {
				if publicCIDR(c) && len(rules) < maxDetailItems {
					rules = append(rules, map[string]any{"protocol": proto, "from_port": from, "to_port": to, "cidr": c})
				}
			}
		}
		if len(rules) > 0 {
			d["public_ingress"] = rules
		}
	case "ModifySecurityGroupRules":
		req, _ := rp["ModifySecurityGroupRulesRequest"].(map[string]any)
		if req == nil {
			return
		}
		putStr(d, "group_id", req["GroupId"])
		var rules []any
		for _, r := range objects(req["SecurityGroupRule"]) {
			spec := objectOf(r["SecurityGroupRule"])
			for _, k := range []string{"CidrIpv4", "CidrIpv6"} {
				if c, _ := spec[k].(string); publicCIDR(c) && len(rules) < maxDetailItems {
					m := map[string]any{"protocol": protoOf(spec["IpProtocol"]), "from_port": portOf(spec["FromPort"]), "to_port": portOf(spec["ToPort"]), "cidr": c}
					putStr(m, "rule_id", r["SecurityGroupRuleId"])
					rules = append(rules, m)
				}
			}
		}
		if len(rules) > 0 {
			d["public_ingress"] = rules
		}
	case "ModifySnapshotAttribute":
		putStr(d, "snapshot_id", rp["snapshotId"])
		if addsAll(rp["createVolumePermission"]) {
			d["shared_public"] = true
		}
	case "ModifyImageAttribute":
		putStr(d, "image_id", rp["imageId"])
		if addsAll(rp["launchPermission"]) {
			d["shared_public"] = true
		}
	case "DeleteFlowLogs":
		req, _ := rp["DeleteFlowLogsRequest"].(map[string]any)
		var ids []string
		for _, f := range objects(req["FlowLogId"]) {
			if s, _ := f["content"].(string); s != "" {
				ids = append(ids, s)
			}
		}
		if s, ok := req["FlowLogId"].(string); ok && s != "" {
			ids = append(ids, s)
		}
		putList(d, "flow_log_ids", ids)
	}
}

// addsAll は {add: {items: [{group: all}]}} (全員への共有の追加) か。
func addsAll(v any) bool {
	for _, it := range items(objectOf(v)["add"]) {
		if g, _ := it["group"].(string); g == "all" {
			return true
		}
	}
	return false
}

func s3Detail(name string, rp map[string]any, d map[string]any) {
	putStr(d, "bucket", rp["bucketName"])
	switch name {
	case "PutBucketPolicy":
		public, sts := publicStatements(rp["bucketPolicy"])
		d["policy_public"] = public
		putList(d, "public_statements", sts)
	case "PutBucketAcl":
		putList(d, "acl_public_grants", publicGrants(rp))
	case "PutPublicAccessBlock", "PutAccountPublicAccessBlock":
		cfg, ok := rp["PublicAccessBlockConfiguration"].(map[string]any)
		if !ok {
			return
		}
		var off []string
		for _, k := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
			if v, _ := cfg[k].(bool); !v { // 省略は false (API の既定)
				off = append(off, k)
			}
		}
		putList(d, "pab_disabled", off)
	case "PutBucketLifecycle":
		lc := objectOf(rp["LifecycleConfiguration"])
		min := -1
		for _, r := range objects(lc["Rule"]) {
			if n, ok := num(objectOf(r["Expiration"])["Days"]); ok && (min < 0 || n < min) {
				min = n
			}
		}
		if min >= 0 {
			d["lifecycle_expiration_days"] = min
		}
	}
}

// restrictingConditionKeys は、Principal が "*" でも送信元・組織・アカウントで絞る条件キー (小文字)。
// aws:SecureTransport のように通信路だけを縛る条件は公開を止めないので含めない。
var restrictingConditionKeys = map[string]bool{
	"aws:sourcevpce": true, "aws:sourcevpc": true, "aws:sourceip": true, "aws:principalorgid": true, "aws:principalorgpaths": true,
	"aws:principalaccount": true, "aws:principalarn": true, "aws:sourceaccount": true, "aws:sourcearn": true, "aws:sourceorgid": true, "aws:sourceorgpaths": true,
}

// publicStatements はバケットポリシーのうち、誰でも (Principal "*" / AWS "*") に条件なしで Allow するステートメントを "Sid: action,..." で返す。
func publicStatements(v any) (bool, []string) {
	pol := objectOf(v)
	if s, ok := v.(string); ok {
		_ = json.Unmarshal([]byte(s), &pol)
	}
	var out []string
	for i, st := range objects(pol["Statement"]) {
		if e, _ := st["Effect"].(string); e != "Allow" || !publicPrincipal(st["Principal"]) || restricted(st["Condition"]) {
			continue
		}
		sid, _ := st["Sid"].(string)
		if sid == "" {
			sid = "#" + itoa(i)
		}
		acts := strs(st["Action"])
		if len(acts) > maxActions {
			acts = append(acts[:maxActions], "...")
		}
		if len(out) < maxDetailItems {
			out = append(out, sid+": "+strings.Join(acts, ","))
		}
	}
	return len(out) > 0, out
}

func publicPrincipal(p any) bool {
	if s, ok := p.(string); ok {
		return s == "*"
	}
	return contains(strs(objectOf(p)["AWS"]), "*")
}

func restricted(c any) bool {
	for _, kv := range objectOf(c) {
		for k := range objectOf(kv) {
			if restrictingConditionKeys[strings.ToLower(k)] {
				return true
			}
		}
	}
	return false
}

var publicGroups = []string{"AllUsers", "AuthenticatedUsers"}

// publicGrants は ACL のうち AllUsers / AuthenticatedUsers への付与を "AllUsers:READ"、公開の既定 ACL を "canned:public-read" で返す。
func publicGrants(rp map[string]any) []string {
	var out []string
	acl := objectOf(objectOf(rp["AccessControlPolicy"])["AccessControlList"])
	for _, g := range objects(acl["Grant"]) {
		uri, _ := objectOf(g["Grantee"])["URI"].(string)
		perm, _ := g["Permission"].(string)
		for _, grp := range publicGroups {
			if strings.HasSuffix(uri, "/"+grp) {
				out = append(out, grp+":"+perm)
			}
		}
	}
	for _, c := range strs(rp["x-amz-acl"]) {
		if c == "public-read" || c == "public-read-write" || c == "authenticated-read" {
			out = append(out, "canned:"+c)
		}
	}
	for _, h := range []string{"read", "write", "read-acp", "write-acp", "full-control"} {
		for _, v := range strs(rp["x-amz-grant-"+h]) {
			for _, grp := range publicGroups {
				if strings.Contains(v, "/"+grp) {
					out = append(out, grp+":"+strings.ToUpper(strings.ReplaceAll(h, "-", "_")))
				}
			}
		}
	}
	return dedupStrings(out)
}

func publicCIDR(c string) bool { return c == "0.0.0.0/0" || c == "::/0" }

func protoOf(v any) string {
	switch p := v.(type) {
	case string:
		return p
	case float64:
		return itoa(int(p))
	}
	return ""
}

func portOf(v any) int {
	if n, ok := num(v); ok {
		return n
	}
	return -1
}

// --- JSON の値の扱い (CloudTrail は 1 件のとき配列ではなくオブジェクトにすることがある) ---

func objectOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// objects は配列か単独のオブジェクトをオブジェクトの列にする。
func objects(v any) []map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// items は EC2 の {items: [...]} の中身。
func items(v any) []map[string]any { return objects(objectOf(v)["items"]) }

// strs は文字列か文字列の配列を列にする。
func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func num(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

func putStr(d map[string]any, k string, v any) {
	if s, ok := v.(string); ok && s != "" {
		d[k] = s
	}
}

func putList(d map[string]any, k string, l []string) {
	if len(l) > 0 {
		if len(l) > maxDetailItems {
			l = l[:maxDetailItems]
		}
		d[k] = l
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func dedupStrings(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

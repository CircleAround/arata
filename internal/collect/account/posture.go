package account

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// 姿勢の項目 (posture_item の Key)。GuardDuty はリージョンごとに `guardduty|<region>`、ALB の WAF もリージョンごとに `alb_waf|<region>`。
const (
	PostureCloudTrail     = "cloudtrail"
	PostureGuardDuty      = "guardduty"
	PostureRootMFA        = "root_mfa"
	PostureS3PublicAccess = "s3_public_access_block"
	PosturePasswordPolicy = "password_policy"
	PostureALBWAF         = "alb_waf"
)

// Posture はアカウントの姿勢 (事実) を項目ごとに 1 つ出す collector (posture_item)。良し悪しの判定は posture チェックが行う。
//
// 決定 (ADR 0015): 項目ごとに別の API・別の権限なので、一部が拒否されても他の項目は取る。取れなかった項目は
// Data に `unknown: true` と action を入れて出し (チェックは前回の finding を維持する)、Problems() で返す (coverage と標準エラー)。
type Posture struct {
	base
	problems []*collect.Error
	// albChecked は直近の Collect で WebACL を確かめたインターネット向けの ALB の数 (Probe が「未確認」を出すのに使う)。
	albChecked int
}

var (
	_ collect.Collector       = (*Posture)(nil)
	_ collect.PartialReporter = (*Posture)(nil)
)

// NewPosture は collector を作る。IAM・S3 (アカウント単位)・CloudTrail は先頭のリージョンで引き、GuardDuty はリージョンごとに見る。
func NewPosture(id string, clients ...Clients) *Posture {
	return &Posture{base: newBase(id, clients)}
}

func (c *Posture) Yields() []record.Kind { return []record.Kind{record.KindPostureItem} }

func (c *Posture) Problems() []*collect.Error { return c.problems }

func (c *Posture) Collect(ctx context.Context, w collect.Window, sink collect.RecordSink) error {
	c.problems = nil
	c.albChecked = 0
	at := snapshotTime(w)
	home := c.clients[0]
	emit := func(key string, data map[string]any, action string, err error) error {
		if err != nil {
			ce := c.fail(action, err)
			if ce.Action == "" {
				ce.Action = action
			}
			c.problems = append(c.problems, ce)
			data = map[string]any{"unknown": true, "action": action, "code": ce.Code}
		}
		return sink.Emit(ctx, item(record.KindPostureItem, at, c.id, key, data))
	}
	d, action, err := c.cloudTrail(ctx, home)
	if err := emit(PostureCloudTrail, d, action, err); err != nil {
		return err
	}
	for _, cl := range c.clients {
		key := PostureGuardDuty + "|" + cl.Region
		ids, aerr := enabledDetectors(ctx, cl.GuardDuty)
		if aerr != nil {
			err = emit(key, nil, aerr.action, aerr.err)
		} else {
			err = emit(key, map[string]any{"enabled": len(ids) > 0, "region": cl.Region}, "", nil)
		}
		if err != nil {
			return err
		}
	}
	sum, err := home.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	d = nil
	if err == nil {
		d = map[string]any{"mfa_enabled": sum.SummaryMap["AccountMFAEnabled"] == 1, "root_access_keys": sum.SummaryMap["AccountAccessKeysPresent"] > 0}
	}
	if err := emit(PostureRootMFA, d, ActionGetAccountSummary, err); err != nil {
		return err
	}
	d, action, err = c.publicAccessBlock(ctx, home)
	if err := emit(PostureS3PublicAccess, d, action, err); err != nil {
		return err
	}
	d, err = passwordPolicy(ctx, home.IAM)
	if err := emit(PosturePasswordPolicy, d, ActionGetPasswordPolicy, err); err != nil {
		return err
	}
	for _, cl := range c.clients {
		d, action, err = c.albWAF(ctx, cl)
		if err := emit(PostureALBWAF+"|"+cl.Region, d, action, err); err != nil {
			return err
		}
	}
	return nil
}

// albWAF はリージョンのインターネット向けの Application Load Balancer と、WAFv2 の WebACL が付いていないものを返す (ADR 0048)。
//
// 決定:
//   - internal の ALB と、ALB 以外 (NLB・GWLB。WAF を付けられない) は見ない
//   - 一覧 (DescribeLoadBalancers) か WebACL の確認 (GetWebACLForResource) が 1 つでも失敗したら、そのリージョンは取れなかったことにする
//     (一部の ALB だけで「付いている」と言わない)。一覧の後に消えた ALB (WAFNonexistentItemException) だけは数えずに続ける
//   - 持つのは名前と ARN だけ (DNS 名・サブネット・セキュリティグループ・WebACL の中身は持たない)
func (c *Posture) albWAF(ctx context.Context, cl Clients) (map[string]any, string, error) {
	without := []any{}
	facing := 0
	var marker *string
	for {
		out, err := cl.ELBV2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, ActionDescribeLoadBalancers, err
		}
		for _, lb := range out.LoadBalancers {
			if lb.Type != elbtypes.LoadBalancerTypeEnumApplication || lb.Scheme != elbtypes.LoadBalancerSchemeEnumInternetFacing {
				continue
			}
			acl, err := cl.WAFV2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: lb.LoadBalancerArn})
			if collect.APICode(err) == "WAFNonexistentItemException" {
				continue
			}
			if err != nil {
				return nil, ActionGetWebACLForResource, err
			}
			c.albChecked++
			facing++
			if acl.WebACL == nil {
				without = append(without, map[string]any{"name": aws.ToString(lb.LoadBalancerName), "arn": aws.ToString(lb.LoadBalancerArn)})
			}
		}
		if marker = out.NextMarker; aws.ToString(marker) == "" {
			break
		}
	}
	return map[string]any{"region": cl.Region, "internet_facing": facing, "without_waf": without}, "", nil
}

func (c *Posture) cloudTrail(ctx context.Context, cl Clients) (map[string]any, string, error) {
	out, err := cl.CloudTrail.DescribeTrails(ctx, &ct.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		return nil, ActionDescribeTrails, err
	}
	var logging, unvalidated []string
	multi := false
	for _, t := range out.TrailList {
		st, err := cl.CloudTrail.GetTrailStatus(ctx, &ct.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			return nil, ActionGetTrailStatus, err
		}
		if !aws.ToBool(st.IsLogging) {
			continue
		}
		name := aws.ToString(t.Name)
		logging = append(logging, name)
		multi = multi || aws.ToBool(t.IsMultiRegionTrail)
		if !aws.ToBool(t.LogFileValidationEnabled) {
			unvalidated = append(unvalidated, name)
		}
	}
	return map[string]any{"trails": len(out.TrailList), "logging": nonNil(logging), "multi_region_logging": multi, "without_validation": nonNil(unvalidated)}, "", nil
}

func (c *Posture) publicAccessBlock(ctx context.Context, cl Clients) (map[string]any, string, error) {
	id, err := cl.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, "sts:GetCallerIdentity", err
	}
	out, err := cl.S3Control.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: id.Account})
	if collect.APICode(err) == "NoSuchPublicAccessBlockConfiguration" {
		return map[string]any{"configured": false}, "", nil
	}
	if err != nil {
		return nil, ActionGetPublicAccessBlock, err
	}
	p := out.PublicAccessBlockConfiguration
	if p == nil {
		return map[string]any{"configured": false}, "", nil
	}
	return map[string]any{"configured": true, "block_public_acls": aws.ToBool(p.BlockPublicAcls), "ignore_public_acls": aws.ToBool(p.IgnorePublicAcls),
		"block_public_policy": aws.ToBool(p.BlockPublicPolicy), "restrict_public_buckets": aws.ToBool(p.RestrictPublicBuckets)}, "", nil
}

func passwordPolicy(ctx context.Context, api IAMAPI) (map[string]any, error) {
	out, err := api.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if collect.APICode(err) == "NoSuchEntity" {
		return map[string]any{"configured": false}, nil
	}
	if err != nil {
		return nil, err
	}
	if out.PasswordPolicy == nil {
		return map[string]any{"configured": false}, nil
	}
	p := out.PasswordPolicy
	return map[string]any{"configured": true, "minimum_length": int(aws.ToInt32(p.MinimumPasswordLength)), "require_symbols": p.RequireSymbols,
		"require_numbers": p.RequireNumbers, "require_uppercase": p.RequireUppercaseCharacters, "require_lowercase": p.RequireLowercaseCharacters}, nil
}

// Probe は各項目の読み取り API を 1 回ずつ試す (Collect と同じ。書き込みは無い)。
func (c *Posture) Probe(ctx context.Context) []collect.ProbeResult {
	var sink nopSink
	_ = c.Collect(ctx, collect.Window{}, sink)
	denied := map[string]error{}
	for _, p := range c.problems {
		denied[p.Action] = p
	}
	// 前段が拒否されると後段は呼ばれないので「未確認」とする
	after := map[string]string{ActionGetTrailStatus: ActionDescribeTrails, ActionGetDetector: ActionListDetectors, ActionGetWebACLForResource: ActionDescribeLoadBalancers}
	var out []collect.ProbeResult
	for _, a := range RequiredActions[KindPosture] {
		r := collect.ProbeResult{Action: a, Err: denied[a]}
		if pre := after[a]; pre != "" && denied[pre] != nil && r.Err == nil {
			r.Detail = pre + " が拒否されたため未確認"
		} else if a == ActionGetWebACLForResource && r.Err == nil && c.albChecked == 0 {
			r.Detail = "インターネット向けの ALB が無いため未確認"
		}
		out = append(out, r)
	}
	for _, a := range RequiredActions[KindPosture] {
		delete(denied, a)
	}
	for a, err := range denied {
		out = append(out, collect.ProbeResult{Action: a, Err: err})
	}
	return out
}

type nopSink struct{}

func (nopSink) Emit(context.Context, record.Record) error { return nil }

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// IsUnknown は posture_item が取れなかった項目か。
func IsUnknown(it record.SnapshotItem) bool { return it.Bool("unknown") }

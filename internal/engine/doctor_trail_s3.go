package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cloudtrail"
	"github.com/CircleAround/arata/internal/config"
)

// cloudtrail-s3 の doctor (ADR 0063)。
//
// 決定:
//   - 権限: リージョンごとに ListObjectsV2 を 1 回 (キー 1 つ)、直近のファイルを 1 つ GetObject して読む。拒否は ng で、GetObject の拒否には
//     「バケットポリシー・キーポリシー (SSE-KMS) の可能性」を添える (ロールのポリシーだけでは読めない構成がある)
//   - trail の設定: DescribeTrails で配信先が同じバケット・接頭辞の trail を探し、GetEventSelectors で「管理イベントの読み取りと書き込みを全部、
//     種類を除かずに記録している」かを見る。足りなければ warn (今のチェックの材料が欠ける)。見つからない・読めない (組織の trail を
//     メンバーのアカウントから見ているなど) ときも warn (確かめられない)
//   - マルチリージョンでない trail が regions を覆わないときも warn

// CloudTrailS3Actions は cloudtrail-s3 のソースに要る action (doctor の required_actions)。
var CloudTrailS3Actions = []string{cloudtrail.ActionS3ListBucket, cloudtrail.ActionS3GetObject, "cloudtrail:DescribeTrails", cloudtrail.ActionGetEventSelectors}

func (d *doctor) trailS3(ctx context.Context, src config.Source) {
	api, err := d.deps.CloudTrailS3(ctx, d.cfg, src)
	if err != nil {
		d.addErr(src, "permission", err)
		return
	}
	loc := cloudtrail.TrailLocation{Bucket: src.Bucket, Prefix: src.Prefix, OrganizationID: src.OrganizationID, AccountID: src.AccountID, Regions: src.Regions}
	for _, region := range src.Regions {
		d.trailS3Region(ctx, src, api, loc, region)
	}
	d.trailSettings(ctx, src)
}

func (d *doctor) trailS3Region(ctx context.Context, src config.Source, api cloudtrail.S3API, loc cloudtrail.TrailLocation, region string) {
	// 今日 (UTC) の配信を見る。日の変わり目の直後で今日の分がまだ無ければ前日を見る
	var latest string
	for _, day := range []int{0, -1} {
		prefix := loc.RegionPrefix(region) + d.now.UTC().AddDate(0, 0, day).Format("2006/01/02") + "/"
		in := &s3.ListObjectsV2Input{Bucket: aws.String(src.Bucket), Prefix: aws.String(prefix)}
		for {
			out, err := api.ListObjectsV2(ctx, in)
			if err != nil {
				ce := collect.Classify(src.ID, cloudtrail.ActionS3ListBucket, err)
				ce.Err = fmt.Errorf("%s (%s): %w", cloudtrail.ActionS3ListBucket, region, ce.Err)
				d.addErr(src, "permission", ce)
				return
			}
			for _, o := range out.Contents {
				latest = aws.ToString(o.Key) // 辞書順 = 配信時刻の順
			}
			if !aws.ToBool(out.IsTruncated) || out.NextContinuationToken == nil {
				break
			}
			in.ContinuationToken = out.NextContinuationToken
		}
		if latest != "" {
			break
		}
	}
	if latest == "" {
		d.add(src, "permission", DoctorWarn, "", fmt.Sprintf("%s (%s): s3://%s/%s の下に直近 2 日のファイルが無い (bucket・prefix・organization_id・account_id と、trail がこのリージョンを記録しているかを確認)",
			cloudtrail.ActionS3ListBucket, region, src.Bucket, loc.RegionPrefix(region)))
		return
	}
	d.add(src, "permission", DoctorOK, "", cloudtrail.ActionS3ListBucket+" ("+region+")")
	out, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(src.Bucket), Key: aws.String(latest)})
	if err != nil {
		ce := collect.Classify(src.ID, cloudtrail.ActionS3GetObject, err)
		ce.Err = fmt.Errorf("%s (%s): %w", cloudtrail.ActionS3GetObject, region, ce.Err)
		if ce.Code == collect.CodeAccessDenied {
			ce.Err = fmt.Errorf("%w (ロールのポリシーに加えて、バケットポリシーと、SSE-KMS ならキーポリシーの kms:Decrypt も確認。ADR 0063)", ce.Err)
		}
		d.addErr(src, "permission", ce)
		return
	}
	defer out.Body.Close()
	recs, _, err := cloudtrail.ReadTrailFile(out.Body, cloudtrail.MaxTrailFileBytes)
	if err != nil {
		d.add(src, "permission", DoctorWarn, "", fmt.Sprintf("%s (%s): 直近のファイルを読めない: %v", cloudtrail.ActionS3GetObject, region, err))
		return
	}
	d.add(src, "permission", DoctorOK, "", fmt.Sprintf("%s (%s。直近のファイルの記録 %d 件)", cloudtrail.ActionS3GetObject, region, len(recs)))
}

// trailSettings は配信先が同じ trail を探し、記録の範囲を確かめる。
func (d *doctor) trailSettings(ctx context.Context, src config.Source) {
	api, err := d.deps.TrailInfo(ctx, d.cfg, d.cfg.AWS.Region)
	if err != nil {
		d.add(src, "trail", DoctorWarn, "", "trail の設定を確かめられない: "+err.Error())
		return
	}
	out, err := api.DescribeTrails(ctx, &ct.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
	if err != nil {
		d.add(src, "trail", DoctorWarn, "", "trail の設定を確かめられない (cloudtrail:DescribeTrails): "+err.Error())
		return
	}
	var trail *cttypes.Trail
	for i, t := range out.TrailList {
		if aws.ToString(t.S3BucketName) == src.Bucket && strings.Trim(aws.ToString(t.S3KeyPrefix), "/") == strings.Trim(src.Prefix, "/") {
			trail = &out.TrailList[i]
			break
		}
	}
	if trail == nil {
		d.add(src, "trail", DoctorWarn, "", fmt.Sprintf("配信先が s3://%s/%s の trail がこのアカウントに見当たらない (組織の trail を別のアカウントで管理しているなら、その設定を管理側で確認)",
			src.Bucket, strings.Trim(src.Prefix, "/")))
		return
	}
	name := aws.ToString(trail.TrailARN)
	if !aws.ToBool(trail.IsMultiRegionTrail) {
		var outside []string
		for _, r := range src.Regions {
			if r != aws.ToString(trail.HomeRegion) {
				outside = append(outside, r)
			}
		}
		if len(outside) > 0 {
			d.add(src, "trail", DoctorWarn, "", fmt.Sprintf("%s はマルチリージョンの trail でなく、%s を記録しない (regions を trail のリージョンだけにするか、trail をマルチリージョンにする)",
				name, strings.Join(outside, ", ")))
		}
	}
	sel, err := api.GetEventSelectors(ctx, &ct.GetEventSelectorsInput{TrailName: trail.TrailARN})
	if err != nil {
		d.add(src, "trail", DoctorWarn, "", fmt.Sprintf("%s の記録の範囲を確かめられない (%s): %v", name, cloudtrail.ActionGetEventSelectors, err))
		return
	}
	if problems := TrailSelectorProblems(sel); len(problems) > 0 {
		d.add(src, "trail", DoctorWarn, "", name+": "+strings.Join(problems, "。"))
		return
	}
	d.add(src, "trail", DoctorOK, "", name+": 管理イベントの読み取りと書き込みを全部記録している")
}

// TrailSelectorProblems は trail のイベントセレクタが、今のチェックが要る管理イベント (読み取り・書き込みの全部、種類を除かない) を記録していなければ、その理由を返す。
// 基本のセレクタと高度なセレクタのどちらにも対応する (trail はどちらか一方を持つ)。
func TrailSelectorProblems(out *ct.GetEventSelectorsOutput) []string {
	var read, write bool
	excluded := map[string]bool{}
	for _, s := range out.EventSelectors {
		if s.IncludeManagementEvents != nil && !*s.IncludeManagementEvents {
			continue
		}
		switch s.ReadWriteType {
		case cttypes.ReadWriteTypeReadOnly:
			read = true
		case cttypes.ReadWriteTypeWriteOnly:
			write = true
		default: // All (と、値の無い既定)
			read, write = true, true
		}
		for _, src := range s.ExcludeManagementEventSources {
			excluded[src] = true
		}
	}
	for _, s := range out.AdvancedEventSelectors {
		mgmt, ro := false, ""
		var notSources []string
		for _, f := range s.FieldSelectors {
			switch aws.ToString(f.Field) {
			case "eventCategory":
				mgmt = slices.Contains(f.Equals, "Management")
			case "readOnly":
				if len(f.Equals) == 1 {
					ro = f.Equals[0]
				}
			case "eventSource":
				notSources = append(notSources, f.NotEquals...)
			}
		}
		if !mgmt {
			continue
		}
		read = read || ro == "" || ro == "true"
		write = write || ro == "" || ro == "false"
		for _, src := range notSources {
			excluded[src] = true
		}
	}
	var out2 []string
	if !read && !write {
		return []string{"管理イベントを記録していない (cloudtrail-s3 では何も読めない。cloudtrail-lookup を使うか、trail で管理イベントを記録する)"}
	}
	if !read {
		out2 = append(out2, "読み取りの管理イベントを記録していない (secret_access・new_principal・principal_new_source の材料が欠ける)")
	}
	if !write {
		out2 = append(out2, "書き込みの管理イベントを記録していない (iam_changes・defense_evasion など多くのチェックの材料が欠ける)")
	}
	if len(excluded) > 0 {
		var l []string
		for src := range excluded {
			l = append(l, src)
		}
		slices.Sort(l)
		out2 = append(out2, "管理イベントから "+strings.Join(l, ", ")+" を除いている (KMS を除くと defense_evasion のキーの削除・無効化が欠ける)")
	}
	return out2
}

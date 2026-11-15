package engine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CircleAround/arata/internal/config"
)

// 読み取り専用ロール (deploy/iam/readonly-role.yaml) の AllowedLogGroupNames の上限 (ADR 0062)。
const (
	// CloudFormation のパラメータの値の上限 (「Parameter value | The maximum size of a parameter value. | 4,096 bytes」
	// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html)
	roleParamValueMax = 4096
	// ロールのインラインポリシーの合計の上限 (「Role policy size can't exceed 10,240 characters.」空白は数えない。
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
	rolePolicyMax = 10240
	// rolePolicyBase は、AllowedLogGroupNames が無い (全部 `*`) ときのポリシーの大きさ (空白を除いた JSON の文字数) の上限の見積もり。
	// rolePolicyPerName は名前 1 つあたりに足される文字数 (名前の長さの 2 倍を除く)。readonly_role_test.go が実際のテンプレートと突き合わせる
	rolePolicyBase    = 1600
	rolePolicyPerName = 60
	// rolePolicyTrail は CloudTrailBucketName を渡したときに足される文 (ListBucket・GetObject) の文字数 (バケットの名前の 2 倍と接頭辞の 2 倍を除く。ADR 0063)
	rolePolicyTrail = 260
)

// roleLogGroupName は readonly-role.yaml の AllowedLogGroupNames / DeniedLogGroupNames の 1 要素の規則 (AllowedPattern と同じ文字)。
// readonly_role_test.go がテンプレートの AllowedPattern と同じであることを確かめる。
// RoleNoLogGroups は、どのロググループの中身も読ませない AllowedLogGroupNames の予約語 (値の全体がこの 1 語のときだけ。ADR 0062)。
const RoleNoLogGroups = "none"

var roleLogGroupName = regexp.MustCompile(`^[A-Za-z0-9_./#-]+$`)

// RoleParams は、設定から作った読み取り専用ロールのパラメータ。
type RoleParams struct {
	// AllowedLogGroupNames はロールの AllowedLogGroupNames に渡す値 (LogGroups をカンマでつないだもの)。
	AllowedLogGroupNames string
	// LogGroups は cloudwatch-logs のソースの log_group (重複を除き、設定の順)。
	LogGroups []string
	// CloudTrailBucketName / CloudTrailBucketPrefix は cloudtrail-s3 のソースの bucket と prefix (前後の / を外したもの)。ソースが無ければ空 (ADR 0063)。
	// CloudTrailKmsKeyArn は設定から分からない (arata は trail の暗号化の鍵を設定に持たない) ので出さない。
	CloudTrailBucketName   string
	CloudTrailBucketPrefix string
	// Warnings は、出した値で困るおそれ (人向けの文)。
	Warnings []string
}

// BuildRoleParams は設定から読み取り専用ロールのパラメータを作る (ADR 0062)。AWS には繋がない。
//
// 決定:
//   - 一覧は cloudwatch-logs のソースの log_group (Config.AuditLogGroups)。リージョンは見ない (ロールの ARN はリージョンを * にする)
//   - ソースが無ければ `none` (どのロググループも読ませない)。error にしない (repo init の設定はロググループのソースがコメントだけ)。
//     全部を読ませる (`*`) かどうかは利用者が決めることで、arata は出さない
//   - `none` という名前のロググループは、予約語と区別できないので error (値の全体が `none` のときだけ予約語だが、1 つだけのソースだと区別できない)
//   - ロールの AllowedPattern に合わない名前・パラメータの値の上限を超える並びは error (スタックの更新で弾かれる前に分かる)
//   - ロールのインラインポリシーの上限に近ければ warning。Deny (DeniedLogGroupNames) の分は設定から分からないので、見積もりは Allow の分だけ
func BuildRoleParams(cfg *config.Config) (RoleParams, error) {
	var bucket, prefix string
	for _, s := range cfg.Sources {
		if s.Kind == config.KindCloudTrailS3 {
			bucket, prefix = s.Bucket, strings.Trim(s.Prefix, "/")
		}
	}
	groups := cfg.AuditLogGroups()
	if len(groups) == 0 {
		return RoleParams{AllowedLogGroupNames: RoleNoLogGroups, LogGroups: []string{}, CloudTrailBucketName: bucket, CloudTrailBucketPrefix: prefix}, nil
	}
	var bad []string
	size := rolePolicyBase
	if bucket != "" {
		size += rolePolicyTrail + 2*len(bucket) + 2*len(prefix)
	}
	for _, g := range groups {
		if !roleLogGroupName.MatchString(g) || g == RoleNoLogGroups {
			bad = append(bad, fmt.Sprintf("%q", g))
		}
		size += 2*len(g) + rolePolicyPerName
	}
	if len(bad) > 0 {
		return RoleParams{}, fmt.Errorf("config: log_group %s cannot be passed to the role (AllowedLogGroupNames takes letters, digits and _ - / . # only, and %q alone means no log group)", strings.Join(bad, ", "), RoleNoLogGroups)
	}
	p := RoleParams{AllowedLogGroupNames: strings.Join(groups, ","), LogGroups: groups, CloudTrailBucketName: bucket, CloudTrailBucketPrefix: prefix}
	if n := len(p.AllowedLogGroupNames); n > roleParamValueMax {
		return RoleParams{}, fmt.Errorf("config: AllowedLogGroupNames would be %d bytes, over the CloudFormation parameter value limit of 4,096 bytes (%d log groups)", n, len(groups))
	}
	if size > rolePolicyMax*9/10 {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"the role's inline policy would be about %d characters with these %d log groups, close to or over the IAM limit of 10,240 characters (DeniedLogGroupNames adds more); the stack update may fail", size, len(groups)))
	}
	return p, nil
}

package engine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// GitHub Actions の実行の仕組み (deploy/github-actions/runner.yaml) の守りを固定する (ADR 0040)。
// 実 AWS には接続しない。YAML を読み、信頼の条件・権限の範囲・Retain・公開ブロックを確かめる。

func loadRunnerTemplate(t *testing.T) (map[string]any, *yaml.Node) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "github-actions", "runner.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return m, &doc
}

// dig は map をキーの列でたどる。無ければテストを止める。
func dig(t *testing.T, v any, keys ...string) any {
	t.Helper()
	for i, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: mapping でない (%T)", strings.Join(keys[:i], "."), v)
		}
		v, ok = m[k]
		if !ok {
			t.Fatalf("%s が無い", strings.Join(keys[:i+1], "."))
		}
	}
	return v
}

func runnerResource(t *testing.T, tpl map[string]any, typ string) (string, map[string]any) {
	t.Helper()
	var name string
	var found map[string]any
	for n, r := range dig(t, tpl, "Resources").(map[string]any) {
		rm := r.(map[string]any)
		if rm["Type"] == typ {
			if found != nil {
				t.Fatalf("%s が 2 つ以上ある", typ)
			}
			name, found = n, rm
		}
	}
	if found == nil {
		t.Fatalf("%s が無い", typ)
	}
	return name, found
}

func TestRunnerTemplateResourceTypes(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	got := map[string]bool{}
	for _, r := range dig(t, tpl, "Resources").(map[string]any) {
		got[r.(map[string]any)["Type"].(string)] = true
	}
	want := map[string]bool{"AWS::IAM::OIDCProvider": true, "AWS::S3::Bucket": true, "AWS::S3::BucketPolicy": true, "AWS::IAM::Role": true}
	if d := setDiff(got, want); len(d) > 0 {
		t.Errorf("想定していない資源: %v", d)
	}
	if d := setDiff(want, got); len(d) > 0 {
		t.Errorf("足りない資源: %v", d)
	}
}

// バケットは消しても残し、バージョニング・暗号化・公開ブロック・TLS 必須を持つ (arata doctor の推奨と同じ)。
func TestRunnerTemplateBucket(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	_, b := runnerResource(t, tpl, "AWS::S3::Bucket")
	for _, k := range []string{"DeletionPolicy", "UpdateReplacePolicy"} {
		if b[k] != "Retain" {
			t.Errorf("バケットの %s は Retain: %v", k, b[k])
		}
	}
	if got := dig(t, b, "Properties", "VersioningConfiguration", "Status"); got != "Enabled" {
		t.Errorf("バージョニング: %v", got)
	}
	enc := dig(t, b, "Properties", "BucketEncryption", "ServerSideEncryptionConfiguration").([]any)
	if len(enc) != 1 || dig(t, enc[0], "ServerSideEncryptionByDefault", "SSEAlgorithm") != "AES256" {
		t.Errorf("既定の暗号化: %v", enc)
	}
	pab := dig(t, b, "Properties", "PublicAccessBlockConfiguration").(map[string]any)
	for _, k := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
		if pab[k] != true {
			t.Errorf("パブリックアクセスブロックの %s が true でない: %v", k, pab[k])
		}
	}
	if len(pab) != 4 {
		t.Errorf("パブリックアクセスブロックは 4 項目: %v", pab)
	}
	if got := dig(t, b, "Properties", "OwnershipControls", "Rules").([]any); len(got) != 1 || dig(t, got[0], "ObjectOwnership") != "BucketOwnerEnforced" {
		t.Errorf("ACL を無効にする (BucketOwnerEnforced): %v", got)
	}

	_, p := runnerResource(t, tpl, "AWS::S3::BucketPolicy")
	if p["DeletionPolicy"] != "Retain" {
		t.Errorf("バケットポリシーもバケットと一緒に残す: %v", p["DeletionPolicy"])
	}
	stmts := dig(t, p, "Properties", "PolicyDocument", "Statement").([]any)
	if len(stmts) != 1 {
		t.Fatalf("バケットポリシーの文は TLS 必須の 1 つだけ: %d", len(stmts))
	}
	s := stmts[0].(map[string]any)
	if s["Effect"] != "Deny" || s["Principal"] != "*" || s["Action"] != "s3:*" {
		t.Errorf("TLS 必須の Deny: %v", s)
	}
	if got := dig(t, s, "Condition", "Bool", "aws:SecureTransport"); got != false && got != "false" {
		t.Errorf("aws:SecureTransport: false を条件にする: %v", got)
	}
	if res, ok := s["Resource"].([]any); !ok || len(res) != 2 {
		t.Errorf("バケットとオブジェクトの両方を対象にする: %v", s["Resource"])
	}
}

// OIDC プロバイダはアカウントに 1 つなので、既存の ARN を渡したら作らない。作ったものは残す。
func TestRunnerTemplateOIDCProvider(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	_, o := runnerResource(t, tpl, "AWS::IAM::OIDCProvider")
	if o["Condition"] != "CreateOIDCProvider" {
		t.Errorf("作るかどうかは条件で切り替える: %v", o["Condition"])
	}
	if o["DeletionPolicy"] != "Retain" {
		t.Errorf("アカウントで共有されるので、スタックを消しても残す: %v", o["DeletionPolicy"])
	}
	if got := dig(t, o, "Properties", "Url"); got != "https://token.actions.githubusercontent.com" {
		t.Errorf("Url: %v", got)
	}
	if got := dig(t, o, "Properties", "ClientIdList").([]any); len(got) != 1 || got[0] != "sts.amazonaws.com" {
		t.Errorf("ClientIdList: %v", got)
	}
	if dig(t, tpl, "Parameters", "OIDCProviderArn", "Default") != "" {
		t.Errorf("OIDCProviderArn の既定は空 (作る)")
	}
}

// 信頼は 1 つのリポジトリの 1 つのブランチに完全一致で絞る。ワイルドカードの余地を残さない。
func TestRunnerTemplateTrustPolicy(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	_, r := runnerResource(t, tpl, "AWS::IAM::Role")
	if got := dig(t, r, "Properties", "MaxSessionDuration"); got != 3600 {
		t.Errorf("最大セッションは 1 時間: %v", got)
	}
	stmts := dig(t, r, "Properties", "AssumeRolePolicyDocument", "Statement").([]any)
	if len(stmts) != 1 {
		t.Fatalf("信頼の文は 1 つ: %d", len(stmts))
	}
	s := stmts[0].(map[string]any)
	if s["Effect"] != "Allow" || s["Action"] != "sts:AssumeRoleWithWebIdentity" {
		t.Errorf("信頼の文: %v", s)
	}
	princ := dig(t, s, "Principal").(map[string]any)
	if len(princ) != 1 || princ["Federated"] == nil {
		t.Errorf("主体は OIDC プロバイダだけ: %v", princ)
	}
	cond := dig(t, s, "Condition").(map[string]any)
	if len(cond) != 1 {
		t.Errorf("条件の演算子は StringEquals だけ (StringLike を使わない): %v", cond)
	}
	// job_workflow_ref は任意。指定したときだけ StringEquals に足す (Fn::If)。aud と sub は常に要る
	eq := dig(t, cond, "StringEquals").(map[string]any)
	if eq["token.actions.githubusercontent.com:aud"] != "sts.amazonaws.com" {
		t.Errorf("aud: %v", eq["token.actions.githubusercontent.com:aud"])
	}
	// sub は Fn::If で 3 通り。environment を指定しないとき (既定) は、これまでと同じブランチの sub の 1 つだけ (ADR 0057)
	const branchSub = "repo:${GitHubRepository}:ref:refs/heads/${GitHubBranch}"
	const envSub = "repo:${GitHubRepository}:environment:${GitHubEnvironment}"
	sub, ok := eq["token.actions.githubusercontent.com:sub"].([]any)
	if !ok || len(sub) != 3 || sub[0] != "UseEnvironment" || sub[2] != branchSub {
		t.Fatalf("sub は !If [UseEnvironment, <environment のとき>, %s]: %v", branchSub, eq["token.actions.githubusercontent.com:sub"])
	}
	// environment のとき: 既定は environment の sub の 1 つだけ。移行の期間 (KeepBranchSubject=true) だけ、ブランチの sub も並べる
	inner, ok := sub[1].([]any)
	if !ok || len(inner) != 3 || inner[0] != "AlsoAllowBranchSubject" || inner[2] != envSub {
		t.Fatalf("environment のときの sub は !If [AlsoAllowBranchSubject, <両方>, %s]: %v", envSub, sub[1])
	}
	if both, ok := inner[1].([]any); !ok || len(both) != 2 || both[0] != envSub || both[1] != branchSub {
		t.Errorf("移行の期間の sub は environment とブランチの 2 つだけ: %v", inner[1])
	}
	// environment の sub にはブランチが入らないので、ref の条件でブランチに絞る。environment を指定しないときは足さない (今と同じ)
	if ref, ok := eq["token.actions.githubusercontent.com:ref"].([]any); !ok || len(ref) != 3 || ref[0] != "UseEnvironment" || ref[1] != "refs/heads/${GitHubBranch}" || ref[2] != "AWS::NoValue" {
		t.Errorf("ref は !If [UseEnvironment, refs/heads/${GitHubBranch}, AWS::NoValue]: %v", eq["token.actions.githubusercontent.com:ref"])
	}
	conds := dig(t, tpl, "Conditions").(map[string]any)
	if got, _ := yaml.Marshal(conds["UseEnvironment"]); strings.Join(strings.Fields(string(got)), " ") != "- - GitHubEnvironment - \"\"" {
		t.Errorf("UseEnvironment は GitHubEnvironment が空でないこと: %s", got)
	}
	if got, _ := yaml.Marshal(conds["AlsoAllowBranchSubject"]); strings.Join(strings.Fields(string(got)), " ") != "- KeepBranchSubject - \"true\"" {
		t.Errorf("AlsoAllowBranchSubject は KeepBranchSubject が true のこと: %s", got)
	}
	for k := range eq {
		switch k {
		case "token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:sub", "token.actions.githubusercontent.com:job_workflow_ref", "token.actions.githubusercontent.com:ref":
		default:
			t.Errorf("想定していない条件キー: %s", k)
		}
	}
	if _, ok := eq["token.actions.githubusercontent.com:job_workflow_ref"]; !ok {
		t.Errorf("job_workflow_ref の条件 (任意) が無い")
	}
}

// パラメータはワイルドカードを受け付けない (sub・job_workflow_ref・AssumeRole の先を広げさせない)。
func TestRunnerTemplateParameterPatterns(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	cases := map[string]struct{ ok, ng []string }{
		"GitHubRepository": {
			ok: []string{"example-org/security-audit", "example-org@1234567/security-audit@7654321", "alice/my.repo_1"},
			ng: []string{"", "example-org/*", "example-org", "*/security-audit", "example-org/security-audit:ref:refs/heads/main", "example-org/a b", "example-org/security-audit/x", "example-org@x/security-audit"},
		},
		"GitHubBranch": {
			ok: []string{"main", "release/1.x"},
			ng: []string{"", "*", "ma?n", "main:x", "a b"},
		},
		"GitHubEnvironment": {
			ok: []string{"", "audit", "arata-audit_1.x"},
			ng: []string{"*", "aud?t", "audit:ref:refs/heads/main", "audit%3Ax", "a b", "a/b"},
		},
		"GitHubWorkflowRef": {
			ok: []string{"", "example-org/security-audit/.github/workflows/arata-audit.yml@refs/heads/main"},
			ng: []string{"*", "example-org/security-audit/.github/workflows/*@refs/heads/main", "example-org/security-audit/.github/workflows/arata-audit.yml", "example-org/security-audit/.github/workflows/a.yml@refs/heads/ma?n"},
		},
		"AuditRoleArns": {
			ok: []string{"arn:aws:iam::123456789012:role/arata-readonly", "arn:aws:iam::111122223333:role/path/arata-readonly"},
			ng: []string{"", "*", "arn:aws:iam::123456789012:role/*", "arn:aws:iam::*:role/arata-readonly", "arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:root"},
		},
		"OIDCProviderArn": {
			ok: []string{"", "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
			ng: []string{"arn:aws:iam::123456789012:oidc-provider/example.com", "arn:aws:iam::123456789012:oidc-provider/*"},
		},
		"BedrockInferenceProfileArn": {
			ok: []string{"", "arn:aws:bedrock:ap-northeast-1:123456789012:inference-profile/jp.example.model-v1:0", "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123def456"},
			ng: []string{"*", "arn:aws:bedrock:ap-northeast-1:123456789012:inference-profile/*", "arn:aws:bedrock:*:123456789012:inference-profile/jp.example.model-v1:0", "arn:aws:bedrock:ap-northeast-1::foundation-model/example.model-v1:0", "jp.example.model-v1:0"},
		},
		"StoreBucketName": {
			ok: []string{"", "example-arata-store"},
			ng: []string{"Example", "a/b", "ab"},
		},
		"StorePrefix": {
			ok: []string{"", "example", "aws/prod"},
			ng: []string{"/example", "example/", "a*", "a//b", "a b"},
		},
	}
	for name, c := range cases {
		pat, ok := dig(t, tpl, "Parameters", name).(map[string]any)["AllowedPattern"].(string)
		if !ok {
			t.Errorf("%s に AllowedPattern が無い", name)
			continue
		}
		// CloudFormation は値の全体に一致させる
		re, err := regexp.Compile("^(?:" + pat + ")$")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, v := range c.ok {
			if !re.MatchString(v) {
				t.Errorf("%s は %q を受け付けるはず", name, v)
			}
		}
		for _, v := range c.ng {
			if re.MatchString(v) {
				t.Errorf("%s は %q を拒むはず", name, v)
			}
		}
	}
	// ConstraintDescription は ASCII だけ (日本語は CloudFormation のエラーの表示で ? に化ける。実機で確かめた)
	for name, p := range dig(t, tpl, "Parameters").(map[string]any) {
		if d, ok := p.(map[string]any)["ConstraintDescription"].(string); ok && strings.IndexFunc(d, func(r rune) bool { return r > 0x7e }) >= 0 {
			t.Errorf("%s の ConstraintDescription は ASCII だけ: %q", name, d)
		}
	}
	if got := dig(t, tpl, "Parameters", "AuditRoleArns", "Type"); got != "CommaDelimitedList" {
		t.Errorf("監査ロールは複数を受ける: %v", got)
	}
	if got := dig(t, tpl, "Parameters", "GitHubBranch", "Default"); got != "main" {
		t.Errorf("ブランチの既定は main: %v", got)
	}
	// environment は既定で使わない (今までのスタックは、更新しても信頼が変わらない)。移行の期間の許可も既定で無し
	if got := dig(t, tpl, "Parameters", "GitHubEnvironment", "Default"); got != "" {
		t.Errorf("GitHubEnvironment の既定は空: %v", got)
	}
	keep := dig(t, tpl, "Parameters", "KeepBranchSubject").(map[string]any)
	if keep["Default"] != "false" {
		t.Errorf("KeepBranchSubject の既定は false: %v", keep["Default"])
	}
	if av, ok := keep["AllowedValues"].([]any); !ok || len(av) != 2 || av[0] != "false" || av[1] != "true" {
		t.Errorf("KeepBranchSubject は false / true だけ: %v", keep["AllowedValues"])
	}
}

// 権限はストアの 3 つの action (doctor の一覧と同じ) と、監査ロールの引き受けだけ。
func TestRunnerTemplatePermissions(t *testing.T) {
	tpl, doc := loadRunnerTemplate(t)
	_, r := runnerResource(t, tpl, "AWS::IAM::Role")
	if _, ok := r["Properties"].(map[string]any)["ManagedPolicyArns"]; ok {
		t.Errorf("管理ポリシーは付けない")
	}
	pols := dig(t, r, "Properties", "Policies").([]any)
	if len(pols) != 1 {
		t.Fatalf("インラインポリシーは 1 つ: %d", len(pols))
	}
	want := map[string]bool{"sts:AssumeRole": true}
	for _, a := range StoreActions {
		want[a] = true
	}
	got := map[string]bool{}
	byAction := map[string]any{}
	for _, s := range dig(t, pols[0], "PolicyDocument", "Statement").([]any) {
		sm, ok := s.(map[string]any)
		if !ok {
			continue // !If で包んだ任意の文 (Bedrock)。TestRunnerTemplateBedrock が見る
		}
		if sm["Effect"] != "Allow" {
			t.Errorf("Allow の文だけ: %v", sm)
		}
		if _, ok := sm["NotAction"]; ok {
			t.Errorf("NotAction は使わない")
		}
		if _, ok := sm["NotResource"]; ok {
			t.Errorf("NotResource は使わない")
		}
		var acts []any
		switch a := sm["Action"].(type) {
		case string:
			acts = []any{a}
		case []any:
			acts = a
		}
		for _, a := range acts {
			got[a.(string)] = true
			byAction[a.(string)] = sm["Resource"]
		}
		if sm["Resource"] == "*" {
			t.Errorf("Resource に * は使わない: %v", sm)
		}
	}
	if d := setDiff(want, got); len(d) > 0 {
		t.Errorf("ロールに無い action: %v", d)
	}
	if d := setDiff(got, want); len(d) > 0 {
		t.Errorf("要らない action がロールにある: %v", d)
	}
	// AssumeRole の先はパラメータの一覧そのもの (!Ref AuditRoleArns)
	if byAction["sts:AssumeRole"] != "AuditRoleArns" {
		t.Errorf("sts:AssumeRole の Resource は !Ref AuditRoleArns: %v", byAction["sts:AssumeRole"])
	}
	// オブジェクトの読み書きは prefix の下だけ。ListBucket はバケット (s3:prefix で絞らない。README「S3 ストア」)
	for _, a := range []string{"s3:GetObject", "s3:PutObject"} {
		res, ok := byAction[a].([]any) // !If [HasStorePrefix, <prefix の下>, <バケット全体>]
		if !ok || len(res) != 3 || res[0] != "HasStorePrefix" || res[1] != "${StoreBucket.Arn}/${StorePrefix}/*" || res[2] != "${StoreBucket.Arn}/*" {
			t.Errorf("%s の Resource: %v", a, byAction[a])
		}
	}
	if byAction["s3:ListBucket"] != "StoreBucket.Arn" {
		t.Errorf("s3:ListBucket の Resource はバケット: %v", byAction["s3:ListBucket"])
	}
	// テンプレートのどこにも s3:Delete* や iam の書き込みが無い
	var actions []*yaml.Node
	findKey(doc, "Action", &actions)
	all := map[string]bool{}
	for _, n := range actions {
		collectScalars(n, all)
	}
	for a := range all {
		if a != "s3:*" && a != "sts:AssumeRoleWithWebIdentity" && a != "bedrock:InvokeModel" && !want[a] { // s3:* はバケットポリシーの Deny
			t.Errorf("想定していない action: %s", a)
		}
	}
}

func TestRunnerTemplateOutputs(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	out := dig(t, tpl, "Outputs").(map[string]any)
	for _, k := range []string{"RunnerRoleArn", "StoreBucketName", "StoreUrl", "OIDCProviderArn"} {
		if _, ok := out[k]; !ok {
			t.Errorf("出力 %s が無い", k)
		}
	}
	// 説明は ASCII だけ (IAM の Description は日本語を受け付けない。sandbox で deploy して分かった種類の誤りを先に止める)
	_, r := runnerResource(t, tpl, "AWS::IAM::Role")
	for _, c := range dig(t, r, "Properties", "Description").(string) {
		if c > 0x7e {
			t.Errorf("ロールの Description は ASCII だけ")
			break
		}
	}
}

// aratam の provider: bedrock 用の権限は任意。推論プロファイルを指定したときだけ、そのプロファイルと、
// そのプロファイルを通した基盤モデルの呼び出しに限って bedrock:InvokeModel を許す (aratam は Converse だけを使う)。
func TestRunnerTemplateBedrock(t *testing.T) {
	tpl, _ := loadRunnerTemplate(t)
	if dig(t, tpl, "Parameters", "BedrockInferenceProfileArn", "Default") != "" {
		t.Errorf("既定は空 (Bedrock の権限を足さない)")
	}
	_, r := runnerResource(t, tpl, "AWS::IAM::Role")
	pols := dig(t, r, "Properties", "Policies").([]any)
	var stmts []map[string]any
	for _, s := range dig(t, pols[0], "PolicyDocument", "Statement").([]any) {
		l, ok := s.([]any)
		if !ok {
			continue
		}
		// !If [HasBedrockInferenceProfile, <文>, !Ref AWS::NoValue]
		if len(l) != 3 || l[0] != "HasBedrockInferenceProfile" || l[2] != "AWS::NoValue" {
			t.Fatalf("任意の文は HasBedrockInferenceProfile のときだけ: %v", l)
		}
		stmts = append(stmts, l[1].(map[string]any))
	}
	if len(stmts) != 2 {
		t.Fatalf("Bedrock の文は 2 つ (推論プロファイルと基盤モデル): %d", len(stmts))
	}
	var sawProfile, sawModel bool
	for _, s := range stmts {
		if s["Effect"] != "Allow" || s["Action"] != "bedrock:InvokeModel" {
			t.Errorf("bedrock:InvokeModel だけを許す (ストリーミングは使わない): %v", s)
		}
		switch res := s["Resource"]; res {
		case "BedrockInferenceProfileArn": // !Ref
			sawProfile = true
			if _, ok := s["Condition"]; ok {
				t.Errorf("推論プロファイルの文に条件は要らない: %v", s)
			}
		case "arn:${AWS::Partition}:bedrock:*::foundation-model/*":
			// 振り分け先のリージョンと基盤モデルはテンプレートから分からないので、「そのプロファイルを通した呼び出し」で絞る
			sawModel = true
			cond := dig(t, s, "Condition").(map[string]any)
			if len(cond) != 1 || dig(t, cond, "StringEquals", "bedrock:InferenceProfileArn") != "BedrockInferenceProfileArn" {
				t.Errorf("基盤モデルは bedrock:InferenceProfileArn の完全一致で絞る: %v", cond)
			}
		default:
			t.Errorf("想定していない Resource: %v", res)
		}
	}
	if !sawProfile || !sawModel {
		t.Errorf("推論プロファイルと基盤モデルの両方の文が要る")
	}
}

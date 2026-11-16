// 顧客に配る deploy/iam/readonly-role.yaml (素の CloudFormation) を CfnInclude で読み、中身を固定する。
// action が Go の collector と一致することは internal/engine/readonly_role_test.go が確かめる。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { CfnInclude } from 'aws-cdk-lib/cloudformation-include';
import { READONLY_ROLE_TEMPLATE } from '../lib/sandbox-stack.ts';

// README の表と設計書 8 章の action。書き込み系は iam:GenerateCredentialReport だけ。
const EXPECTED_ACTIONS = [
  'access-analyzer:ListAnalyzers',
  'access-analyzer:ListFindings',
  'account:ListRegions',
  'ce:GetAnomalies',
  'ce:GetAnomalyMonitors',
  'cloudtrail:DescribeTrails',
  'cloudtrail:GetEventSelectors',
  'cloudtrail:GetTrailStatus',
  'cloudtrail:LookupEvents',
  'elasticloadbalancing:DescribeLoadBalancers',
  'guardduty:GetDetector',
  'guardduty:GetFindings',
  'guardduty:ListDetectors',
  'guardduty:ListFindings',
  'iam:GenerateCredentialReport',
  'iam:GetAccountPasswordPolicy',
  'iam:GetAccountSummary',
  'iam:GetCredentialReport',
  'logs:DescribeLogGroups',
  'logs:GetQueryResults',
  'logs:StartQuery',
  'logs:StopQuery',
  's3:GetAccountPublicAccessBlock',
  'wafv2:DescribeManagedRuleGroup',
  'wafv2:GetLoggingConfiguration',
  'wafv2:GetWebACL',
  'wafv2:GetWebACLForResource',
  'wafv2:ListResourcesForWebACL',
  'wafv2:ListWebACLs',
];

function rawTemplate(): Record<string, any> {
  const stack = new Stack(new App(), 'Raw');
  new CfnInclude(stack, 'Role', { templateFile: READONLY_ROLE_TEMPLATE });
  return Template.fromStack(stack).toJSON();
}

function roleOf(t: Record<string, any>): Record<string, any> {
  const roles = Object.values(t.Resources).filter((r: any) => r.Type === 'AWS::IAM::Role');
  assert.equal(roles.length, 1);
  return roles[0] as Record<string, any>;
}

test('読み取りロールの権限は決めた action だけ (ワイルドカード無し)', () => {
  const t = rawTemplate();
  const role = roleOf(t);
  const all = role.Properties.Policies.flatMap((p: any) => p.PolicyDocument.Statement);
  // 条件付きの文 (Fn::If) は、DeniedLogGroupNames の Deny、AllowedLogGroupNames=none で出さない Logs Insights の Allow、
  // CloudTrailBucketName・CloudTrailKmsKeyArn を渡したときだけの S3 と KMS の 3 つ (ADR 0063) の計 5 つ。下のテストで見る
  const statements = all.filter((s: any) => !s['Fn::If']);
  assert.equal(all.length - statements.length, 5, '条件付きの文は 5 つ');
  const insights = all.filter((s: any) => s['Fn::If']?.[0] === 'AllowNoLogGroups').map((s: any) => s['Fn::If'][2]);
  const actions = [...statements, ...insights].flatMap((s: any) => [s.Action].flat()).sort();
  assert.deepEqual(actions, EXPECTED_ACTIONS);
  for (const s of statements) {
    assert.equal(s.Effect, 'Allow');
    assert.equal(s.NotAction, undefined);
  }
  assert.equal(role.Properties.ManagedPolicyArns, undefined, '管理ポリシー (ReadOnlyAccess など) は付けない');
  const others = Object.values(t.Resources).filter((r: any) => r.Type !== 'AWS::IAM::Role');
  assert.deepEqual(others, [], 'ロール以外のリソースは作らない');
});

test('信頼する主体・Roles Anywhere のトラストアンカー・ExternalId・ロール名はパラメータ', () => {
  const t = rawTemplate();
  for (const p of ['TrustedPrincipalArn', 'RolesAnywhereTrustAnchorArn', 'ExternalId', 'RoleName']) {
    assert.ok(t.Parameters?.[p], `パラメータ ${p} が無い`);
  }
  assert.equal(t.Parameters.RolesAnywhereTrustAnchorArn.Default, '');
  assert.equal(t.Parameters.ExternalId.Default, '');
  const role = roleOf(t);
  assert.deepEqual(role.Properties.RoleName, { Ref: 'RoleName' });
  const trust = JSON.stringify(role.Properties.AssumeRolePolicyDocument);
  assert.ok(trust.includes('"Ref":"TrustedPrincipalArn"'));
  assert.ok(trust.includes('rolesanywhere.amazonaws.com'));
  assert.ok(trust.includes('"Ref":"RolesAnywhereTrustAnchorArn"'), 'Roles Anywhere はトラストアンカーで絞る');
  assert.ok(trust.includes('sts:ExternalId'));
});

test('DeniedLogGroupNames のロググループは明示の Deny で読ませない (既定は空で、文を出さない)', () => {
  const t = rawTemplate();
  const p = t.Parameters.DeniedLogGroupNames;
  assert.equal(p.Type, 'String');
  assert.equal(p.Default, '');
  const pattern = new RegExp(p.AllowedPattern);
  for (const ok of ['', 'prod-mail-delivery', 'prod-mail-delivery,/app/prod/mail-bounce']) {
    assert.ok(pattern.test(ok), `通るはず: ${ok}`);
  }
  for (const ng of ['*', 'prod-*', 'a, b', 'a,', 'a:*', 'arn:aws:logs:ap-northeast-1:123456789012:log-group:a']) {
    assert.ok(!pattern.test(ng), `弾くはず: ${ng}`);
  }
  assert.deepEqual(t.Conditions.HasDeniedLogGroups, { 'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'DeniedLogGroupNames' }, ''] }] });

  const statements = roleOf(t).Properties.Policies.flatMap((p: any) => p.PolicyDocument.Statement);
  const conditional = statements.filter((s: any) => s['Fn::If']?.[0] === 'HasDeniedLogGroups');
  assert.equal(conditional.length, 1);
  const [cond, deny, otherwise] = conditional[0]['Fn::If'];
  assert.equal(cond, 'HasDeniedLogGroups');
  assert.deepEqual(otherwise, { Ref: 'AWS::NoValue' }, '空なら文を出さない');
  assert.equal(deny.Effect, 'Deny');
  assert.equal(deny.NotAction, undefined);
  assert.equal(deny.NotResource, undefined);
  assert.equal(deny.Condition, undefined);
  assert.deepEqual([...deny.Action].sort(), [
    'logs:FilterLogEvents',
    'logs:GetLogEvents',
    'logs:GetLogGroupFields',
    'logs:GetLogRecord',
    'logs:GetQueryResults',
    'logs:StartLiveTail',
    'logs:StartQuery',
    'logs:Unmask',
  ]);
  // Resource は名前の並びから組み立てる (解いた結果は internal/engine/readonly_role_test.go が確かめる)
  const resource = JSON.stringify(deny.Resource);
  assert.ok(resource.includes('"Ref":"DeniedLogGroupNames"'), resource);
  assert.ok(resource.includes('arn:*:logs:*:*:log-group:'), resource);
  assert.notEqual(deny.Resource, '*');
});

test('AllowedLogGroupNames のロググループだけ、ログの中身を読める (既定は無く、全部なら *、どれも読ませないなら none。ADR 0062)', () => {
  const t = rawTemplate();
  const p = t.Parameters.AllowedLogGroupNames;
  assert.equal(p.Type, 'String');
  assert.ok(!('Default' in p), '既定は書かない (更新でも値が要る)');
  const pattern = new RegExp(p.AllowedPattern);
  for (const ok of ['*', 'none', 'prod-nginx-access', 'prod-nginx-access,/app/prod/api']) {
    assert.ok(pattern.test(ok), `通るはず: ${ok}`);
  }
  for (const ng of ['', '**', 'prod-*', 'a,*', 'a, b', 'a,', 'a:*', 'arn:aws:logs:ap-northeast-1:123456789012:log-group:a']) {
    assert.ok(!pattern.test(ng), `弾くはず: ${ng}`);
  }
  assert.deepEqual(t.Conditions.AllowAllLogGroups, { 'Fn::Equals': [{ Ref: 'AllowedLogGroupNames' }, '*'] });
  assert.deepEqual(t.Conditions.AllowNoLogGroups, { 'Fn::Equals': [{ Ref: 'AllowedLogGroupNames' }, 'none'] });

  const statements = roleOf(t).Properties.Policies.flatMap((p: any) => p.PolicyDocument.Statement);
  // none (どのロググループも読ませない) なら、中身を読む文を出さない
  const [noneCond, noneValue, read] = statements.find((s: any) => s['Fn::If']?.[0] === 'AllowNoLogGroups')['Fn::If'];
  assert.equal(noneCond, 'AllowNoLogGroups');
  assert.deepEqual(noneValue, { Ref: 'AWS::NoValue' });
  assert.equal(read.Sid, 'CloudWatchLogsInsights');
  assert.deepEqual([...read.Action].sort(), ['logs:GetQueryResults', 'logs:StartQuery']);
  const [cond, all, listed] = read.Resource['Fn::If'];
  assert.equal(cond, 'AllowAllLogGroups');
  assert.equal(all, '*');
  // 名前の並びから組み立てる (解いた結果は internal/engine/readonly_role_test.go が確かめる)
  const resource = JSON.stringify(listed);
  assert.ok(resource.includes('"Ref":"AllowedLogGroupNames"'), resource);
  assert.ok(resource.includes('arn:*:logs:*:*:log-group:'), resource);
  const list = statements.find((s: any) => s.Sid === 'CloudWatchLogsList');
  assert.deepEqual([...list.Action].sort(), ['logs:DescribeLogGroups', 'logs:StopQuery']);
  assert.equal(list.Resource, '*');
});

test('cloudtrail-s3 の S3 と KMS の文は、パラメータを渡したときだけ (既定は空で、今までのロールと同じ。ADR 0063)', () => {
  const t = rawTemplate();
  for (const name of ['CloudTrailBucketName', 'CloudTrailBucketPrefix', 'CloudTrailKmsKeyArn']) {
    assert.equal(t.Parameters[name].Type, 'String');
    assert.equal(t.Parameters[name].Default, '', `${name} の既定は空`);
  }
  const bucket = new RegExp(t.Parameters.CloudTrailBucketName.AllowedPattern);
  for (const ng of ['arn:aws:s3:::example-trail-logs', 's3://example-trail-logs', 'Example', 'x*']) {
    assert.ok(!bucket.test(ng), `弾くはず: ${ng}`);
  }
  const prefix = new RegExp(t.Parameters.CloudTrailBucketPrefix.AllowedPattern);
  for (const ng of ['/logs', 'logs/', 'logs/*', 'lo?gs']) {
    assert.ok(!prefix.test(ng), `弾くはず: ${ng}`);
  }
  assert.deepEqual(t.Conditions.HasTrailBucket, { 'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'CloudTrailBucketName' }, ''] }] });
  assert.deepEqual(t.Conditions.HasTrailKmsKey, { 'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'CloudTrailKmsKeyArn' }, ''] }] });

  const statements = roleOf(t).Properties.Policies.flatMap((p: any) => p.PolicyDocument.Statement);
  const byCond = (cond: string) => statements.filter((s: any) => s['Fn::If']?.[0] === cond).map((s: any) => {
    const [, value, otherwise] = s['Fn::If'];
    assert.deepEqual(otherwise, { Ref: 'AWS::NoValue' }, `${cond} が偽なら文を出さない`);
    return value;
  });
  const s3 = byCond('HasTrailBucket');
  assert.deepEqual(s3.map((s: any) => [s.Sid, s.Action]), [['CloudTrailS3List', ['s3:ListBucket']], ['CloudTrailS3Read', ['s3:GetObject']]]);
  assert.ok(JSON.stringify(s3[0].Condition).includes('AWSLogs/*'), '一覧は AWSLogs/ の下に絞る');
  assert.ok(JSON.stringify(s3[1].Resource).includes('/AWSLogs/*'), '読み取りは AWSLogs/ の下だけ');
  const [kms] = byCond('HasTrailKmsKey');
  assert.deepEqual(kms.Action, ['kms:Decrypt']);
  assert.deepEqual(kms.Resource, { Ref: 'CloudTrailKmsKeyArn' });
  assert.deepEqual(kms.Condition, { Null: { 'kms:EncryptionContext:aws:cloudtrail:arn': 'false' } });
});

test('信頼先が 1 つも無いスタックは作らせない (Rules)', () => {
  const t = rawTemplate();
  const rules = JSON.stringify(t.Rules ?? {});
  assert.ok(rules.includes('TrustedPrincipalArn') && rules.includes('RolesAnywhereTrustAnchorArn'), rules);
});

test('ロール ARN を出力する', () => {
  const t = rawTemplate();
  assert.ok(t.Outputs?.RoleArn, 'Outputs.RoleArn が無い');
});

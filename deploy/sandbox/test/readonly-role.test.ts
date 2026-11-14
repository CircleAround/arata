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
  // 条件付きの文 (Fn::If) は DeniedLogGroupNames の Deny だけ。下のテストで見る
  const statements = all.filter((s: any) => !s['Fn::If']);
  assert.equal(all.length - statements.length, 1, '条件付きの文は 1 つ (Deny) だけ');
  const actions = statements.flatMap((s: any) => [s.Action].flat()).sort();
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
  const conditional = statements.filter((s: any) => s['Fn::If']);
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

test('信頼先が 1 つも無いスタックは作らせない (Rules)', () => {
  const t = rawTemplate();
  const rules = JSON.stringify(t.Rules ?? {});
  assert.ok(rules.includes('TrustedPrincipalArn') && rules.includes('RolesAnywhereTrustAnchorArn'), rules);
});

test('ロール ARN を出力する', () => {
  const t = rawTemplate();
  assert.ok(t.Outputs?.RoleArn, 'Outputs.RoleArn が無い');
});

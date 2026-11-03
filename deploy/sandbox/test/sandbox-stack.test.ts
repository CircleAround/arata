import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { parseConfig } from '../lib/config.ts';
import { SandboxStack, buildSandbox } from '../lib/sandbox-stack.ts';

const examplePath = fileURLToPath(new URL('../config.example.json', import.meta.url));

// cdk.json の context (推奨の feature flag と、CloudFormation の検証の警告をエラーにする設定) で合成し、cdk synth と同じ結果にする
const cdkContext = JSON.parse(readFileSync(new URL('../cdk.json', import.meta.url), 'utf8')).context as Record<string, unknown>;

function newApp(): App {
  return new App({ context: cdkContext });
}

test('cdk.json: 検証の警告をエラーにし、推奨の feature flag を入れている', () => {
  assert.equal(cdkContext['@aws-cdk/core:validateAgainstDefaultRules'], true);
  assert.ok(Object.keys(cdkContext).filter((k) => k.startsWith('@aws-cdk')).length > 50, 'cdk init と同じ推奨のフラグ');
});

function example(): Record<string, any> {
  return JSON.parse(readFileSync(examplePath, 'utf8'));
}

function synth(mutate: (raw: Record<string, any>) => void = () => {}): Template {
  const raw = example();
  mutate(raw);
  const config = parseConfig(raw);
  const stack = new SandboxStack(newApp(), 'Test', { config });
  return Template.fromStack(stack);
}

function resourcesOf(t: Template, type: string): Record<string, any>[] {
  return Object.values(t.findResources(type));
}

test('スタックの env は設定のアカウントとリージョン (別アカウントの認証情報では deploy できない)', () => {
  const stack = new SandboxStack(newApp(), 'Test', { config: parseConfig(example()) });
  assert.equal(stack.account, '123456789012');
  assert.equal(stack.region, 'ap-northeast-1');
});

test('buildSandbox: スタック名は prefix', () => {
  const app = newApp();
  const stack = buildSandbox(app, examplePath);
  assert.equal(stack.stackName, 'arata-sandbox');
});

test('読み取りロールは deploy/iam/readonly-role.yaml を取り込み、設定の主体を信頼する (パラメータの既定値で渡す)', () => {
  const t = synth();
  const params = t.toJSON().Parameters as Record<string, any>;
  assert.equal(params.RoleName.Default, 'arata-sandbox-readonly');
  assert.equal(params.TrustedPrincipalArn.Default, 'arn:aws:iam::123456789012:root');
  assert.equal(params.ExternalId.Default, '');
  assert.equal(params.RolesAnywhereTrustAnchorArn.Default, '');
  t.hasResourceProperties('AWS::IAM::Role', {
    RoleName: { Ref: 'RoleName' },
    Policies: Match.arrayWith([
      Match.objectLike({
        PolicyDocument: Match.objectLike({
          Statement: Match.arrayWith([Match.objectLike({ Action: Match.arrayWith(['iam:GenerateCredentialReport']) })]),
        }),
      }),
    ]),
  });
});

test('リソースの説明は ASCII (IAM などは日本語を受け付けず deploy で失敗する)', () => {
  const t = synth((raw) => {
    raw.guardDuty.enabled = true;
    raw.bedrock.enabled = true;
    raw.waf.enabled = true;
  });
  for (const [id, r] of Object.entries(t.toJSON().Resources as Record<string, any>)) {
    const d = r.Properties?.Description;
    if (typeof d === 'string') assert.match(d, /^[\x20-\x7e]*$/, `${id} の Description: ${d}`);
  }
});

test('nginx のロググループは設定の名前・保持期間で、destroy で消える', () => {
  const t = synth();
  t.hasResource('AWS::Logs::LogGroup', {
    Properties: { LogGroupName: 'prod-nginx-access', RetentionInDays: 7 },
    DeletionPolicy: 'Delete',
    UpdateReplacePolicy: 'Delete',
  });
});

test('試験ユーザーは prefix 付きの名前で、ポリシー・グループを一切持たない', () => {
  const t = synth();
  const users = resourcesOf(t, 'AWS::IAM::User');
  assert.deepEqual(users.map((u) => u.Properties.UserName).sort(), ['arata-sandbox-alice', 'arata-sandbox-bob']);
  for (const u of users) {
    assert.equal(u.Properties.Policies, undefined);
    assert.equal(u.Properties.ManagedPolicyArns, undefined);
    assert.equal(u.Properties.Groups, undefined);
    assert.equal(u.Properties.PermissionsBoundary, undefined);
  }
});

test('consolePassword のユーザーだけ、生成したシークレットを動的参照するパスワードを持つ (MFA は付けない)', () => {
  const t = synth();
  const users = resourcesOf(t, 'AWS::IAM::User');
  const alice = users.find((u) => u.Properties.UserName === 'arata-sandbox-alice')!;
  const bob = users.find((u) => u.Properties.UserName === 'arata-sandbox-bob')!;
  assert.equal(bob.Properties.LoginProfile, undefined);
  const pw = JSON.stringify(alice.Properties.LoginProfile.Password);
  assert.ok(pw.includes('{{resolve:secretsmanager:'), `動的参照ではない: ${pw}`);
  assert.equal(alice.Properties.LoginProfile.PasswordResetRequired, false);

  const secrets = Object.values(t.findResources('AWS::SecretsManager::Secret'));
  assert.equal(secrets.length, 1);
  assert.ok(secrets[0].Properties.GenerateSecretString, 'パスワードは生成する (テンプレートに値を書かない)');
  assert.equal(secrets[0].DeletionPolicy, 'Delete');
  t.resourceCountIs('AWS::IAM::VirtualMFADevice', 0);
});

test('accessKey のユーザーだけアクセスキーを持ち、秘密値はどこからも参照しない', () => {
  const t = synth();
  const keys = resourcesOf(t, 'AWS::IAM::AccessKey');
  assert.equal(keys.length, 1);
  const users = t.findResources('AWS::IAM::User');
  const bobId = Object.keys(users).find((id) => users[id].Properties.UserName === 'arata-sandbox-bob');
  assert.deepEqual(keys[0].Properties.UserName, { Ref: bobId });
  assert.ok(!JSON.stringify(t.toJSON()).includes('SecretAccessKey'), 'SecretAccessKey を参照している');
});

test('外部アカウントから AssumeRole される役のロールは権限を持たない', () => {
  const t = synth();
  const roles = resourcesOf(t, 'AWS::IAM::Role').filter((r) => r.Properties.RoleName === 'arata-sandbox-external');
  assert.equal(roles.length, 1);
  const role = roles[0];
  assert.deepEqual(role.Properties.AssumeRolePolicyDocument.Statement, [
    {
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::111122223333:root' },
      Action: 'sts:AssumeRole',
      Condition: { StringEquals: { 'sts:ExternalId': 'example-external-id' } },
    },
  ]);
  assert.equal(role.Properties.Policies, undefined);
  assert.equal(role.Properties.ManagedPolicyArns, undefined);
});

test('externalId を省略すると条件を付けない', () => {
  const t = synth((raw) => delete raw.externalRole.externalId);
  const role = resourcesOf(t, 'AWS::IAM::Role').find((r) => r.Properties.RoleName === 'arata-sandbox-external')!;
  assert.equal(role.Properties.AssumeRolePolicyDocument.Statement[0].Condition, undefined);
});

test('IAM のポリシーは読み取りロールのインラインポリシーだけ (別のポリシーリソースを作らない)', () => {
  const t = synth((raw) => {
    raw.guardDuty.enabled = true;
    raw.bedrock.enabled = true;
    raw.waf.enabled = true;
  });
  t.resourceCountIs('AWS::IAM::Policy', 0);
  t.resourceCountIs('AWS::IAM::ManagedPolicy', 0);
  t.resourceCountIs('AWS::IAM::UserToGroupAddition', 0);
  t.resourceCountIs('AWS::IAM::Group', 0);
  const withPolicies = resourcesOf(t, 'AWS::IAM::Role').filter((r) => r.Properties.Policies || r.Properties.ManagedPolicyArns);
  assert.deepEqual(withPolicies.map((r) => r.Properties.RoleName), [{ Ref: 'RoleName' }], '読み取りロール (名前はパラメータ) だけ');
});

test('GuardDuty は設定で on/off', () => {
  synth().resourceCountIs('AWS::GuardDuty::Detector', 0);
  const t = synth((raw) => (raw.guardDuty.enabled = true));
  t.hasResourceProperties('AWS::GuardDuty::Detector', { Enable: true });
});

test('Access Analyzer (外部アクセス、アカウント単位) は設定で on/off', () => {
  synth().hasResourceProperties('AWS::AccessAnalyzer::Analyzer', { Type: 'ACCOUNT', AnalyzerName: 'arata-sandbox' });
  synth((raw) => (raw.accessAnalyzer.enabled = false)).resourceCountIs('AWS::AccessAnalyzer::Analyzer', 0);
});

test('Bedrock の application inference profile は設定で on/off し、ARN を出力する', () => {
  synth().resourceCountIs('AWS::Bedrock::ApplicationInferenceProfile', 0);
  const t = synth((raw) => (raw.bedrock.enabled = true));
  t.hasResourceProperties('AWS::Bedrock::ApplicationInferenceProfile', {
    InferenceProfileName: 'arata-sandbox',
    ModelSource: { CopyFrom: example().bedrock.modelSourceArn },
  });
  assert.ok(t.findOutputs('InferenceProfileArn').InferenceProfileArn);
});

test('全リソースが cdk destroy で消える (Retain / Snapshot を持たない)', () => {
  const t = synth((raw) => {
    raw.guardDuty.enabled = true;
    raw.bedrock.enabled = true;
    raw.waf.enabled = true;
  });
  for (const [id, r] of Object.entries(t.toJSON().Resources as Record<string, any>)) {
    for (const key of ['DeletionPolicy', 'UpdateReplacePolicy']) {
      assert.ok(r[key] === undefined || r[key] === 'Delete', `${id} (${r.Type}) の ${key} が ${r[key]}`);
    }
  }
});

test('出力に秘密値を含めない・使い方に要る値は出す', () => {
  const t = synth();
  const outputs = t.toJSON().Outputs as Record<string, any>;
  for (const name of ['ReadonlyRoleArn', 'NginxLogGroupName', 'ExternalRoleArn', 'TestUserNames']) {
    assert.ok(outputs[name], `Outputs.${name} が無い`);
  }
  const s = JSON.stringify(outputs);
  assert.ok(!s.includes('Secret'), s);
});

// --- WAF (waf.enabled)。WAF の修正提案を本物の AWS で確かめるための、低コストの試験用 WAF ---

function withWaf(): Template {
  return synth((raw) => (raw.waf.enabled = true));
}

const WAF_TYPES = [
  'AWS::ApiGateway::RestApi',
  'AWS::WAFv2::WebACL',
  'AWS::WAFv2::WebACLAssociation',
  'AWS::WAFv2::LoggingConfiguration',
  'AWS::Logs::ResourcePolicy',
];

test('WAF: 無効なら API・WebACL・WAF のロググループを作らず、出力も出さない', () => {
  const t = synth();
  for (const type of WAF_TYPES) t.resourceCountIs(type, 0);
  assert.equal(resourcesOf(t, 'AWS::Logs::LogGroup').length, 1, 'nginx のロググループだけ');
  const outputs = t.toJSON().Outputs as Record<string, any>;
  for (const name of ['ApiUrl', 'WebAclArn', 'WafLogGroupName']) assert.equal(outputs[name], undefined, name);
});

test('WAF: API Gateway (REST、REGIONAL) は mock 統合で固定の 200 を返し、認証なし', () => {
  const t = withWaf();
  t.hasResourceProperties('AWS::ApiGateway::RestApi', {
    Name: 'arata-sandbox-waf',
    EndpointConfiguration: { Types: ['REGIONAL'] },
  });
  const paths = resourcesOf(t, 'AWS::ApiGateway::Resource').map((r) => r.Properties.PathPart).sort();
  assert.deepEqual(paths, ['api', 'health', 'login', 'search', '{proxy+}']);

  const methods = resourcesOf(t, 'AWS::ApiGateway::Method');
  assert.deepEqual(methods.map((m) => m.Properties.HttpMethod).sort(), ['ANY', 'GET', 'GET', 'GET', 'POST']);
  for (const m of methods) {
    assert.equal(m.Properties.AuthorizationType, 'NONE');
    assert.equal(m.Properties.Integration.Type, 'MOCK');
    assert.deepEqual(m.Properties.Integration.RequestTemplates, { 'application/json': '{"statusCode": 200}' });
    assert.equal(m.Properties.Integration.IntegrationResponses[0].StatusCode, '200');
  }
});

test('WAF: ステージのスロットリングは低め', () => {
  const t = withWaf();
  t.hasResourceProperties('AWS::ApiGateway::Stage', {
    StageName: 'sandbox',
    MethodSettings: Match.arrayWith([
      Match.objectLike({ HttpMethod: '*', ResourcePath: '/*', ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 }),
    ]),
  });
});

test('WAF: API Gateway のアカウント全体の設定 (CloudWatch 用ロール) を作らず、ステージのログも出さない', () => {
  const t = withWaf();
  t.resourceCountIs('AWS::ApiGateway::Account', 0);
  const stage = resourcesOf(t, 'AWS::ApiGateway::Stage')[0];
  assert.equal(stage.Properties.AccessLogSetting, undefined);
  for (const ms of stage.Properties.MethodSettings ?? []) {
    assert.equal(ms.LoggingLevel, undefined);
    assert.ok(!ms.DataTraceEnabled, `DataTraceEnabled: ${ms.DataTraceEnabled}`);
  }
  const roles = resourcesOf(t, 'AWS::IAM::Role').filter((r) =>
    JSON.stringify(r.Properties.AssumeRolePolicyDocument).includes('apigateway.amazonaws.com'),
  );
  assert.equal(roles.length, 0);
});

function webAcl(t: Template): Record<string, any> {
  const acls = resourcesOf(t, 'AWS::WAFv2::WebACL');
  assert.equal(acls.length, 1);
  return acls[0].Properties;
}

function ruleNamed(acl: Record<string, any>, name: string): Record<string, any> {
  const r = acl.Rules.find((x: any) => x.Name === name);
  assert.ok(r, `ルール ${name} が無い: ${acl.Rules.map((x: any) => x.Name).join(', ')}`);
  return r;
}

test('WAF: WebACL は REGIONAL、既定の action は ALLOW、ルールは 3 つ', () => {
  const acl = webAcl(withWaf());
  assert.equal(acl.Name, 'arata-sandbox');
  assert.equal(acl.Scope, 'REGIONAL');
  assert.deepEqual(acl.DefaultAction, { Allow: {} });
  assert.deepEqual(acl.Rules.map((r: any) => r.Name), ['login-rate-limit', 'AWSManagedRulesKnownBadInputsRuleSet', 'AWSManagedRulesCommonRuleSet']);
  const priorities = acl.Rules.map((r: any) => r.Priority);
  assert.equal(new Set(priorities).size, priorities.length, '優先度が重複している');
});

test('WAF: CommonRuleSet は一部のルールだけ COUNT に上書きし、残りは BLOCK のまま', () => {
  const r = ruleNamed(webAcl(withWaf()), 'AWSManagedRulesCommonRuleSet');
  assert.deepEqual(r.OverrideAction, { None: {} });
  assert.equal(r.Statement.ManagedRuleGroupStatement.VendorName, 'AWS');
  assert.equal(r.Statement.ManagedRuleGroupStatement.Name, 'AWSManagedRulesCommonRuleSet');
  const overrides = r.Statement.ManagedRuleGroupStatement.RuleActionOverrides;
  assert.deepEqual(
    overrides.map((o: any) => o.Name).sort(),
    ['NoUserAgent_HEADER', 'SizeRestrictions_BODY', 'SizeRestrictions_QUERYSTRING'],
  );
  for (const o of overrides) assert.deepEqual(o.ActionToUse, { Count: {} });
});

test('WAF: KnownBadInputsRuleSet は全体を COUNT', () => {
  const r = ruleNamed(webAcl(withWaf()), 'AWSManagedRulesKnownBadInputsRuleSet');
  assert.deepEqual(r.OverrideAction, { Count: {} });
  assert.equal(r.Statement.ManagedRuleGroupStatement.Name, 'AWSManagedRulesKnownBadInputsRuleSet');
  assert.equal(r.Statement.ManagedRuleGroupStatement.RuleActionOverrides, undefined);
});

test('WAF: レートベースのルールは /login に絞り、低い値で BLOCK', () => {
  const r = ruleNamed(webAcl(withWaf()), 'login-rate-limit');
  assert.deepEqual(r.Action, { Block: {} });
  const rate = r.Statement.RateBasedStatement;
  assert.equal(rate.AggregateKeyType, 'IP');
  assert.equal(rate.Limit, 10, 'WAF の下限 (10)');
  assert.equal(rate.EvaluationWindowSec, 60);
  // REST API の URI にはステージ名が付く (/sandbox/login) ので、末尾で一致させる
  assert.deepEqual(rate.ScopeDownStatement, {
    ByteMatchStatement: {
      FieldToMatch: { UriPath: {} },
      PositionalConstraint: 'ENDS_WITH',
      SearchString: '/login',
      TextTransformations: [{ Priority: 0, Type: 'LOWERCASE' }],
    },
  });
});

test('WAF: ルールと WebACL は CloudWatch のメトリクスを持ち、サンプルは取らない', () => {
  const acl = webAcl(withWaf());
  for (const v of [acl.VisibilityConfig, ...acl.Rules.map((r: any) => r.VisibilityConfig)]) {
    assert.equal(v.CloudWatchMetricsEnabled, true);
    assert.equal(v.SampledRequestsEnabled, false);
    assert.ok(v.MetricName);
  }
});

test('WAF: WebACL を API のステージに関連付ける (ステージができてから)', () => {
  const t = withWaf();
  const assocs = t.findResources('AWS::WAFv2::WebACLAssociation');
  assert.equal(Object.keys(assocs).length, 1);
  const assoc = Object.values(assocs)[0];
  const stageId = Object.keys(t.findResources('AWS::ApiGateway::Stage'))[0];
  const aclId = Object.keys(t.findResources('AWS::WAFv2::WebACL'))[0];
  assert.deepEqual(assoc.Properties.WebACLArn, { 'Fn::GetAtt': [aclId, 'Arn'] });
  const arn = JSON.stringify(assoc.Properties.ResourceArn);
  assert.ok(arn.includes(':apigateway:') && arn.includes('/restapis/') && arn.includes('/stages/'), arn);
  assert.ok([assoc.DependsOn].flat().includes(stageId), `ステージ ${stageId} に依存しない: ${assoc.DependsOn}`);
});

test('WAF: ログは aws-waf-logs-<prefix> に出し、保持は設定の日数、destroy で消える', () => {
  const t = withWaf();
  t.hasResource('AWS::Logs::LogGroup', {
    Properties: { LogGroupName: 'aws-waf-logs-arata-sandbox', RetentionInDays: 7 },
    DeletionPolicy: 'Delete',
    UpdateReplacePolicy: 'Delete',
  });
});

test('WAF: ログの設定は authorization と cookie のヘッダーを落とし、ロググループの ARN (末尾の :* なし) を指す', () => {
  const t = withWaf();
  const cfgs = resourcesOf(t, 'AWS::WAFv2::LoggingConfiguration');
  assert.equal(cfgs.length, 1);
  const cfg = cfgs[0].Properties;
  assert.deepEqual(cfg.RedactedFields, [{ SingleHeader: { Name: 'authorization' } }, { SingleHeader: { Name: 'cookie' } }]);
  const dest = JSON.stringify(cfg.LogDestinationConfigs);
  assert.ok(dest.includes('log-group:aws-waf-logs-arata-sandbox'), dest);
  assert.ok(!dest.includes(':*'), dest);
});

test('WAF: ログの配信の許可はロググループに絞ったリソースポリシーで、送り元のアカウントを条件にする', () => {
  const t = withWaf();
  const policies = resourcesOf(t, 'AWS::Logs::ResourcePolicy');
  assert.equal(policies.length, 1);
  const doc = JSON.parse(JSON.stringify(policies[0].Properties.PolicyDocument));
  const text = JSON.stringify(doc);
  assert.ok(text.includes('delivery.logs.amazonaws.com'), text);
  assert.ok(text.includes('log-group:aws-waf-logs-arata-sandbox:log-stream:*'), text);
  assert.ok(text.includes('aws:SourceAccount') && text.includes('123456789012'), text);
  assert.ok(!text.includes('"Resource":"*"'), text);
  const cfgId = Object.keys(t.findResources('AWS::WAFv2::LoggingConfiguration'))[0];
  const cfg = t.toJSON().Resources[cfgId];
  const policyId = Object.keys(t.findResources('AWS::Logs::ResourcePolicy'))[0];
  assert.ok([cfg.DependsOn].flat().includes(policyId), 'ログの設定はリソースポリシーの後に作る');
});

test('WAF: ApiUrl・WebAclArn・WafLogGroupName を出力する', () => {
  const outputs = withWaf().toJSON().Outputs as Record<string, any>;
  for (const name of ['ApiUrl', 'WebAclArn', 'WafLogGroupName']) assert.ok(outputs[name], `Outputs.${name} が無い`);
  assert.deepEqual(Object.keys(outputs).filter((k) => k.includes('Endpoint')), [], 'RestApi の自動の出力 (ApiUrl と重複) は出さない');
});

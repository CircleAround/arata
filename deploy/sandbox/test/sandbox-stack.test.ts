import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { parseConfig } from '../lib/config.ts';
import { SandboxStack, buildSandbox } from '../lib/sandbox-stack.ts';

const examplePath = fileURLToPath(new URL('../config.example.json', import.meta.url));

// cdk.json と同じく、CloudFormation の検証の警告をエラーにする (deploy して初めて分かる誤りを synth で止める)
function newApp(): App {
  return new App({ context: { '@aws-cdk/core:validateAgainstDefaultRules': true } });
}

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
      Principal: { AWS: { 'Fn::Join': ['', ['arn:', { Ref: 'AWS::Partition' }, ':iam::111122223333:root']] } },
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

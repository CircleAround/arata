import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ConfigError, DEFAULT_PREFIX, loadConfig, parseConfig } from '../lib/config.ts';

const examplePath = new URL('../config.example.json', import.meta.url);

function example(): Record<string, any> {
  return JSON.parse(readFileSync(examplePath, 'utf8'));
}

function errorsOf(fn: () => unknown): string[] {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ConfigError, `ConfigError ではない: ${e}`);
    return e.problems;
  }
  assert.fail('エラーにならなかった');
}

test('config.example.json は検証を通る', () => {
  const c = parseConfig(example());
  assert.equal(c.account, '123456789012');
  assert.equal(c.prefix, 'arata-sandbox');
  assert.equal(c.testUsers.length, 2);
  assert.equal(c.externalRole.trustedAccountId, '111122223333');
});

test('prefix を省略すると既定の prefix になる', () => {
  const raw = example();
  delete raw.prefix;
  assert.equal(parseConfig(raw).prefix, DEFAULT_PREFIX);
});

test('必須の項目が無ければ、その名前を挙げてエラーにする', () => {
  const raw = example();
  delete raw.account;
  delete raw.guardDuty;
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.includes('account') && p.includes('必須')), problems.join('\n'));
  assert.ok(problems.some((p) => p.includes('guardDuty') && p.includes('必須')), problems.join('\n'));
});

test('誤りはまとめて全部報告する', () => {
  const raw = example();
  raw.account = '12345';
  raw.externalRole.trustedAccountId = 'abc';
  raw.nginxLogGroup.retentionDays = 8;
  const problems = errorsOf(() => parseConfig(raw));
  assert.equal(problems.length, 3, problems.join('\n'));
  assert.ok(problems.some((p) => p.startsWith('account:') && p.includes('12 桁')));
  assert.ok(problems.some((p) => p.startsWith('externalRole.trustedAccountId:')));
  assert.ok(problems.some((p) => p.startsWith('nginxLogGroup.retentionDays:') && p.includes('7')));
});

test('未知のキーは打ち間違いとしてエラーにする', () => {
  const raw = example();
  raw.guardduty = { enabled: true };
  raw.accessAnalyzer.enable = true;
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.includes('guardduty') && p.includes('未知')), problems.join('\n'));
  assert.ok(problems.some((p) => p.includes('accessAnalyzer.enable') && p.includes('未知')), problems.join('\n'));
});

test('型の誤り', () => {
  const raw = example();
  raw.guardDuty.enabled = 'yes';
  raw.testUsers = {};
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.startsWith('guardDuty.enabled:') && p.includes('真偽値')), problems.join('\n'));
  assert.ok(problems.some((p) => p.startsWith('testUsers:') && p.includes('配列')), problems.join('\n'));
});

test('試験ユーザーの名前は重複と使えない文字を弾く', () => {
  const raw = example();
  raw.testUsers = [
    { name: 'alice', consolePassword: true, accessKey: false },
    { name: 'alice', consolePassword: false, accessKey: false },
    { name: 'bad name!', consolePassword: false, accessKey: false },
  ];
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.startsWith('testUsers[1].name:') && p.includes('重複')), problems.join('\n'));
  assert.ok(problems.some((p) => p.startsWith('testUsers[2].name:')), problems.join('\n'));
});

test('IAM ユーザー名の長さ (prefix を含めて 64 文字) を超えればエラー', () => {
  const raw = example();
  raw.testUsers = [{ name: 'x'.repeat(60), consolePassword: false, accessKey: false }];
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.startsWith('testUsers[0].name:') && p.includes('64')), problems.join('\n'));
});

test('bedrock を有効にするとコピー元の ARN が要る', () => {
  const raw = example();
  raw.bedrock = { enabled: true };
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.startsWith('bedrock.modelSourceArn:')), problems.join('\n'));

  raw.bedrock = { enabled: true, modelSourceArn: 'not-an-arn' };
  const problems2 = errorsOf(() => parseConfig(raw));
  assert.ok(problems2.some((p) => p.startsWith('bedrock.modelSourceArn:') && p.includes('arn:')), problems2.join('\n'));
});

test('bedrock が無効ならコピー元の ARN は省略できる', () => {
  const raw = example();
  raw.bedrock = { enabled: false };
  assert.equal(parseConfig(raw).bedrock.enabled, false);
});

test('信頼する主体は ARN でなければならない', () => {
  const raw = example();
  raw.readonlyRole.trustedPrincipalArn = '123456789012';
  const problems = errorsOf(() => parseConfig(raw));
  assert.ok(problems.some((p) => p.startsWith('readonlyRole.trustedPrincipalArn:')), problems.join('\n'));
});

test('トップレベルがオブジェクトでなければエラー', () => {
  const problems = errorsOf(() => parseConfig([]));
  assert.equal(problems.length, 1);
});

test('loadConfig: ファイルが無い・JSON でない場合はパスを含むエラー', () => {
  const dir = mkdtempSync(join(tmpdir(), 'arata-sandbox-'));
  const missing = join(dir, 'missing.json');
  assert.throws(() => loadConfig(missing), (e: unknown) => e instanceof ConfigError && e.message.includes(missing));

  const broken = join(dir, 'broken.json');
  writeFileSync(broken, '{ "account": ');
  assert.throws(() => loadConfig(broken), (e: unknown) => e instanceof ConfigError && e.message.includes('JSON'));
});

test('loadConfig: パスが指定されていなければ渡し方を案内する', () => {
  assert.throws(() => loadConfig(undefined), (e: unknown) => e instanceof ConfigError && e.message.includes('-c config='));
});

test('waf は必須で、enabled は真偽値 (暗黙の既定を持たない)', () => {
  assert.equal(parseConfig(example()).waf.enabled, false, 'config.example.json は false (費用がかかるので試験のときだけ有効にする)');

  const missing = example();
  delete missing.waf;
  assert.ok(errorsOf(() => parseConfig(missing)).some((p) => p.startsWith('waf:') && p.includes('必須')));

  const noEnabled = example();
  noEnabled.waf = {};
  assert.ok(errorsOf(() => parseConfig(noEnabled)).some((p) => p.startsWith('waf.enabled:') && p.includes('必須')));

  const wrongType = example();
  wrongType.waf = { enabled: 'yes' };
  assert.ok(errorsOf(() => parseConfig(wrongType)).some((p) => p.startsWith('waf.enabled:') && p.includes('真偽値')));

  const unknown = example();
  unknown.waf = { enabled: true, rateLimit: 10 };
  assert.ok(errorsOf(() => parseConfig(unknown)).some((p) => p.startsWith('waf.rateLimit:') && p.includes('未知')));

  const on = example();
  on.waf = { enabled: true };
  assert.equal(parseConfig(on).waf.enabled, true);
});

test('secretAccess は必須で、enabled は真偽値 (暗黙の既定を持たない)', () => {
  assert.equal(parseConfig(example()).secretAccess.enabled, false, 'config.example.json は false (シークレットは月額の費用がかかる)');

  const missing = example();
  delete missing.secretAccess;
  assert.ok(errorsOf(() => parseConfig(missing)).some((p) => p.startsWith('secretAccess:') && p.includes('必須')));

  const wrongType = example();
  wrongType.secretAccess = { enabled: 1 };
  assert.ok(errorsOf(() => parseConfig(wrongType)).some((p) => p.startsWith('secretAccess.enabled:') && p.includes('真偽値')));

  const on = example();
  on.secretAccess = { enabled: true };
  assert.equal(parseConfig(on).secretAccess.enabled, true);
});

test('costAnomaly は必須で、enabled は真偽値 (暗黙の既定を持たない)', () => {
  assert.equal(parseConfig(example()).costAnomaly.enabled, false, 'config.example.json は false (アカウントに既にモニターがあることがある)');

  const missing = example();
  delete missing.costAnomaly;
  assert.ok(errorsOf(() => parseConfig(missing)).some((p) => p.startsWith('costAnomaly:') && p.includes('必須')));

  const wrongType = example();
  wrongType.costAnomaly = { enabled: 'yes' };
  assert.ok(errorsOf(() => parseConfig(wrongType)).some((p) => p.startsWith('costAnomaly.enabled:') && p.includes('真偽値')));

  const on = example();
  on.costAnomaly = { enabled: true };
  assert.equal(parseConfig(on).costAnomaly.enabled, true);
});

test('waf.challenge / waf.captcha は真偽値で、既定は false。waf.enabled が false のまま true にすると誤り (効かないため)', () => {
  const ex = parseConfig(example());
  assert.equal(ex.waf.challenge, false);
  assert.equal(ex.waf.captcha, false);

  const omitted = example();
  omitted.waf = { enabled: true };
  assert.deepEqual(parseConfig(omitted).waf, { enabled: true, challenge: false, captcha: false });

  const on = example();
  on.waf = { enabled: true, challenge: true, captcha: true };
  assert.deepEqual(parseConfig(on).waf, { enabled: true, challenge: true, captcha: true });

  const wrongType = example();
  wrongType.waf = { enabled: true, challenge: 'yes' };
  assert.ok(errorsOf(() => parseConfig(wrongType)).some((p) => p.startsWith('waf.challenge:') && p.includes('真偽値')));

  const disabled = example();
  disabled.waf = { enabled: false, captcha: true };
  assert.ok(errorsOf(() => parseConfig(disabled)).some((p) => p.startsWith('waf.captcha:') && p.includes('waf.enabled')));
});

test('storeBucket は必須で、enabled は真偽値 (暗黙の既定を持たない)', () => {
  assert.equal(parseConfig(example()).storeBucket.enabled, false, 'config.example.json は false (S3 ストアの試験のときだけ有効にする)');

  const missing = example();
  delete missing.storeBucket;
  assert.ok(errorsOf(() => parseConfig(missing)).some((p) => p.startsWith('storeBucket:') && p.includes('必須')));

  const wrongType = example();
  wrongType.storeBucket = { enabled: 'yes' };
  assert.ok(errorsOf(() => parseConfig(wrongType)).some((p) => p.startsWith('storeBucket.enabled:') && p.includes('真偽値')));

  const on = example();
  on.storeBucket = { enabled: true };
  assert.equal(parseConfig(on).storeBucket.enabled, true);
});

function githubOidc(raw: Record<string, any>): void {
  raw.storeBucket = { enabled: true };
  raw.githubOidc = { enabled: true, repository: 'example-org/example-audit', branch: 'main', createProvider: true, storePrefix: 'example' };
}

test('githubOidc: 無効なら他のキーは要らず、有効なら値を返す', () => {
  assert.deepEqual(parseConfig(example()).githubOidc, { enabled: false });
  const raw = example();
  githubOidc(raw);
  assert.deepEqual(parseConfig(raw).githubOidc, raw.githubOidc);
});

test('githubOidc: 書き忘れは必須のエラーにする (暗黙の既定を持たない)', () => {
  const raw = example();
  delete raw.githubOidc;
  assert.ok(errorsOf(() => parseConfig(raw)).some((p) => p.includes('githubOidc') && p.includes('必須')));
});

test('githubOidc: 有効なら repository / branch / createProvider / storePrefix が必須', () => {
  const raw = example();
  raw.storeBucket = { enabled: true };
  raw.githubOidc = { enabled: true };
  const problems = errorsOf(() => parseConfig(raw));
  for (const k of ['repository', 'branch', 'createProvider', 'storePrefix']) {
    assert.ok(problems.some((p) => p.startsWith(`githubOidc.${k}:`) && p.includes('必須')), problems.join('\n'));
  }
});

test('githubOidc: 信頼を広げるワイルドカードは受け付けない', () => {
  for (const [key, value] of [['repository', 'example-org/*'], ['repository', 'example-audit'], ['branch', '*'], ['branch', 'release/*'], ['storePrefix', 'a/*'], ['storePrefix', 'a/']]) {
    const raw = example();
    githubOidc(raw);
    raw.githubOidc[key] = value;
    const problems = errorsOf(() => parseConfig(raw));
    assert.ok(problems.some((p) => p.startsWith(`githubOidc.${key}:`)), `${key}=${value}: ${problems.join('\n')}`);
  }
});

test('githubOidc: ストアのバケットが無ければエラーにする', () => {
  const raw = example();
  githubOidc(raw);
  raw.storeBucket = { enabled: false };
  assert.ok(errorsOf(() => parseConfig(raw)).some((p) => p.startsWith('githubOidc.enabled:') && p.includes('storeBucket')));
});

test('githubOidc: 読み取り専用ロールがアカウントを信頼していなければエラーにする (実行用ロールが引き受けられない)', () => {
  const raw = example();
  githubOidc(raw);
  raw.readonlyRole.trustedPrincipalArn = 'arn:aws:iam::123456789012:role/developer';
  assert.ok(errorsOf(() => parseConfig(raw)).some((p) => p.startsWith('githubOidc.enabled:') && p.includes('trustedPrincipalArn')));
  raw.readonlyRole.trustedPrincipalArn = 'arn:aws:iam::111122223333:root';
  assert.ok(errorsOf(() => parseConfig(raw)).some((p) => p.startsWith('githubOidc.enabled:') && p.includes('trustedPrincipalArn')));
});

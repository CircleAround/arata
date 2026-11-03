import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseLockPackages, checkAges, runAgegate } from '../scripts/agegate.ts';

const LOCK = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      aws-cdk-lib:
        specifier: 2.274.0
        version: 2.274.0(constructs@10.8.1)

packages:

  '@types/node@24.19.2':
    resolution: {integrity: sha512-x}

  aws-cdk-lib@2.274.0:
    resolution: {integrity: sha512-y}
    peerDependencies:
      constructs: ^10.5.0

  constructs@10.8.1:
    resolution: {integrity: sha512-z}

snapshots:

  aws-cdk-lib@2.274.0(constructs@10.8.1):
    dependencies:
      constructs: 10.8.1
`;

const NOW = new Date('2026-11-01T00:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

test('pnpm-lock.yaml の packages の名前と版を読む (scope 付き・引用符付きも)', () => {
  assert.deepEqual(parseLockPackages(LOCK), [
    { name: '@types/node', version: '24.19.2' },
    { name: 'aws-cdk-lib', version: '2.274.0' },
    { name: 'constructs', version: '10.8.1' },
  ]);
});

test('packages が無いロックファイルは誤りとして扱う (fail closed)', () => {
  assert.throws(() => parseLockPackages('lockfileVersion: 9.0\n'));
});

test('公開から days 日未満の版を挙げる', async () => {
  const times: Record<string, Date> = {
    '@types/node@24.19.2': new Date(NOW.getTime() - 30 * DAY),
    'aws-cdk-lib@2.274.0': new Date(NOW.getTime() - 3 * DAY),
    'constructs@10.8.1': new Date(NOW.getTime() - 7 * DAY),
  };
  const r = await checkAges(parseLockPackages(LOCK), async (p) => times[`${p.name}@${p.version}`], NOW, 7);
  assert.deepEqual(r.tooNew.map((x) => x.name), ['aws-cdk-lib']);
  assert.deepEqual(r.errors, []);
});

test('公開時刻が取れない版は通さない', async () => {
  const r = await checkAges(parseLockPackages(LOCK), async (p) => {
    if (p.name === 'constructs') throw new Error('404');
    return undefined;
  }, NOW, 7);
  assert.equal(r.errors.length, 3);
});

test('runAgegate の終了コード: 0 = 全部古い、1 = 新しすぎる版がある、2 = 判定できない', async () => {
  const out: string[] = [];
  const log = (s: string) => out.push(s);
  const old = async () => new Date(NOW.getTime() - 30 * DAY);
  const fresh = async () => new Date(NOW.getTime() - 1 * DAY);
  const broken = async () => {
    throw new Error('network');
  };
  assert.equal(await runAgegate(LOCK, old, NOW, 7, log), 0);
  assert.equal(await runAgegate(LOCK, fresh, NOW, 7, log), 1);
  assert.ok(out.some((s) => s.includes('aws-cdk-lib@2.274.0')));
  assert.equal(await runAgegate(LOCK, broken, NOW, 7, log), 2);
  assert.equal(await runAgegate('nothing', old, NOW, 7, log), 2);
});

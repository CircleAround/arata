// pnpm-lock.yaml の全パッケージについて、npm レジストリでの公開から days 日以上経っていることを確かめる (CI 用)。
//
//   node scripts/agegate.ts [days=7]
//
// pnpm の minimumReleaseAge は版を「解決するとき」にしか効かず、`pnpm install --frozen-lockfile` はロックファイルに既にある版の
// 公開日を見ない。ロックファイルに新しすぎる版が入ってきた場合 (手で書き換えた、設定を外して解決した) を CI で止めるのがこのスクリプト。
// Go の tools/agegate と同じ考え方 (ADR 0017・0020)。判定できないものは通さない (fail closed)。依存は持たない。
// 終了コード: 0 = すべて days 日以上前、1 = 新しすぎる版がある、2 = 入力・通信のエラー。
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface LockPackage {
  name: string;
  version: string;
}

/** pnpm-lock.yaml (lockfileVersion 9) の `packages:` の見出しから名前と版を読む。 */
export function parseLockPackages(text: string): LockPackage[] {
  const lines = text.split('\n');
  const start = lines.indexOf('packages:');
  if (start < 0) throw new Error('pnpm-lock.yaml に packages: がありません');
  const pkgs: LockPackage[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line)) break; // 次のトップレベル (snapshots: など)
    const m = /^ {2}'?((?:@[^/@\s]+\/)?[^@\s']+)@([^(':\s]+)[^:]*'?:$/.exec(line);
    if (m) pkgs.push({ name: m[1], version: m[2] });
  }
  if (pkgs.length === 0) throw new Error('pnpm-lock.yaml の packages: が空です');
  return pkgs;
}

/** 公開時刻を返す。取れなければ undefined か例外。 */
export type PublishedAt = (p: LockPackage) => Promise<Date | undefined>;

export async function checkAges(
  pkgs: LockPackage[],
  publishedAt: PublishedAt,
  now: Date,
  days: number,
): Promise<{ tooNew: (LockPackage & { published: Date })[]; errors: string[] }> {
  const minAge = days * 24 * 60 * 60 * 1000;
  const tooNew: (LockPackage & { published: Date })[] = [];
  const errors: string[] = [];
  for (const p of pkgs) {
    let at: Date | undefined;
    try {
      at = await publishedAt(p);
    } catch (e) {
      errors.push(`${p.name}@${p.version}: 公開時刻を取れません: ${(e as Error).message}`);
      continue;
    }
    if (!at || Number.isNaN(at.getTime())) {
      errors.push(`${p.name}@${p.version}: 公開時刻がありません`);
      continue;
    }
    if (now.getTime() - at.getTime() < minAge) tooNew.push({ ...p, published: at });
  }
  return { tooNew, errors };
}

export async function runAgegate(
  lockText: string,
  publishedAt: PublishedAt,
  now: Date,
  days: number,
  log: (s: string) => void,
): Promise<number> {
  let pkgs: LockPackage[];
  try {
    pkgs = parseLockPackages(lockText);
  } catch (e) {
    log(`agegate: ${(e as Error).message}`);
    return 2;
  }
  const { tooNew, errors } = await checkAges(pkgs, publishedAt, now, days);
  for (const e of errors) log(`agegate: ${e}`);
  for (const p of tooNew) log(`agegate: ${p.name}@${p.version} は公開から ${days} 日経っていません (${p.published.toISOString()})`);
  if (errors.length > 0) return 2;
  if (tooNew.length > 0) return 1;
  log(`agegate: ${pkgs.length} パッケージ、すべて公開から ${days} 日以上`);
  return 0;
}

/** npm レジストリのパッケージ文書の time[version]。 */
async function registryPublishedAt(p: LockPackage): Promise<Date | undefined> {
  const url = `https://registry.npmjs.org/${p.name.replace('/', '%2f')}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const doc = (await res.json()) as { time?: Record<string, string> };
  const t = doc.time?.[p.version];
  return t ? new Date(t) : undefined;
}

// 直接実行されたときだけ動く (テストから import したときは動かない)
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const days = Number(process.argv[2] ?? '7');
  if (!Number.isInteger(days) || days < 0) {
    console.error('agegate: days は 0 以上の整数');
    process.exit(2);
  }
  const lockPath = new URL('../pnpm-lock.yaml', import.meta.url);
  process.exitCode = await runAgegate(readFileSync(lockPath, 'utf8'), registryPublishedAt, new Date(), days, (s) => console.error(s));
}

// sandbox の設定 (リポジトリの外に置く JSON。`cdk deploy -c config=<path>` で渡す) の読み込みと検証。
// 依存を増やさないため検証は手で書く。誤りは 1 つずつではなく、まとめて「場所: 何が悪いか」で報告する。
// 未知のキーは打ち間違いとしてエラーにする (arata の設定と同じ方針)。
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/** prefix を省略したときの名前。スタック名とリソース名の頭に付く。 */
export const DEFAULT_PREFIX = 'arata-sandbox';

/** CloudWatch Logs の保持期間として指定できる日数。 */
export const RETENTION_DAYS = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];

export interface TestUser {
  name: string;
  consolePassword: boolean;
  accessKey: boolean;
}

export interface SandboxConfig {
  account: string;
  region: string;
  prefix: string;
  readonlyRole: { trustedPrincipalArn: string };
  nginxLogGroup: { name: string; retentionDays: number };
  testUsers: TestUser[];
  externalRole: { trustedAccountId: string; externalId?: string };
  guardDuty: { enabled: boolean };
  accessAnalyzer: { enabled: boolean };
  bedrock: { enabled: boolean; modelSourceArn?: string };
  /**
   * 試験用の WAF (API Gateway + WebACL)。費用がかかるので試験のときだけ有効にする。
   * challenge / captcha は Challenge (GET /search) と CAPTCHA (/contact) のルールを足す (ADR 0028。省略時は false。waf.enabled のときだけ)。
   */
  waf: { enabled: boolean; challenge: boolean; captcha: boolean };
  /** 秘匿値の読み取りの試験用 (シークレット 3 つと読み手のロール。シナリオ 10)。シークレットは月額の費用がかかる。 */
  secretAccess: { enabled: boolean };
}

export class ConfigError extends Error {
  readonly problems: string[];
  constructor(problems: string[], source?: string) {
    const head = source ? `sandbox の設定 ${source} に誤りがあります:` : 'sandbox の設定に誤りがあります:';
    super([head, ...problems.map((p) => `  - ${p}`)].join('\n'));
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

/**
 * 設定ファイルを読み、検証する。path は `-c config=<path>` の値 (相対パスはカレントディレクトリから)。
 */
export function loadConfig(path: string | undefined): SandboxConfig {
  if (!path) {
    throw new ConfigError([
      '設定ファイルが指定されていません。`cdk deploy -c config=<path>` で渡してください (例は config.example.json)',
    ]);
  }
  const abs = resolve(path);
  let text: string;
  try {
    text = readFileSync(abs, 'utf8');
  } catch (e) {
    throw new ConfigError([`読めません: ${(e as Error).message}`], abs);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError([`JSON として読めません: ${(e as Error).message}`], abs);
  }
  try {
    return parseConfig(raw);
  } catch (e) {
    if (e instanceof ConfigError) throw new ConfigError(e.problems, abs);
    throw e;
  }
}

type Obj = Record<string, unknown>;

/** 検証の途中経過。問題を貯め、最後にまとめて投げる。 */
class Checker {
  problems: string[] = [];

  add(path: string, msg: string): void {
    this.problems.push(`${path}: ${msg}`);
  }

  /** オブジェクトであることと、未知のキーが無いことを確かめる。 */
  object(v: unknown, path: string, keys: string[]): Obj | undefined {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) {
      this.add(path, 'オブジェクトを指定してください');
      return undefined;
    }
    for (const k of Object.keys(v)) {
      if (!keys.includes(k)) this.add(join(path, k), `未知のキーです (使えるキー: ${keys.join(', ')})`);
    }
    return v as Obj;
  }

  required(o: Obj, key: string, path: string): unknown {
    if (o[key] === undefined) {
      this.add(join(path, key), '必須です');
      return undefined;
    }
    return o[key];
  }

  string(o: Obj, key: string, path: string, opts: { optional?: boolean; pattern?: RegExp; hint?: string } = {}): string | undefined {
    const v = opts.optional ? o[key] : this.required(o, key, path);
    if (v === undefined) return undefined;
    if (typeof v !== 'string') {
      this.add(join(path, key), '文字列を指定してください');
      return undefined;
    }
    if (opts.pattern && !opts.pattern.test(v)) {
      this.add(join(path, key), `${JSON.stringify(v)} は使えません (${opts.hint})`);
      return undefined;
    }
    return v;
  }

  boolean(o: Obj, key: string, path: string, opts: { optional?: boolean } = {}): boolean | undefined {
    const v = opts.optional ? o[key] : this.required(o, key, path);
    if (v === undefined) return undefined;
    if (typeof v !== 'boolean') {
      this.add(join(path, key), '真偽値 (true / false) を指定してください');
      return undefined;
    }
    return v;
  }
}

function join(path: string, key: string): string {
  return path ? `${path}.${key}` : key;
}

const ACCOUNT_ID = /^\d{12}$/;
const REGION = /^[a-z]{2}(-[a-z]+)+-\d$/;
const PREFIX = /^[a-z][a-z0-9-]{0,31}$/;
const IAM_NAME = /^[\w+=,.@-]+$/;
const PRINCIPAL_ARN = /^arn:aws[a-z-]*:(iam|sts)::\d{12}:.+$/;
const ARN = /^arn:aws[a-z-]*:[a-z0-9-]+:.*$/;
const LOG_GROUP = /^[\w\-./#]{1,512}$/;
const EXTERNAL_ID = /^[\w+=,.@:/-]{2,1224}$/;

/** IAM ユーザー名の上限。 */
const MAX_USER_NAME = 64;

/**
 * JSON を読んだ値を検証し、SandboxConfig にする。誤りがあれば ConfigError (problems に全部)。
 */
export function parseConfig(raw: unknown): SandboxConfig {
  const c = new Checker();
  const top = c.object(raw, '(トップレベル)', [
    'account',
    'region',
    'prefix',
    'readonlyRole',
    'nginxLogGroup',
    'testUsers',
    'externalRole',
    'guardDuty',
    'accessAnalyzer',
    'bedrock',
    'waf',
    'secretAccess',
  ]);
  if (!top) throw new ConfigError(c.problems);
  // トップレベルの未知のキーは「(トップレベル).x」ではなく「x」と出す
  c.problems = c.problems.map((p) => p.replace(/^\(トップレベル\)\./, ''));

  const account = c.string(top, 'account', '', { pattern: ACCOUNT_ID, hint: '12 桁の AWS アカウント ID' });
  const region = c.string(top, 'region', '', { pattern: REGION, hint: '例 ap-northeast-1' });
  const prefix =
    c.string(top, 'prefix', '', { optional: true, pattern: PREFIX, hint: '英小文字で始まる英小文字・数字・ハイフン、32 文字まで' }) ??
    (top.prefix === undefined ? DEFAULT_PREFIX : undefined);

  // readonlyRole
  let trustedPrincipalArn: string | undefined;
  const rr = c.required(top, 'readonlyRole', '');
  if (rr !== undefined) {
    const o = c.object(rr, 'readonlyRole', ['trustedPrincipalArn']);
    if (o) {
      trustedPrincipalArn = c.string(o, 'trustedPrincipalArn', 'readonlyRole', {
        pattern: PRINCIPAL_ARN,
        hint: 'IAM の主体の ARN (例 arn:aws:iam::123456789012:root)',
      });
    }
  }

  // nginxLogGroup
  let logGroupName: string | undefined;
  let retentionDays: number | undefined;
  const lg = c.required(top, 'nginxLogGroup', '');
  if (lg !== undefined) {
    const o = c.object(lg, 'nginxLogGroup', ['name', 'retentionDays']);
    if (o) {
      logGroupName = c.string(o, 'name', 'nginxLogGroup', { pattern: LOG_GROUP, hint: 'ロググループ名に使える文字、512 文字まで' });
      const r = c.required(o, 'retentionDays', 'nginxLogGroup');
      if (r !== undefined) {
        if (typeof r !== 'number' || !RETENTION_DAYS.includes(r)) {
          c.add('nginxLogGroup.retentionDays', `${JSON.stringify(r)} は使えません (CloudWatch Logs の保持日数: ${RETENTION_DAYS.slice(0, 6).join(', ')} など。試験には 7 程度)`);
        } else {
          retentionDays = r;
        }
      }
    }
  }

  // testUsers
  const users: TestUser[] = [];
  const tu = c.required(top, 'testUsers', '');
  if (tu !== undefined) {
    if (!Array.isArray(tu)) {
      c.add('testUsers', '配列を指定してください (試験ユーザーが不要なら [])');
    } else {
      const seen = new Set<string>();
      tu.forEach((u, i) => {
        const path = `testUsers[${i}]`;
        const o = c.object(u, path, ['name', 'consolePassword', 'accessKey']);
        if (!o) return;
        let name = c.string(o, 'name', path, { pattern: IAM_NAME, hint: 'IAM ユーザー名に使える文字 (英数字と +=,.@_-)' });
        if (name !== undefined && prefix !== undefined && `${prefix}-${name}`.length > MAX_USER_NAME) {
          c.add(`${path}.name`, `prefix を付けた名前 ${prefix}-${name} が IAM ユーザー名の上限 ${MAX_USER_NAME} 文字を超えます`);
          name = undefined;
        }
        if (name !== undefined && seen.has(name)) {
          c.add(`${path}.name`, `${name} が重複しています`);
          name = undefined;
        }
        if (name !== undefined) seen.add(name);
        const consolePassword = c.boolean(o, 'consolePassword', path);
        const accessKey = c.boolean(o, 'accessKey', path);
        if (name !== undefined && consolePassword !== undefined && accessKey !== undefined) {
          users.push({ name, consolePassword, accessKey });
        }
      });
    }
  }

  // externalRole
  let trustedAccountId: string | undefined;
  let externalId: string | undefined;
  const er = c.required(top, 'externalRole', '');
  if (er !== undefined) {
    const o = c.object(er, 'externalRole', ['trustedAccountId', 'externalId']);
    if (o) {
      trustedAccountId = c.string(o, 'trustedAccountId', 'externalRole', { pattern: ACCOUNT_ID, hint: '12 桁の AWS アカウント ID' });
      externalId = c.string(o, 'externalId', 'externalRole', { optional: true, pattern: EXTERNAL_ID, hint: '2〜1224 文字の英数字と +=,.@:/-' });
    }
  }

  // 任意の機能。暗黙の既定を持たないよう enabled は必須
  const toggle = (key: 'guardDuty' | 'accessAnalyzer' | 'secretAccess'): boolean | undefined => {
    const v = c.required(top, key, '');
    if (v === undefined) return undefined;
    const o = c.object(v, key, ['enabled']);
    return o ? c.boolean(o, 'enabled', key) : undefined;
  };
  const guardDuty = toggle('guardDuty');
  const accessAnalyzer = toggle('accessAnalyzer');
  const secretAccess = toggle('secretAccess');

  // WAF。challenge / captcha は WAF の試験の追加のルール (省略時は false)。waf.enabled が false のまま true にしても効かないので誤りにする
  let waf: boolean | undefined;
  let challenge = false;
  let captcha = false;
  const wv = c.required(top, 'waf', '');
  if (wv !== undefined) {
    const o = c.object(wv, 'waf', ['enabled', 'challenge', 'captcha']);
    if (o) {
      waf = c.boolean(o, 'enabled', 'waf');
      for (const k of ['challenge', 'captcha'] as const) {
        const b = c.boolean(o, k, 'waf', { optional: true });
        if (b === true && waf === false) c.add(`waf.${k}`, 'waf.enabled が true のときだけ使えます');
        if (b !== undefined) {
          if (k === 'challenge') challenge = b;
          else captcha = b;
        }
      }
    }
  }

  let bedrockEnabled: boolean | undefined;
  let modelSourceArn: string | undefined;
  const br = c.required(top, 'bedrock', '');
  if (br !== undefined) {
    const o = c.object(br, 'bedrock', ['enabled', 'modelSourceArn']);
    if (o) {
      bedrockEnabled = c.boolean(o, 'enabled', 'bedrock');
      if (bedrockEnabled === true && o.modelSourceArn === undefined) {
        c.add('bedrock.modelSourceArn', 'bedrock.enabled が true のときは必須です (コピー元の基盤モデルかシステム定義の推論プロファイルの ARN)');
      } else {
        modelSourceArn = c.string(o, 'modelSourceArn', 'bedrock', { optional: true, pattern: ARN, hint: 'arn: で始まる ARN' });
      }
    }
  }

  if (c.problems.length > 0) throw new ConfigError(c.problems);
  return {
    account: account!,
    region: region!,
    prefix: prefix!,
    readonlyRole: { trustedPrincipalArn: trustedPrincipalArn! },
    nginxLogGroup: { name: logGroupName!, retentionDays: retentionDays! },
    testUsers: users,
    externalRole: externalId === undefined ? { trustedAccountId: trustedAccountId! } : { trustedAccountId: trustedAccountId!, externalId },
    guardDuty: { enabled: guardDuty! },
    accessAnalyzer: { enabled: accessAnalyzer! },
    bedrock: modelSourceArn === undefined ? { enabled: bedrockEnabled! } : { enabled: bedrockEnabled!, modelSourceArn },
    waf: { enabled: waf!, challenge, captcha },
    secretAccess: { enabled: secretAccess! },
  };
}

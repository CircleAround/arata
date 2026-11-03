// sandbox = arata の試験用に条件を整えた、開発用 AWS アカウント上の環境。
// arata の各チェックに中身が出る状態 (MFA の無いユーザー、外部アカウントから引き受けられるロール、nginx のロググループなど) を作る。
// 置くものには実権限を付けない (漏れても何もできない)。cdk destroy で全部消える (Retain / Snapshot を持たない。CDK の既定が Retain のロググループとシークレットだけ明示で DESTROY)。
import { fileURLToPath } from 'node:url';
import { App, CfnOutput, Fn, RemovalPolicy, SecretValue, Stack, Tags, type StackProps } from 'aws-cdk-lib';
import { CfnInclude } from 'aws-cdk-lib/cloudformation-include';
import * as accessanalyzer from 'aws-cdk-lib/aws-accessanalyzer';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import type { Construct } from 'constructs';
import { loadConfig, type SandboxConfig } from './config.ts';
import { SandboxWaf } from './waf.ts';

/** 顧客に配る読み取り専用ロール。sandbox はこれをそのまま取り込む (定義は 1 か所。ADR 0020)。 */
export const READONLY_ROLE_TEMPLATE = fileURLToPath(new URL('../../iam/readonly-role.yaml', import.meta.url));

export interface SandboxStackProps extends StackProps {
  config: SandboxConfig;
}

export class SandboxStack extends Stack {
  constructor(scope: Construct, id: string, props: SandboxStackProps) {
    const { config } = props;
    // env を設定のアカウントに固定する。別アカウントの認証情報で deploy しようとすると CDK が止める
    super(scope, id, { ...props, env: { account: config.account, region: config.region } });
    const p = config.prefix;
    Tags.of(this).add('arata:sandbox', p);

    // 1. 読み取り専用ロール (配布用の素の CloudFormation を取り込む)。
    //    CfnInclude の parameters で置換すると条件式が定数になり検証で警告が出るので、パラメータのまま既定値だけを設定に合わせる
    const readonly = new CfnInclude(this, 'ReadonlyRole', { templateFile: READONLY_ROLE_TEMPLATE });
    const defaults: Record<string, string> = {
      RoleName: `${p}-readonly`,
      TrustedPrincipalArn: config.readonlyRole.trustedPrincipalArn,
      ExternalId: '',
      RolesAnywhereTrustAnchorArn: '',
    };
    for (const [name, value] of Object.entries(defaults)) {
      readonly.getParameter(name).default = value;
    }
    const readonlyRole = readonly.getResource('Role') as iam.CfnRole;

    // 2. nginx のアクセスログ (シナリオがここに行を入れ、arata の cloudwatch-logs ソースが読む)
    const logGroup = new logs.LogGroup(this, 'NginxAccessLog', {
      logGroupName: config.nginxLogGroup.name,
      retention: config.nginxLogGroup.retentionDays as logs.RetentionDays,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // 3. 試験用 IAM ユーザー。ポリシー・グループは付けない (credential_hygiene に中身を出すためだけに居る)
    for (const u of config.testUsers) {
      const id = `TestUser-${u.name}`;
      let password: SecretValue | undefined;
      if (u.consolePassword) {
        // パスワードは Secrets Manager で生成し、動的参照で渡す (テンプレート・出力・リポジトリに値が出ない)。MFA は付けない
        const secret = new secretsmanager.Secret(this, `${id}-Password`, {
          description: `arata sandbox: console password of ${p}-${u.name} (test user without MFA; never used)`,
          generateSecretString: { passwordLength: 32 },
          removalPolicy: RemovalPolicy.DESTROY,
        });
        password = secret.secretValue;
      }
      const user = new iam.User(this, id, {
        userName: `${p}-${u.name}`,
        password,
        passwordResetRequired: password ? false : undefined,
      });
      if (u.accessKey) {
        // 秘密値 (SecretAccessKey) は参照しない。出力にも Secrets Manager にも置かない
        new iam.CfnAccessKey(this, `${id}-AccessKey`, { userName: user.userName });
      }
    }

    // 4. 外部アカウント (SaaS 役) から AssumeRole される役のロール。権限は持たない
    const externalRole = new iam.Role(this, 'ExternalRole', {
      roleName: `${p}-external`,
      description: 'arata sandbox: assumed from an external account (no permissions)',
      assumedBy: new iam.AccountPrincipal(config.externalRole.trustedAccountId),
      externalIds: config.externalRole.externalId ? [config.externalRole.externalId] : undefined,
    });

    // 5. 任意の機能
    if (config.guardDuty.enabled) {
      // リージョンに 1 つしか作れない。既に有効なアカウントでは false にする
      new guardduty.CfnDetector(this, 'GuardDuty', { enable: true });
    }
    if (config.accessAnalyzer.enabled) {
      // 外部アクセスのアナライザー (アカウント単位)。上の外部ロールの信頼が finding になる
      new accessanalyzer.CfnAnalyzer(this, 'AccessAnalyzer', { analyzerName: p, type: 'ACCOUNT' });
    }
    if (config.bedrock.enabled) {
      // aratam の bedrock プロバイダの試験用 (モデルの利用申請は手動。README)
      const profile = new bedrock.CfnApplicationInferenceProfile(this, 'InferenceProfile', {
        inferenceProfileName: p,
        description: 'arata sandbox: for testing the aratam bedrock provider',
        modelSource: { copyFrom: config.bedrock.modelSourceArn! },
      });
      new CfnOutput(this, 'InferenceProfileArn', { value: profile.attrInferenceProfileArn });
    }
    if (config.waf.enabled) {
      // WAF の修正提案の試験用 (費用がかかる。試験のときだけ。lib/waf.ts)。ログの保持は nginx のロググループと同じ日数
      new SandboxWaf(this, 'Waf', {
        prefix: p,
        retentionDays: config.nginxLogGroup.retentionDays,
        challenge: config.waf.challenge,
        captcha: config.waf.captcha,
      });
    }

    if (config.secretAccess.enabled) {
      // 秘匿値の読み取りの試験用 (シナリオ 10。secret_access)。値は生成した無意味な文字列で、実際の秘密は入れない。
      // 読み手のロールは読み取りロールと同じ主体を信頼し、権限はこのシークレットと /<prefix>/scenario-10 のパラメータの読み取りだけ。
      // SecureString のパラメータは CloudFormation で作れないので、シナリオが作って消す。復号は AWS 管理の鍵 (aws/ssm) のキーポリシーで許される
      // 名前は付けない (CloudFormation が付ける)。削除したシークレットは猶予期間 (30 日) の間同じ名前で作れず、deploy し直せなくなるため
      const secrets = [1, 2, 3].map(
        (i) =>
          new secretsmanager.Secret(this, `ScenarioSecret${i}`, {
            description: 'arata sandbox: dummy secret for the secret_access scenario (no real secret)',
            generateSecretString: { passwordLength: 16, excludePunctuation: true },
            removalPolicy: RemovalPolicy.DESTROY,
          }),
      );
      const paramArn = (suffix: string) => Stack.of(this).formatArn({ service: 'ssm', resource: 'parameter', resourceName: `${p}/scenario-10${suffix}` });
      const reader = new iam.Role(this, 'SecretReaderRole', {
        roleName: `${p}-secret-reader`,
        description: 'arata sandbox: reads the scenario-10 dummy secrets and parameters only',
        assumedBy: new iam.ArnPrincipal(config.readonlyRole.trustedPrincipalArn),
        inlinePolicies: {
          ScenarioSecretRead: new iam.PolicyDocument({
            statements: [
              new iam.PolicyStatement({ actions: ['secretsmanager:GetSecretValue'], resources: secrets.map((s) => s.secretArn) }),
              // BatchGetSecretValue は資源を指定できない。値を読めるかは GetSecretValue の権限で決まる
              new iam.PolicyStatement({ actions: ['secretsmanager:BatchGetSecretValue'], resources: ['*'] }),
              new iam.PolicyStatement({
                actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath'],
                resources: [paramArn(''), paramArn('/*')],
              }),
            ],
          }),
        },
      });
      new CfnOutput(this, 'SecretReaderRoleArn', { value: reader.roleArn });
      new CfnOutput(this, 'ScenarioSecretArns', { value: Fn.join(',', secrets.map((s) => s.secretArn)) });
      new CfnOutput(this, 'ScenarioParameterPath', { value: `/${p}/scenario-10` });
    }

    new CfnOutput(this, 'ReadonlyRoleArn', { value: readonlyRole.attrArn });
    new CfnOutput(this, 'NginxLogGroupName', { value: logGroup.logGroupName });
    new CfnOutput(this, 'ExternalRoleArn', { value: externalRole.roleArn });
    new CfnOutput(this, 'TestUserNames', { value: config.testUsers.map((u) => `${p}-${u.name}`).join(',') || '(none)' });
  }
}

/** `-c config=<path>` の設定を読み、スタック (名前は prefix) を作る。 */
export function buildSandbox(app: App, configPath: string | undefined): SandboxStack {
  const config = loadConfig(configPath);
  return new SandboxStack(app, config.prefix, { config });
}

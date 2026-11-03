// 試験用の WAF (config の waf.enabled)。WAF の修正提案 (arata の waf_review) を本物の AWS のログで確かめるためのもの。
// API Gateway (REST、mock 統合で固定の 200) に WAFv2 の WebACL (REGIONAL) を付け、ログを CloudWatch Logs の aws-waf-logs-<prefix> に出す。
// 費用は WebACL 月 5 USD + ルール 1 USD/個 + リクエスト。試験のときだけ有効にし、終わったら destroy か false に戻す (README)。
//
// API Gateway のアカウント全体の設定 (CloudWatch Logs 用のロール。AWS::ApiGateway::Account) は作らない。
// アクセスログ・実行ログは出さないので要らない (見たいのは WAF のログだけ)。
import { Arn, ArnFormat, CfnOutput, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';

/** REST API のステージ名。WAF のログの URI にはこれが頭に付く (/sandbox/login)。 */
export const WAF_STAGE_NAME = 'sandbox';

/** /login へのレート制限 (1 IP あたり、評価の窓 60 秒)。10 は WAF の下限。 */
export const LOGIN_RATE_LIMIT = 10;

/** CommonRuleSet のうち COUNT に上書きするルール (「カウントで様子を見る」段階のルールの素材)。 */
export const COMMON_RULES_IN_COUNT = ['NoUserAgent_HEADER', 'SizeRestrictions_QUERYSTRING', 'SizeRestrictions_BODY'];

export interface SandboxWafProps {
  prefix: string;
  retentionDays: number;
}

export class SandboxWaf extends Construct {
  constructor(scope: Construct, id: string, props: SandboxWafProps) {
    super(scope, id);
    const { prefix: p } = props;
    const stack = Stack.of(this);

    // 1. API Gateway。認証なし、mock 統合で固定の 200 を返す。スロットリングは低め
    const api = new apigateway.RestApi(this, 'Api', {
      restApiName: `${p}-waf`,
      description: 'arata sandbox: mock API behind the test WAF (returns a fixed 200)',
      endpointConfiguration: { types: [apigateway.EndpointType.REGIONAL] },
      cloudWatchRole: false,
      deployOptions: {
        stageName: WAF_STAGE_NAME,
        throttlingRateLimit: 10,
        throttlingBurstLimit: 20,
      },
    });
    // RestApi が自動で付ける出力 (Endpoint) は下の ApiUrl と同じ値なので外す
    api.node.tryRemoveChild('Endpoint');
    const mock = new apigateway.MockIntegration({
      requestTemplates: { 'application/json': '{"statusCode": 200}' },
      integrationResponses: [{ statusCode: '200', responseTemplates: { 'application/json': '{"ok": true}' } }],
    });
    const methodOptions: apigateway.MethodOptions = {
      authorizationType: apigateway.AuthorizationType.NONE,
      methodResponses: [{ statusCode: '200' }],
    };
    api.root.addMethod('GET', mock, methodOptions);
    api.root.addResource('health').addMethod('GET', mock, methodOptions);
    api.root.addResource('search').addMethod('GET', mock, methodOptions);
    api.root.addResource('login').addMethod('POST', mock, methodOptions);
    api.root.addResource('api').addResource('{proxy+}').addMethod('ANY', mock, methodOptions);

    // 2. WebACL。既定は ALLOW。BLOCK / COUNT / ALLOW がそれぞれ出るようにルールを組む
    const visibility = (metricName: string): wafv2.CfnWebACL.VisibilityConfigProperty => ({
      cloudWatchMetricsEnabled: true,
      metricName,
      sampledRequestsEnabled: false,
    });
    const managed = (name: string, priority: number, opts: { countAll?: boolean; countRules?: string[] }): wafv2.CfnWebACL.RuleProperty => ({
      name,
      priority,
      overrideAction: opts.countAll ? { count: {} } : { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: 'AWS',
          name,
          ruleActionOverrides: opts.countRules?.map((r) => ({ name: r, actionToUse: { count: {} } })),
        },
      },
      visibilityConfig: visibility(`${p}-${name}`),
    });
    const acl = new wafv2.CfnWebACL(this, 'WebAcl', {
      name: p,
      description: 'arata sandbox: test WebACL for WAF review proposals',
      scope: 'REGIONAL',
      defaultAction: { allow: {} },
      visibilityConfig: visibility(p),
      rules: [
        {
          // /login だけを 1 IP あたり 60 秒に 10 件までにする。REST API の URI はステージ名が付く (/sandbox/login) ので末尾で一致
          name: 'login-rate-limit',
          priority: 0,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              aggregateKeyType: 'IP',
              limit: LOGIN_RATE_LIMIT,
              evaluationWindowSec: 60,
              scopeDownStatement: {
                byteMatchStatement: {
                  fieldToMatch: { uriPath: {} },
                  positionalConstraint: 'ENDS_WITH',
                  searchString: '/login',
                  textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                },
              },
            },
          },
          visibilityConfig: visibility(`${p}-login-rate-limit`),
        },
        managed('AWSManagedRulesKnownBadInputsRuleSet', 1, { countAll: true }),
        managed('AWSManagedRulesCommonRuleSet', 2, { countRules: COMMON_RULES_IN_COUNT }),
      ],
    });

    const assoc = new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
      webAclArn: acl.attrArn,
      resourceArn: api.deploymentStage.stageArn,
    });
    // stageArn は文字列の組み立てで、ステージへの参照にならない。ステージができる前に関連付けると失敗する
    assoc.node.addDependency(api.deploymentStage);

    // 3. ログ。WAF の決まりでロググループ名は aws-waf-logs- で始める
    const logGroupName = `aws-waf-logs-${p}`;
    const logGroup = new logs.LogGroup(this, 'Logs', {
      logGroupName,
      retention: props.retentionDays as logs.RetentionDays,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    // WAF のログの宛先は末尾に :* の付かないロググループの ARN (LogGroup.logGroupArn は :* が付く)
    const logGroupArn = stack.formatArn({ service: 'logs', resource: 'log-group', resourceName: logGroupName, arnFormat: ArnFormat.COLON_RESOURCE_NAME });

    // 配信の許可。無いと WAF がアカウントのリソースポリシーを自動で作り、destroy で消えずに残る。このロググループに絞って自分で作る
    const policy = new logs.CfnResourcePolicy(this, 'LogsDeliveryPolicy', {
      policyName: `${p}-waf-logs`,
      policyDocument: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AWSWAFLogDelivery',
            Effect: 'Allow',
            Principal: { Service: 'delivery.logs.amazonaws.com' },
            Action: ['logs:CreateLogStream', 'logs:PutLogEvents'],
            Resource: `${logGroupArn}:log-stream:*`,
            Condition: {
              StringEquals: { 'aws:SourceAccount': stack.account },
              ArnLike: { 'aws:SourceArn': Arn.format({ service: 'logs', resource: '*' }, stack) },
            },
          },
        ],
      }),
    });

    const logging = new wafv2.CfnLoggingConfiguration(this, 'Logging', {
      resourceArn: acl.attrArn,
      logDestinationConfigs: [logGroupArn],
      // 認証情報と Cookie はログに残さない
      redactedFields: [{ singleHeader: { Name: 'authorization' } }, { singleHeader: { Name: 'cookie' } }],
    });
    logging.node.addDependency(policy);
    logging.node.addDependency(logGroup);

    new CfnOutput(stack, 'ApiUrl', { value: api.url });
    new CfnOutput(stack, 'WebAclArn', { value: acl.attrArn });
    new CfnOutput(stack, 'WafLogGroupName', { value: logGroup.logGroupName });
  }
}

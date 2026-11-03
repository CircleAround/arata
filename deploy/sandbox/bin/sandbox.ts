// cdk の app。設定は `-c config=<path>` で渡す (リポジトリの外に置く。例は config.example.json)。
// 実行は Node の型除去 (Node 24。.ts をそのまま動かす) で、ts-node などは使わない。
import { App } from 'aws-cdk-lib';
import { ConfigError } from '../lib/config.ts';
import { buildSandbox } from '../lib/sandbox-stack.ts';

const app = new App();
try {
  buildSandbox(app, app.node.tryGetContext('config'));
} catch (e) {
  if (e instanceof ConfigError) {
    // 設定の誤りはスタックトレースを出さずに一覧だけを出す
    console.error(e.message);
    process.exit(1);
  }
  throw e;
}

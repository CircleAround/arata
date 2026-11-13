# 0048. posture は、インターネット向けの ALB に WAFv2 の WebACL が付いていないことを報告する (読み取りの権限を 2 つ足す)

- 日付: 2026-11-13
- 状態: 採用

## 背景

WAF は、インターネットに面した Web アプリケーションの最低限の防御の 1 つと考えてよくなった。ところが arata の WAF のチェック
(`waf_block_trend`・`waf_review`) は **WAF があること** が前提で、WAF が無いアカウントではソースが無いので skip される。
「WAF が無い」こと自体はどこにも出ない。

週次の posture は「基本の守りが欠けている」ことを項目ごとに報告する (ADR 0015)。WAF の有無もここに入れるのが自然である。

## 決定

**posture に、インターネット向けの Application Load Balancer に WAFv2 の WebACL が付いていない、という項目を足す。**

- 対象: posture のソースの `regions` の各リージョンの、Scheme が `internet-facing` の Application Load Balancer。
  internal の ALB、NLB・GWLB (WAF を付けられない)、CloudFront、API Gateway は見ない
- 判定: `elasticloadbalancing:DescribeLoadBalancers` で一覧を取り、ALB ごとに `wafv2:GetWebACLForResource` を呼ぶ。WebACL が返らなければ finding
- finding の key は `alb_waf|<region>|<ALB の名前>` (ALB ごと。名前はリージョンとアカウントの中で一意)。Data は `region`・`name`・`arn` だけ。
  DNS 名・サブネット・セキュリティグループ・WebACL の中身は持たない
- 重大度は **medium**。最低限の防御として推奨するが、無くても直ちに侵害の兆候ではないので、パスワードポリシー・ログファイルの検証と同じ位置に置く
- 状態型。WebACL を付ければ次の weekly で解消になる
- 取れなかったとき: 一覧か WebACL の確認が 1 つでも失敗したリージョンは、取れなかったことにする (`unknown`)。
  そのリージョンの前回の finding を全部維持し、`coverage.sources_failed` に `partial: true` と不足の action を出す (終了コード 3)。
  一部の ALB だけを見て「付いている」とは言わない。一覧の後に消えた ALB (`WAFNonexistentItemException`) だけは数えずに続ける
- 権限: 配布用の読み取り専用ロール (`deploy/iam/readonly-role.yaml`) に `elasticloadbalancing:DescribeLoadBalancers` と
  `wafv2:GetWebACLForResource` を足す。どちらも読み取りで、書き込み系の例外 (設計書 8 章) は増えない。
  `arata doctor` は両方を試す (インターネット向けの ALB が無ければ後者は試せないので「未確認」と出す)
- 設定の項目は足さない。posture を入れている利用者は、版を上げると次の weekly からこの項目が出る。
  意図して WAF を付けない ALB は、理由を記録して ack する
- 依存: AWS SDK の `service/elasticloadbalancingv2` を足す (ALB の一覧を取る公式のクライアント。SDK の本体と同じ版の組を選び、他の依存は動かさない)

## 検討した選択肢

- **`wafv2:ListResourcesForWebACL` で「WebACL の付いた ALB」を集めて引き算する**: 既にロールにある action で、足す権限は 1 つで済む。
  しかし WebACL の数だけ呼ぶことになり、一覧の取り漏れ (ページ送り・権限) が「WAF が無い」という誤報になる。
  ALB から直接たずねる `GetWebACLForResource` のほうが、失敗が「取れなかった」に倒れる。採らなかった
- **リージョンごとに 1 つの finding にまとめる**: 件数は減るが、ALB を 1 つ直しても解消にならず、ack が ALB ごとにできない。採らなかった
- **重大度を high にする**: ほかの high (証跡が無い・GuardDuty が無効・ルートに MFA が無い) は、侵害に気づけない・侵害が直ちに全権になる欠けである。
  WAF が無いことは守りの層が 1 つ薄いことで、同列ではない。medium にした
- **新しいチェック (`alb_waf`) として分ける**: プロファイルに足す手間が利用者に生じ、入れ忘れると出ない。
  「基本の守りの欠け」は posture の役割なので、項目として足した
- **CloudFront・API Gateway も見る**: 前段に CloudFront の WebACL があれば ALB には要らない、API Gateway は認可や使用量プランで守る、など考え方が違う。
  今回は ALB に限り、必要になったら別に決める
- **WAF Classic の関連付けも見る**: WAF Classic は新規の利用が終わっている。WAFv2 だけを見る (Classic だけの ALB は「付いていない」と出る)

## 結果 (良い点・引き受けるコスト)

- WAF の無いアカウントで、これまで何も出なかった「WAF が無い」が出るようになる
- **既に配ったロールは更新が要る**。更新するまで、この項目だけが取れず、毎週 `partial` (終了コード 3) になる。README と doctor で案内する
- 前段の CloudFront に WebACL がある、送信元を絞っている、といった ALB にも出る。ack で黙らせる (理由が記録に残る)
- ALB の数だけ `GetWebACLForResource` を呼ぶ (週 1 回。無料)
- 未確認: アカウントの設定によっては、`GetWebACLForResource` を ALB に使うのに `elasticloadbalancing:GetLoadBalancerWebACL` も要ると読める公式文書がある。
  開発では実際の AWS に接続しないので確かめていない。実環境で `ACCESS_DENIED` が出たら、新しい ADR でこの action を足す

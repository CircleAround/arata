# 0091. ECS Exec (`ecs_exec`) は、その主体の「いつもの形」(クラスター × コンテナ・1 日の回数・MFA・送信元の種類) に収まり、同じ日にほかの普通でない指摘が無いときだけ low に下げる

- 日付: 2026-11-26
- 状態: 提案

## 背景

### 今の判定と負担

ADR 0072 の `ecs_exec` は、成功した `ExecuteCommand` を、主体 × リージョン/クラスター × コンテナ × UTC の日の単位で毎回報告する。
重大度は、知らない主体 (root・承認の期限切れを含む) が high、既知の主体が medium、すべて失敗した試行は 1 段下げる (ADR 0072 の 3 節)。

ADR 0072 の 4 節は「日常の利用を黙らせる仕組みは入れない」とし、量が困る大きさになったら「別の ADR で、出さないのではなく下げる案から考える」と書いた。
実際の利用者の CloudTrail を 15 日分読むと (2 つの利用者。下に形だけを書く)、既知の人が 1 日に 1〜6 回、複数のクラスターとコンテナに入るのが日常の作業だった。
そのたびに medium が (主体 × クラスター × コンテナ) の数だけ出て、片付け (resolve) も毎日要る。
ecs_exec は ack を許さない (ADR 0072 の 8 節) ので、片付けの手間がそのまま積み上がる。medium が毎日並ぶと、本当に違う日 (奪われた認証で入られた日) の medium が埋もれる。

これは 0072 が「本番のシェルを日常の手段にしていることへの指摘」として引き受けたコストだが、利用者がすぐに作業を移せない場合に、指摘としての意味より埋もれさせる害が大きくなった。

### 手口との関係

- `docs/threats.md` の対応表で、ecs_exec に対応する公開の事例は「まだ無い」(2026-11-17 の時点。ADR 0072 の 10 節)。この ADR でも事例は足さない
- playbook (`docs/ai/playbooks/ecs_exec.md`) が重いとするのは、知らない主体・承認の期限切れ、見知らぬ送信元、作業の記録が無い、環境変数・認証情報を読むコマンド、
  同じ時間帯の秘匿値の読み取りや拒否の急増。**下げる条件は、これらのどれにも当たらないことを規則で確かめる形にする**
- 奪われた既知の認証で入る場合 (playbook の「`known: true` だけを理由に正規と書かない」) を、下げる理由にしてはいけない。
  MFA (下の 3 節) と、同じ日のほかのチェックの指摘 (下の 5 節) を、そのための材料にする

### 実際の記録で分かった形 (2026-11-26 に開発リードが確かめた。値は書かず形だけ)

1. 人の操作は、すべて MFA があった (`userIdentity.sessionContext.attributes.mfaAuthenticated` が `true`)。主体は AssumedRole か IAM ユーザー
2. MFA の属性が無かったのは、長く使う鍵の IAM ユーザー (デプロイ用) だけだった (`sessionContext` の無い記録)
3. 送信元は 2 つの形があった
   - (a) 人の端末からの操作: 決まった 1〜3 の回線 (/24 で見て同じ)
   - (b) AWS CloudShell とみられる操作: 毎回違う、AWS の東京リージョンの範囲の送信元
   - 決まった IP で「いつもの形」を作ると、(b) は毎回「新しい送信元」になる
4. 1 人が 1 日に 1〜6 回、本番と検証の両方のクラスターを使う。コンテナは `web`・`batch`・`worker` のような少数
5. 失敗 (`InvalidParameterException`) の混ざる日がある

### 公式文書で確かめたこと (2026-11-26 に読んだ)

1. CloudTrail のユーザーガイド「CloudTrail userIdentity element」
   <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html>
   - `sessionContext.attributes.mfaAuthenticated`: 「The value is `true` if the root user or IAM user who used their credentials for the request also authenticated with an MFA device; otherwise, `false`.」
   - `sessionContext` は「If the request was made with temporary security credentials」のときに付く。長く使う鍵の IAM ユーザーの例には `sessionContext` が無い
     (無いと文で書いてはいない。例から読んだ)
2. VPC のユーザーガイド「AWS IP address ranges」と「Syntax」「Subscribe to notifications」
   <https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html>・<https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-syntax.html>・
   <https://docs.aws.amazon.com/vpc/latest/userguide/subscribe-notifications.html>
   - 公開の一覧は `https://ip-ranges.amazonaws.com/ip-ranges.json`。上の段は `syncToken` (公開の時刻)・`createDate`・`prefixes`・`ipv6_prefixes`。
     各行は `ip_prefix` (`ipv6_prefix`)・`region` (または `GLOBAL`)・`network_border_group`・`service`
   - 「Specify `AMAZON` to get all IP address ranges (meaning that every subset is also in the `AMAZON` subset).」。`service` に CloudShell の値は無い
   - 変わったときは SNS の `AmazonIpSpaceChanged` (us-east-1) で知らせる。決まった周期は書かれていない。知らせの中の `md5` は「壊れていないか」を確かめる値で、署名の仕組みは書かれていない。
     取得では TLS の証明書を確かめるのは利用者の責任、とある
   - 「We don't publish the IP address ranges for all services.」。BYOIP の範囲は入らない
3. CloudShell のユーザーガイド「Limits」「Security FAQs」
   <https://docs.aws.amazon.com/cloudshell/latest/userguide/limits.html>・<https://docs.aws.amazon.com/cloudshell/latest/userguide/cloudshell-security-faqs.html>
   - VPC の外の環境は「Outbound: You can access the public internet.」「No public IP address is available.」。出ていく送信元の範囲や、固定かどうかは書かれていない
   - 「Each CloudShell session receives temporary, regularly-rotated IAM credentials scoped to the user's permissions.」(コンソールの利用者の認証の一時的な認証情報)

**公式文書に無かったこと**: CloudShell から出ていく送信元が AWS の範囲であること、CloudShell から呼んだ API の記録の `sourceIPAddress`・`userAgent`・`mfaAuthenticated` の形。
背景の 3 (b) の「CloudShell とみられる」は、実際の記録の形からの推定である (8 節の未確認の点)。

## 決定

### 1. 下げる条件の全体

- **既知の主体の、成功を含む Key (今の medium) だけを、すべての条件を満たすときに low にする**。1 つでも外れれば今のまま (medium)
- 知らない主体 (high、root、承認の期限切れ) は下げない。「新しい主体」は「いつもの形」を持たないので下げない (2 節の最低の日数)
- すべて失敗した既知の主体の Key は、今も low で、これより下げない (info にしない)。いつもの形かどうかは data に出すだけ
- 下げたときは見出しを「ECS Exec (いつもの形)」にし、data に `usual_shape: true` と、満たした要素を出す。下げなかったときは `usual_shape: false` と、
  外れた要素の名前の一覧 `unusual` (`cluster_container`・`count`・`mfa`・`source`・`related`・`errors`・`history`) を出す。
  人と LLM は「何が違ったか」をここで読む (見出しの文言を機械で読ませない)
- 要素の判定は Key (主体 × クラスター × コンテナ × 日) ごとに行う。ただし回数 (4 節) は主体の 1 日の合計で見る (コンテナを分けて回数を薄めさせない)

### 2. 平常帯の作り方

- 材料はストアの events の `ExecuteCommand` だけ (ADR 0072 で既に残している。新しい収集・権限・API の呼び出しは無い)
- 期間は評価する日の前日から `baseline_days` 日 (既定 30)。events の保持の既定 (90 日) の内。評価する日そのものは平常帯に入れない
- 平常帯に使うのは、その主体の**成功した**記録だけ (失敗の記録で平常帯を広げない)
- **最低の日数**: その主体が平常帯の期間に成功した ExecuteCommand のある日が `min_baseline_days` 日 (既定 5) 未満なら、いつもの形を持たない (`unusual: [history]`)。
  導入の直後と、初めて ECS Exec を使い始めた主体は、`min_baseline_days` 日の間は今のまま medium で報告される
- 要素が「いつもの」と言えるのは、その値が平常帯の期間の**異なる 2 日以上**に現れたとき (1 回の作業で平常帯を広げない)
- パラメータ `baseline_days`・`min_baseline_days` を足し、雛形の `checks:` に既定値を書く (ADR 0014。`config init --diff` で見える)。ほかの値は固定する

### 3. 要素ごとの規則

| 要素 | いつもの形 | 外れたとき |
|---|---|---|
| 主体 | 既知 (ADR 0072 の 3 節と同じ判定) で、最低の日数を満たす | 今のまま |
| クラスター × コンテナ | その組 (`<リージョン>/<クラスター>` と `<コンテナ>`) が平常帯の 2 日以上にある。`-` (取れない) はいつもの形にしない | medium |
| 1 日の回数 | その主体のその日の ExecuteCommand の数 (成功と失敗の和、Key をまたいだ合計) が、平常帯の日ごとの数の最大以下 | medium |
| MFA | 下の「MFA」 | medium |
| 送信元 | 下の「送信元」 | medium |
| 失敗 | 失敗が混ざってもよい。ただし `AccessDenied` で始まる errorCode が 1 件でもあれば外れる | medium |
| 同じ日のほかの指摘 | 5 節 | medium |

- クラスターとコンテナは組で見る (別々に見ると、検証でだけ使うコンテナに本番で入っても「どちらも見たことがある」になる)
- 回数の上限は最大値そのもの (係数を掛けない)。平常帯が 1〜6 回の人は、7 回目で medium に戻る。日の途中の hourly の run で low でも、
  同じ日に回数が増えて外れれば、同じ Key のまま medium になる (Fingerprint は重大度を含むので changed として出直す。ADR 0072 の 4 節)
- **userAgent は判定に使わない** (呼ぶ側が自由に名乗れる。ADR 0083 の却下の理由と同じ)。data に出すのは構わないが、この ADR では足さない

#### MFA

- 記録ごとに、collector が既に残している `session_mfa` (= `mfaAuthenticated`) を読み、`true` / `false` / 無い (属性が無い) の 3 つに分ける
- その日の Key の記録が**すべて `true`** なら「MFA あり」。1 件でも `false` か無いものが混ざれば「MFA なし」
- 平常帯で MFA ありだった主体が、その日 MFA なしなら外れる
- **MFA は強い安全の印として使い、MFA ありなら送信元の /24 の違いを許す** (下の「送信元」)。
  ただし MFA は「その認証情報を作ったときに MFA を通った」ことしか言わない。MFA の後のセッションの認証情報を持ち出されれば、持ち出した側の記録も `true` のままである。
  そのため、MFA があっても、クラスター × コンテナ・回数・送信元の種類・同じ日のほかの指摘は、いつもの形であることを求める

#### MFA の属性が無い主体 (IAM ユーザーの長い鍵)

- 平常帯でも MFA の属性が無い主体 (背景の 2) は、MFA の要素を「無いのがいつもの形」として扱い、MFA で外れはしない。**その代わり、送信元の /24 の違いを許さない**
- 長い鍵は漏れても期限で切れず、持ち出した側は MFA を求められない。下げる余地を残すのは、決まった回線からの、決まったクラスター × コンテナへの、ふだんの回数の操作だけにする
- ADR 0072 の 3 節の「`tags: [deploy]` でも下げない」は変えない。deploy タグは下げる理由にも、下げない理由にもしない (同じ規則で判定する)。
  デプロイ用の鍵で人が ECS Exec をしていること自体は playbook で「鍵を分ける」案を示す

#### 送信元

- 送信元を**種類**と /24 (IPv4) / /48 (IPv6。principal_new_source と同じ) で見る。種類は次の 3 つ:
  - `aws:<リージョン>`: AWS の公開の一覧 (6 節) の範囲に入る。リージョンは一覧の `region` (`GLOBAL` はそのまま)。CloudShell とみられる操作はこれになる
  - `other`: IP だが一覧の範囲に入らない (人の端末の回線など)
  - `service`: IP でない (`*.amazonaws.com`・`AWS Internal`)。ECS Exec では見ていないので、いつもの形にしない
- **MFA あり**: その日の送信元の**種類**が、すべて平常帯の 2 日以上に現れた種類なら、いつもの形 (/24 は違ってよい)。
  ふだん端末からしか入らない人が初めて AWS の範囲から入った (持ち出したセッションを EC2 で使った場合を含む) ときは外れる。
  ふだん CloudShell を使う人の、毎回違う AWS の送信元は外れない
- **MFA なし**: その日の送信元の /24 (/48) が、すべて平常帯の 2 日以上に現れたものなら、いつもの形。種類は見ない (/24 が同じなら種類も同じ)。
  AWS の範囲の送信元でも、決まった送信元 (固定の EIP など) なら下げられる。毎回変わる AWS の送信元は下げない (持ち出した鍵を AWS の上で使う形と区別できない)
- 種類は評価のたびに、保存した IP と同梱の一覧から求める (ストアに種類を残さない)。一覧を入れ替えた版では、過去の日の種類も新しい一覧で数え直される

### 4. 回数の数え方

- 主体の 1 日の数は、その日のその主体の ExecuteCommand の記録の数 (Key をまたぐ。成功と失敗の和)。平常帯の日ごとの数は成功の記録だけで数える
  (失敗の多い日で上限を上げない)
- 1 回の ECS Exec は 1 つの ExecuteCommand の記録。SSM の `StartSession` (ECS が代わりに呼ぶもの) は数えない (ADR 0072 の 7 節)

### 5. 同じ日のほかの普通でない指摘 (`related`)

- 同じ主体の、評価する日と同じ UTC の日に、次のチェックが観測を出していれば、下げない。data の `related` に、そのチェックの名前を出す
  - `access_denied`・`secret_access`・`iam_changes`・`defense_evasion`・`public_exposure`・`unknown_assume_role`・`unused_region_activity`: 重大度を問わない
  - `principal_new_source`: **medium 以上だけ**。low (新しい送信元だけ) は、MFA ありの主体では数えない (3 節で /24 の違いを許したことと揃える)。
    MFA なしの主体では、新しい送信元は 3 節で既に外れる
  - `new_principal`・`root_usage` は数えない (下げる対象は既知の主体だけで、root は下げない)
- **チェックは互いの結果を見られない**ので、principal_new_source が access_denied を呼ぶのと同じく、同じ (ストア, 窓, allowlist, そのチェックの設定) で上のチェックの評価を呼び、
  観測だけを使う (finding は出さない)。プロファイルに入っていないチェックも呼ぶ (呼ぶのはストアの読み取りだけで、AWS には触れない)
- 呼ぶのは、ecs_exec が下げる候補 (1〜4 の条件をすべて満たした Key) を持つときだけ (ふつうの run の重さを増やさない)
- hourly の run では、ほかのチェックの材料がまだその日の途中までしか無い。hourly で low でも、daily の run で `related` が見つかれば、同じ Key のまま medium になり changed で出直す
- 主体の突き合わせは、各チェックの観測の data の `principal` (正規化した ARN) と、ecs_exec の主体の ARN の一致だけで行う。data に主体を持たないチェックは足さない

### 6. AWS の IP の範囲は、一覧を加工してバイナリに同梱する

- 一覧 (`ip-ranges.json`) の `prefixes`・`ipv6_prefixes` から、`service` が `AMAZON` (全部を含む) の行の範囲とリージョンだけを取り出し、隣り合う範囲をまとめた小さなファイルにして、
  `go:embed` で同梱する。元の `syncToken`・`createDate` を一緒に残し、`arata --version` と run の記録に出す (どの一覧で判定したかを後から分かるように)
- 入れ替えは、取り出す道具 (`tools/` に置く。標準ライブラリだけ) を手元で流し、差分を PR で見て入れる。Dependabot のような自動の更新は作らない。
  入れ替えの周期は決めず、リリースの前に確かめる (一覧の更新に決まった周期は無い (公式文書 2)。範囲が増えた直後の取りこぼしは下の理由で害が小さい)
- 取りこぼし (一覧にまだ無い新しい AWS の範囲) は `other` になる。MFA ありの人で `other` がいつもの種類なら下げられるが、それは端末からの操作と同じ扱いで、
  3 節の「MFA があれば /24 の違いを許す」の範囲に収まる。逆に、ふだん `aws:` からだけ入る人は `other` で外れる (下げない側に倒れる)
- **実行中に一覧を取りに行かない**:
  - arata が外に出るのは AWS の API (署名つきの読み取り) だけである。一覧の取得は読み取りだが、署名の無い外の取得が増え、通信を絞った実行環境 (GitHub Actions のランナーを VPC の中に置く場合など) で失敗の道が増える
  - 同じストアから同じ結果を出せなくなる (`arata rebuild`・`run --dry-run`・期間レポートが、取った時刻で変わる)
  - 一覧の中身は重大度を下げる材料になる。署名の仕組みが無い (公式文書 2) ので、取得の経路で書き換えられたときに守る手が TLS だけになる。同梱なら PR の差分として人が見る
- 利用者が一覧を設定で差し替える道は作らない (書き換えた一覧が、そのまま下げる範囲になる)

### 7. 片付けと playbook の表 (ADR 0068)

| 重大度 | 上がる余地 | 許す操作 |
|---|---|---|
| high | なし | snooze・resolve |
| medium・low | あり | snooze・resolve |

- 表の形は変えない。low の上がる余地に「いつもの形で下げた low は、同じ日に回数が増える・ほかのチェックの指摘が出ると medium に戻る」を足す
- ack と approve を許さないのも変えない。low でも ack すると、同じ日に medium に戻ったとき以外の次のセッションが見えなくなる
- いつもの形の low も通知の対象 (aratam の下限の設定による)。low を出さないことにはしない (誰が何を始めたかは残す。ADR 0072 の 4 節)

## 検討した選択肢

- **allowlist に主体 × クラスター × 期限の項目を足し、その範囲を low にする** (ADR 0072 の 4 節が挙げた案): 却下。人が書く範囲は広く書かれがちで、期限の管理も要る。
  回数・MFA・送信元・同じ日の指摘を書けないので、奪われた認証の日も同じ low になる。平常帯なら、いつもと違う日を規則で拾える
- **送信元を /24 だけで見る** (principal_new_source と同じ): 却下。CloudShell の操作が毎回「新しい送信元」になり、CloudShell を使う人は下がらない
- **送信元を見ない** (MFA があれば何も問わない): 却下。持ち出した MFA の後のセッションを、ふだんと違う種類の場所 (AWS の上) で使う形を区別できない
- **MFA なしの主体は下げない**: 決まった回線からの決まった操作まで毎日 medium になり、背景の負担が残る。/24 の一致を求めて下げる余地を残した。
  ただし判断の分かれる点として PR に挙げる
- **AWS の範囲を `aws` の 1 種類にする** (リージョンを区別しない): 却下に寄せた。東京から CloudShell を使う人が、別のリージョンの AWS の範囲から入るのを同じに扱う理由が無い。
  リージョンを変えて CloudShell を使う人は、平常帯がそれを覚えるまで medium になる
- **実行中に ip-ranges.json を取る / 利用者が設定で一覧のパスを渡す**: 6 節の理由で却下
- **userAgent で CloudShell を見分ける**: 却下。呼ぶ側が名乗れる値で重大度を下げない (ADR 0083)
- **回数の上限を中央値 × 係数にする** (access_denied と同じ): 却下に寄せた。1 日の回数は 1〜6 と小さく、中央値 × 係数は 1 日だけ多い作業で外れやすい。
  最大値は平常帯の日数で自然に広がり、係数を持たずに済む
- **クラスターとコンテナを別々に見る**: 却下。3 節の理由 (検証のコンテナ名で本番に入る形を拾えない)
- **ほかのチェックの finding をストアから読む** (`related` を run の結果で作る): 却下に寄せた。チェックの評価の順と、hourly と daily の窓の違いで結果が変わる。
  principal_new_source と同じく、評価を呼んで観測を使う
- **いつもの形なら出さない (info・記録だけ)**: 却下。ADR 0072 の 4 節のとおり、既知の人でも誰が何を始めたかは毎回残す。下げるのは通知の重さだけ

## 結果 (良い点・引き受けるコスト)

- 既知の人の日常の ECS Exec が low になり、medium は「いつもと違う日」に絞られる。外れた要素が `unusual` で分かる
- 新しい権限・収集・API の呼び出しは無い。材料は既に残している ExecuteCommand の記録と `session_mfa` だけ
- 引き受けるコスト:
  - MFA の後のセッションを持ち出され、いつもの種類の場所から、いつもの組に、いつもの回数で使われると、low になる。
    principal_new_source (medium 以上)・access_denied・secret_access などが同じ日に出れば medium に戻るが、何も出なければ low のままである
  - AWS の IP の一覧を同梱して入れ替え続ける作業 (道具と PR) が増える。古い一覧は下げない側か、端末と同じ扱いに倒れる
  - hourly の run の low が、daily の run で medium に変わることがある (通知が 2 回になる)
  - ほかのチェックの評価を呼ぶので、下げる候補がある run は重くなる (ストアの読み取りだけ)
- 影響する文書 (実装の PR で直す。ADR の採用までは変えない):
  - `docs/ai/playbooks/ecs_exec.md`: 重大度の表に「既知の主体で、いつもの形 → low」を足し、data に `usual_shape`・`unusual`・`related`・`source_kinds`・`mfa` を足す。
    「まず確かめること」に `unusual` を読む手順、「やってはいけないこと」に「`usual_shape: true` だけを理由に正規と書かない」を足す。
    「対処の選択肢」に、デプロイ用の長い鍵で人が ECS Exec をしているなら鍵を分ける (人は MFA のある認証で入る) 案を足す
  - `docs/threats.md` と `docs/ai/threats/`: 変えない (ecs_exec に対応する公開の事例はまだ無い。重大度の条件を変えるので、実装の PR で事例を探し直し、見つからなければ playbook の日付を更新する)
  - `docs/design.md`: チェックの表の ecs_exec の重大度と、ADR 0072 の決定の注記にこの ADR を足す
  - `docs/roadmap.md`: 残項目に「ecs_exec のいつもの形 (ADR 0091)」を足す (この PR)
  - ADR 0072: 書き換えない。3 節の表と 4 節の「黙らせる仕組みは入れない」のうち、既知の主体の medium を下げる部分をこの ADR が置き換える (採用のときに一覧の状態を「採用 (3 節の既知の主体の重大度は 0091 で置き換え)」にする)

## 未確認の点

1. CloudShell から呼んだ API の記録の形 (`sourceIPAddress` が AWS の一覧の範囲に入るか、`mfaAuthenticated` がコンソールの MFA を引き継ぐか)。背景の 3 (b) は推定で、公式文書に無い。
   実装の前に、開発用のアカウントで CloudShell から読み取りの API を 1 つ呼び、記録の形を `docs/cloudtrail-event-names.md` に残す
2. CloudShell の VPC の環境 (NAT を通る) では、送信元が利用者の NAT の EIP になるはず (公式文書 3 の VPC の頁) で、`aws:` の決まった /24 として平常帯に入る。確かめていない
3. 拒否された ExecuteCommand の記録に `sessionContext` が残るか (ADR 0072 の 9 節と同じく、拒否の形の実例が無い)。残らなければ MFA なしとして外れる (下げない側)
4. IAM ユーザーのコンソールのサインインのセッションからの操作の `sessionContext` の形 (公式文書 1 の頁の後半を読み切れていない)
5. `min_baseline_days` (5)・`baseline_days` (30)・「異なる 2 日以上」の値は、2 つの利用者の 15 日分からの見立て。実装の後に、`run --dry-run` で過去の日を評価して、下がる割合と外れる要素を確かめる

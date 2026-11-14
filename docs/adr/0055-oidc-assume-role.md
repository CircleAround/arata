# 0055. OIDC でのロールの引き受けを、(プロバイダ, sub, ロール) の組で既知リストと比べる (`oidc_assume_role`)

- 日付: 2026-11-14
- 状態: 提案

## 背景

GitHub のアカウントを乗っ取り、多くのリポジトリのワークフローに CI の秘密を盗むスクリプトを入れる攻撃が、2026-11 に報告された。
スクリプトは、GitHub の OIDC のトークンで AWS のロールを引き受け、そこからほかのロールへ乗り移り、長期のキーを作り、信頼ポリシーを広げる。
攻撃者は正規の GitHub の実行環境の中でトークンを作る。既定のブランチの既存のワークフローを書き換える手口では、信頼ポリシーのブランチの条件も通る。

arata は今、OIDC での引き受け (`AssumeRoleWithWebIdentity`) を見ていない。

- `unknown_assume_role` は呼び出し元の ARN を既知リストの `principals` と比べる。OIDC の引き受けの記録には呼び出し元の ARN が無いので、
  主体が空になり、対象から外れている (意図して外したのではなく、形の結果)
- `new_principal`・`principal_new_source` が見るのは、引き受けた後のロール (のセッション) の活動で、「どのリポジトリのどのブランチから入ったか」は見ない

### 記録の形 (CloudTrail の `AssumeRoleWithWebIdentity`。実際の記録で確かめた)

- `userIdentity.type` は `WebIdentityUser`
- `userIdentity.userName` はトークンの `sub`。GitHub では `repo:example-org/example-repo:ref:refs/heads/main`。
  組織とリポジトリに ID が付いた形 (`repo:example-org@1234567/example-repo@7654321:ref:refs/heads/main`) のこともある。
  environment を使うジョブは `repo:example-org/example-repo:environment:production`
- `userIdentity.identityProvider` は `arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com`
- `requestParameters.roleArn`・`roleSessionName`、`sourceIPAddress` (GitHub の実行環境の IP)
- `userAgent` に `exec-env/GitHubActions` と `md/run_id#<数字>` が入る (aws-actions/configure-aws-credentials を使った場合)
- **`job_workflow_ref` (どのワークフローのファイルから来たか) は記録されない。** だから、ワークフローの単位では見られない。
  見られるのは `sub` に入っている単位 (リポジトリと、ブランチ・タグ・environment・pull_request のどれか) まで。
  既定のブランチの既存のワークフローを書き換える手口は、既知の組のままなので、組の比較では見つからない

## 決定

**新しいチェック `oidc_assume_role` (hourly、event 型、材料は trail_event) を足す。`AssumeRoleWithWebIdentity` を
(プロバイダ, sub, ロール) の組にまとめ、既知リストの新しい節 `oidc_subjects` と比べる。**

| 状況 | 重大度 |
|---|---|
| ロールが `oidc_subjects` のどの項目にも (期限内で) 無い | medium |
| ロールは期限内の項目にあるが、その組 (プロバイダ・リポジトリ・ブランチ / environment) が無い | high |
| 組は既知だが、項目に書いた時間帯・送信元の外 | medium |
| 組は既知だが、その日の回数が平常帯を超えた | low (大きく超えたら medium) |
| 組が既知で、上のどれでもない | 報告しない (ロールごとに info で 1 行) |
| 上の medium / high で、窓の中の引き受けが全部失敗 (信頼ポリシーが止めた) | low |

### 既知リスト

```yaml
oidc_subjects:
  - provider: token.actions.githubusercontent.com   # 必須。プロバイダの ARN の oidc-provider/ より後ろ
    role: arn:aws:iam::123456789012:role/gha-deploy  # 必須。ロールの ARN (完全一致)
    repo: example-org/example-repo                   # GitHub では必須 (完全一致。glob は書けない)
    refs: ["refs/heads/main", "refs/tags/v*"]        # ブランチ・タグ (glob)
    environments: ["production"]                     # environment の名前 (完全一致)
    pull_request: false                              # pull_request のジョブを許すなら true
    hours: ["00:00-03:00"]                           # 任意。許す時間帯 (UTC。日をまたぐ書き方も可)
    source_ips: ["203.0.113.0/24"]                   # 任意。許す送信元 (CIDR)
    note: 本番のデプロイ                                # 必須
    approved_by: alice
    approved_at: 2026-11-14
    expires: 2027-03-31                              # 任意
  - provider: oidc.eks.ap-northeast-1.amazonaws.com/id/EXAMPLE0123456789
    role: arn:aws:iam::123456789012:role/app-irsa    # GitHub 以外は provider と role だけ
    note: クラスタのサービスアカウント
```

- **`principals` とは別の節にする** (ADR 0047 と同じ理由)。`principals` は「主体として既知」で、ロールを承認しても、どこから入ってよいかは決まらない。
  逆に、`oidc_subjects` に書いてもロールは主体として承認されない (ロールの活動は今までどおり `new_principal` などが見る)
- **GitHub の項目は、`refs`・`environments`・`pull_request: true` のどれか 1 つ以上を必ず書く。** 「リポジトリの全部」という暗黙の広さを持たせない
  (全部のブランチを許すなら `refs: ["*"]` と書く)。`repo` は完全一致で、組織の単位の glob は書けない
- `role` は完全一致。`provider` は ARN ではなく名前 (アカウントはロールの ARN が決める)
- `hours`・`source_ips` は任意。書かなければ見ない (GitHub の実行環境の IP は毎回変わるので、既定で送信元を比べない。
  自前のランナーや時刻の決まった定期実行で使う)。書いたときは、窓の中の 1 件でも外れたら medium (`reasons` に `outside_hours` / `unexpected_source`)
- `note` は必須。期限 (`expires`) の扱いは `assume_destinations` と同じ (期限日の終わりまで有効。切れたら「無い」として扱い、data に `allowlist_status: expired`)
- `arata config check` (オフライン) が形を確かめる (知らないキー・必須の欠け・ARN や CIDR や時間帯の形は ng、期限切れと重なる項目は warn)
- **`arata approve` は、この版では対応しない。** 項目は人が書く (書き方は playbook に載せ、finding の data に組の各項目を出す)。
  既知リストに足した後の evaluate の冒頭で、既知になった組の finding (open・acked・snoozed) を resolved にする (`resolved_reason: known_oidc_subject`。ADR 0047 と同じ仕組み)

### sub の読み方 (ログ由来の値。ADR 0037・0041)

- プロバイダの名前が `token.actions.githubusercontent.com` のときだけ `sub` を読む。形は
  `repo:<組織>[@<数字>]/<リポジトリ>[@<数字>]:` の後に `ref:<ref>`・`environment:<名前>`・`pull_request` のどれか。
  組織とリポジトリは GitHub が名前に許す文字だけ、全体に長さの上限を置く。先頭から末尾までの一致
- **ID 入りの形は、ID を外した形に正規化して比べる。** Key も正規化した形にする (2 つの形が混ざっても finding が割れない)。ID は data (`owner_id`・`repo_id`) に残す
- **読めない `sub`** (上の形でない。`sub` の形をカスタマイズしたリポジトリを含む) は、値を残さず「読めない」(`sub_form: unparsed`) としてまとめ、
  既知の組に一致しないものとして扱う (ロールが既知なら high、でなければ medium)。既知リストには書けないので、正常なら ack する
- 収集のときに残すのは、プロバイダの名前、読めた `sub` の各部分、ロールの ARN、送信元、`userAgent` の `run_id` (数字だけ。GitHub Actions の実行のときだけ)。
  `roleSessionName` は残さない (今までと同じ。個人名が入りうる)。`run_id` は呼ぶ側が自由に書ける値なので、**判定に使わず**、調べる手がかりとして data に出すだけにする
- 主体 (`PrincipalARN`) は空のままにする。`sub` を主体として `principals` に載せない (`new_principal`・`principal_new_source` の対象にしない)
- 解釈する関数にはファズテストを足す (守る規則: 読めた組織・リポジトリ・ref に決まった文字しか入らない、ID 入りと ID なしが同じ組になる、
  既知でない組が既知として通らない)

### GitHub 以外の OIDC プロバイダ

- 組は **(プロバイダ, ロール)** にする。`sub` は読まず、残さない。プロバイダごとに形が違い、利用者 1 人ごとの ID が入るもの (Cognito、Google など) がある
  (レポートに個人を特定できる値を書かない)
- 既知リストに無い組は medium。`provider` と `role` だけの項目で既知にできる。ロールが既知で、別のプロバイダから来たら high
- `identityProvider` が ARN でない形 (`cognito-identity.amazonaws.com`・`accounts.google.com` など) は、その文字列をプロバイダの名前として同じに扱う。
  決まった文字と長さに合わない値は「読めない」としてまとめる
- GitHub Enterprise Server (発行元が自前のホスト) は「GitHub 以外」として扱う。`sub` を読むようにするのは、実際の記録を確かめてから新しい ADR で決める

### 平常帯

- 既知の組について、窓に重なる UTC の日ごとの回数 (成功した引き受け) を、その組自身の直近 `baseline_days` 日の日次の回数 (無い日は 0) の中央値と比べる。
  材料は保存済みの注目イベント (`AssumeRole*` は今も全部残している。保持は既定 90 日)。新しい日次集計は足さない
- 回数が `max(min_count, 中央値 × factor)` を超えたら low、その `medium_ratio` 倍を超えたら medium。Key は組の Key に `volume:` を付けた別の行
- CloudTrail を収集し終えた過去日が `min_baseline_days` 未満の間 (導入直後) は判定しない (`principal_new_source` と同じ数え方)
- 設定は `checks.oidc_assume_role` (`baseline_days: 14`、`factor: 3`、`min_count: 20`、`min_baseline_days: 7`、`medium_ratio: 3`)。
  雛形に書き出し、既存の設定には `config init --diff` で見える (ADR 0014)。雛形の hourly と daily のプロファイルに足す。暗黙には動かない

### finding の形

- Key は `<プロバイダの名前>|<正規化した sub。GitHub 以外は ->|<ロールの ARN>`。平常帯の行は先頭に `volume:`、報告しなかった分の行は `known:<ロールの ARN>`
- data: `provider`・`provider_account`・`role_arn`・`repo`・`owner_id`・`repo_id`・`sub_kind` (ref / environment / pull_request)・`ref`・`environment`・
  `sub_form`・`reasons`・`allowlist_status`・`role_known`・`count`・`ips`・`run_ids` (上限つき)・`has_errors` / `denied`
- Fingerprint は重大度と `reasons` (IP は入れない。GitHub の実行環境の IP は毎回変わり、入れると毎回 changed になる)
- 報告しなかった分はロールごとに info で 1 行 (回数と、組の一覧。上限つき)。Fingerprint は固定 (ADR 0047 と同じ)

### 既存のチェックとの重なり

| チェック | 見るもの | 整理 |
|---|---|---|
| `unknown_assume_role` | 呼び出し元の ARN がある `AssumeRole` | `AssumeRoleWithWebIdentity` を名前で明示して対象から外し、テストで固定する (今は主体が空という形の結果で外れている)。OIDC の引き受けを出すのは `oidc_assume_role` だけ |
| `new_principal` | 引き受けた後の、ロールの活動 (主体の初出) | 変えない。見ている出来事が違う (「入った」と「知らない主体が動いた」)。`sub` を主体にしないので、引き受けそのものは出ない |
| `principal_new_source` | 既知のロールの、初めての送信元・リージョン | 変えない。`oidc_assume_role` は送信元の新しさを見ない (`source_ips` を書いたときの「外」だけ)。OIDC で入るロールは `principals` で `dynamic_source: true` にする (playbook に書く) |
| `iam_changes` など | 入った後の操作 | 変えない (デプロイ主体の重大度は ADR 0056) |

新しいロールを初めて OIDC で使うと、`oidc_assume_role` (知らない組) と `new_principal` (知らない主体) の 2 件が出る。
同じ出来事の二重の報告ではなく、片付け方も別 (`oidc_subjects` に入り口を書く / `principals` でロールを承認する) なので、片方に寄せない。

## 検討した選択肢

- **`unknown_assume_role` を広げる** — 却下。あちらの単位は呼び出し元の ARN で、既知リストは `principals`。OIDC の引き受けには呼び出し元の ARN が無く、
  `sub` を ARN の代わりに `principals` に入れると、`principals` を読むチェック全部 (iam_changes・new_principal など) に `sub` の照合が入る。Key と data の形も違う
- **`sub` を主体 (`PrincipalARN`) にして、`new_principal`・`principal_new_source` に任せる** — 却下。「知っているロールに、知らないリポジトリから」を high にできない
  (主体の初出はどれも medium)。ロールとの組も表せない
- **既知リストに書かず、過去に見た組を既知とする (平常帯だけ)** — 却下。導入の時点で攻撃者が入っていれば既知になる。何を正規とするかは人が書いて git に残す (ADR 0004)
- **組織の単位の glob (`repo: example-org/*`)** — 却下。この攻撃は、乗っ取ったアカウントで書き込める多くのリポジトリから来る。
  組織の全部を既知にすると、同じ組織の別のリポジトリからの引き受けが黙る
- **既知のロールへの知らない組も medium** — 却下。ロールが既知なら、正規の入り口は書いてある。そこに別の入り口から成功したなら、信頼ポリシーが広すぎるか、
  書き換えられている
- **送信元 (GitHub の IP の範囲) を既定で比べる** — 却下。範囲は GitHub が変え、arata は実行時に外へ問い合わせない。攻撃者も GitHub の実行環境から来るので、区別にならない
- **`userAgent` (`exec-env/GitHubActions`・`run_id`) を判定に使う** — 却下。呼ぶ側が自由に書ける
- **GitHub 以外のプロバイダの `sub` も残して組に入れる** — 却下 (この版では)。形がプロバイダごとに違い、利用者ごとの ID が入るものがある。要るものから、記録を確かめて足す
- **失敗した引き受けを報告しない** — 却下。知らないリポジトリが自アカウントのロールを試した記録は残す。ただしロールの ARN は秘密ではなく、
  誰でも自分のリポジトリから試せるので、全部失敗なら low に下げる

## 結果 (良い点・引き受けるコスト)

- 知らないリポジトリ・ブランチ・environment からの引き受けが、入った時点 (hourly) で出る。乗っ取ったアカウントが新しいブランチや別のリポジトリから入る手口に効く
- **見えないもの (残るリスク)**
  - 既定のブランチの既存のワークフローの書き換え。組は既知のままで、`job_workflow_ref` は記録に無い。回数の外れ (平常帯) と、入った後の操作
    (`iam_changes`・`secret_access`・`access_denied` など) で補う。GitHub の側の守り (ブランチの保護、environment の承認) は arata の外
  - 入った後に、承認済みのロールからほかのロールへ乗り移ること。`unknown_assume_role` は呼び出し元が `principals` で承認済みなら、どのロールへの引き受けも出さない。
    この ADR では変えない (次の候補)
  - `sub` の形をカスタマイズしたリポジトリは「読めない」にまとまり、リポジトリの単位で既知にできない
  - 組織やリポジトリの名前の付け替え・取り直し。名前で比べるので、ID が変わっても気づかない (ID は data に出る)
- 既知リストに節が 1 つ増え、導入のときに、今ある OIDC の入り口を書く手間がかかる (書くまで、組ごとに medium が 1 件ずつ出る)。approve が無い分は手で書く
- 収集する値が増える (`AssumeRoleWithWebIdentity` の記録だけ。プロバイダの名前・`sub` の各部分・`run_id`)。以前に集めた記録には無いので、平常帯は導入後の記録から貯まる
- 平常帯の評価は、窓ごとに過去 `baseline_days` 日の `AssumeRoleWithWebIdentity` のイベントを読む (引き受けの多いアカウントでは読む量が増える)

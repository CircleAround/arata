# 公開できない情報の検査の運用

規則は CLAUDE.md「顧客の情報を書かない」、判断の理由は [ADR 0036](adr/0036-sensitive-info-scan.md)。

## 何を検査するか

ワークフローは `.github/workflows/secrets-scan.yml`。

| ジョブ | 内容 | いつ |
|---|---|---|
| `gitleaks` | 秘密 (AWS のキー、トークン、Webhook、秘密鍵)、架空の値以外の 12 桁の数字・IP・メール。コミットの差分とメッセージ (読む範囲は下)、PR のタイトルと本文 | PR、main への push、毎日、手動 |
| `words` | 禁止語。全履歴 (削除されたファイル、コミットメッセージ、タグ)、参照の名前、PR のタイトルと本文 | PR (フォークと Dependabot を除く)、main への push、毎日 |
| `github-text` | PR・Issue・コメント・レビュー・Release の本文に上の両方 | 毎日、手動 |

`gitleaks` が読むコミットの範囲はイベントで違う (理由は [ADR 0088](adr/0088-gitleaks-pr-range.md))。

| イベント | 範囲 |
|---|---|
| PR | その PR のコミット (`base..head`) だけ |
| main への push、毎日、手動 | 全部の枝とタグの履歴 (`--all`) |

PR を出していない枝は、毎日の検査まで CI では読まれないので、push の前に手元で読む。マージコミットの差分 (競合の解消で足した行) は、どちらの範囲でも読まれない。

架空の値として使えるメールのドメインは、`example.com` `example.org` `example.net` `example.co.jp` とそのサブドメイン、`.example` `.test` `.invalid` `.localhost` (RFC 2606・6761)。

毎日の定期実行は main のワークフローだけが動く。公開リポジトリでは 60 日間活動が無いと止まるので、止まったら Actions の画面で有効にし直す。

コミットとタグの作者欄 (名前とメールアドレス) は公開前提で、検査の対象外とする。gitleaks も `wordscan` も読まない。

## secrets の登録と更新

一覧は 1 行 1 つの正規表現 (大文字小文字を区別しない。Go の regexp の書式)。空行と `#` で始まる行は読み飛ばす。
登録と更新は同じ手順で、リポジトリの admin 権限が要る。

```bash
gh secret set SENSITIVE_PATTERNS -R CircleAround/arata < sensitive-patterns.txt
gh workflow run secrets-scan.yml -R CircleAround/arata   # 登録できたことを確かめる
```

- 一覧のファイルはリポジトリの外に置く。secrets は読み戻せないので、原本をパスワード管理ツールなどに保管する
- 一覧をコミット・PR・Issue・ログに書かない
- 語を足したら、上の手動実行で既存の履歴と本文に当たらないことを確かめる
- 未登録のときは `words` が失敗する。これは意図した動きで、黙って通さないため
- 改行は LF にする。Actions はステップの `env:` をログに表示し、secret を隠す。改行区切りの値も行ごとに隠れることを、最初の登録の直後に確かめる。次の結果が 0 でなければ、すぐにその実行のログを消して (`gh run delete <id>`) 原因を調べる

```bash
gh run view <run の id> -R CircleAround/arata --log | grep -ciE -f sensitive-patterns.txt
```

## 必須チェックにする

main を守る設定が無いと、検査が失敗してもマージできる。`gitleaks` と `words` を必須にする。
`github-text` は PR で動かないので必須にしない。`words` はフォークと Dependabot の PR でも成功で終わるので、必須にしても止まらない。

Settings → Rules → Rulesets → New branch ruleset で、対象を既定の枝にし、Require status checks to pass に `gitleaks` と `words` を足す。`gh` では次のとおり。

```bash
gh api -X POST repos/CircleAround/arata/rulesets --input - <<'JSON'
{
  "name": "secrets-scan",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [{
    "type": "required_status_checks",
    "parameters": {
      "strict_required_status_checks_policy": false,
      "required_status_checks": [{"context": "gitleaks"}, {"context": "words"}]
    }
  }]
}
JSON
```

GitHub のプランによっては、非公開リポジトリで ruleset が効かない。公開するときに効いていることを確かめる。

## ローカルで回す

`gitleaks` は最初の実行で `bin/` に入る (版とチェックサムは `tools/install-gitleaks.sh`)。一覧は `~/.config/arata/sensitive-patterns.txt` に権限 600 で置く。別の場所なら `SENSITIVE_PATTERNS_FILE=` で渡す。

```bash
make scan-sensitive           # 作業ツリーの禁止語と、未コミットの変更の秘密 (コミットの前)
make scan-sensitive-push      # 送るコミットの秘密 (push の前)
make scan-sensitive-history   # 全履歴の禁止語と秘密 (main の CI と同じ)
make scan-sensitive-github    # GitHub の本文 (gh の認証が要る)
```

コミットの前に自動で回すには、pre-commit のフックにする。

```bash
printf '#!/bin/sh\nexec make scan-sensitive\n' > "$(git rev-parse --git-path hooks)/pre-commit"
chmod +x "$(git rev-parse --git-path hooks)/pre-commit"
```

`make scan-sensitive` はコミットした変更を読まないので、push の前には `make scan-sensitive-push` を流す。読むのは上流があれば `上流..HEAD`、無ければ `origin/main..HEAD` の差分とコミットメッセージで、禁止語は見ない (`make scan-sensitive-history` で見る)。`origin/main` が古いと範囲が広がるので、先に `git fetch` する。

push のたびに自動で回すには、pre-push のフックにする。送る参照ごとに、そのリモートの追跡参照にまだ無いコミットを読み、見つかれば push を止める。

```bash
printf '#!/bin/sh\nexec tools/scan-commits.sh --pre-push "$1"\n' > "$(git rev-parse --git-path hooks)/pre-push"
chmod +x "$(git rev-parse --git-path hooks)/pre-push"
```

- フックは全部の worktree で共通。`tools/scan-commits.sh` が無い古い枝や、`bin/gitleaks` が無い worktree では push が止まる。後者は `make bin/gitleaks` で入れる (別の場所のものを使うなら環境変数 `GITLEAKS`)
- 同じ名前のフックがすでにあれば、上書きせずに中身を足す

## 見つかったときの対処

`wordscan` の出力は場所だけで、語は出さない。

| 出力 | 場所 |
|---|---|
| `docs/a.md:12` | 作業ツリー、または書き出した本文 (`pr-38.txt` など) の行 |
| `blob <oid> docs/a.md:12` | 履歴の中のファイルの行。`git show <oid>` |
| `commit <oid>:8` | コミットのヘッダとメッセージの行。`git cat-file commit <oid>` |
| `tag <oid>:5` / `tree <oid>: ファイル名が一致` | タグの本文 / 履歴の中のファイル名 |
| `file#3` / `ref#2` | 語を含むので名前を伏せたファイルや参照。`git ls-files --cached --others --exclude-standard \| sort \| sed -n 3p` / `git for-each-ref \| sed -n 2p` |

1. **本物か確かめる**。手元で一覧と照らす。確かめた内容を PR やログに書かない
2. **秘密なら先に無効にする** (キーの失効、Webhook の作り直し)。消すより先に行う。公開された秘密は消しても漏れたものとして扱う
3. **まだ push していない**: 架空の値に直し、コミットを作り直す。**push 済みのマージ前の枝**で本物の値なら、同じく作り直す (force push になるので、先に担当者と相談する)。PR の本文やコメントは編集する
4. **main の履歴・Release・マージ済みの PR**: 最新のツリーは架空の値に直す。履歴の書き換えは全員の clone に影響するので、担当者が判断する。書き換えても GitHub の `refs/pull/*` には残るので、消すには GitHub のサポートへの依頼が要る
5. **誤検知** (秘密でも実在の値でもないと確かめられたもの): 枝は書き換えない。下の手順で直す。語の誤検知なら一覧の正規表現を狭める (`\bword\b` など)。実在の値を許可リストや `.gitleaksignore` に足して検査を通さない

検査の失敗は担当者が直すまで続く。定期実行の失敗は、ワークフローを最後に変えた人に GitHub の通知が届く。

### gitleaks の誤検知を、枝を書き換えずに直す

gitleaks はコミットごとの差分を読むので、値を直すコミットを足しても、前のコミットは見つかり続ける。前のコミットの分は `.gitleaksignore` に指紋を書いて外す。

1. 値を直す。引っかからない架空の値にする。同じ形の値をこれからも書くなら、`.gitleaks.toml` の許可リストに足す
2. 指紋を調べる。`-v` で `Fingerprint:` (`コミット:ファイル:規則:行`) が出る。CI のログには出ないので手元で流す

   ```bash
   bin/gitleaks git -v --redact -c .gitleaks.toml --log-opts=origin/main..HEAD .
   ```

3. リポジトリの一番上の `.gitleaksignore` に 1 行 1 指紋で足し、上の行に `#` で理由を書く (見つかった値は書かない)
4. 直しと `.gitleaksignore` をコミットして push する

- 指紋はコミットの ID を含む。squash や rebase でマージするとコミットが変わるので、値を直さずに指紋だけで外すと、マージ後の main でまた見つかる。手順 1 を飛ばさない
- 全部の枝を読む検査 (main への push、毎日) は main の `.gitleaksignore` で動く。PR を出してからマージするまでは、その枝の前のコミットで落ちうる。PR を閉じて枝を残すなら、指紋の行だけを main に入れる
- **コミットメッセージ**の検出には指紋が無く、`.gitleaksignore` では外せない。架空の値なら `.gitleaks.toml` の許可リストに足す。足せない値なら、書き換えるかを担当者が判断する
- PR のタイトルと本文の検出は、本文を編集すれば直る

## gitleaks の版を上げる

Dependabot の対象外なので手で上げる。公開から 7 日以上の版を選び、公開の `checksums.txt` の値を `tools/install-gitleaks.sh` に写す。

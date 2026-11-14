package ai

import (
	"regexp"
	"strings"
	"testing"
)

// TestSections は各トピックの見出しを固定する。見出しを変えたら help ai を読む側 (組み込みの LLM プロンプト) も見直すこと。
func TestSections(t *testing.T) {
	want := map[string][]string{
		"ai":        {"概要", "概念", "コマンド", "終了コード", "標準エラーのログと code", "allowlist.yaml の形式", "認証の注意", "次に読むもの", "出力を機械で読むとき"},
		"ai report": {"report.json の構造", "読む順序", "要約の手順", "相関付け", "分類の基準", "書いてはいけないこと", "追加の裏取り (任意)", "WAF の修正提案の候補 (proposals)", "期間レポート (report --month / --from --to)", "approve について"},
		"ai approve": {"原則", "allowlist.yaml を PR で直す運用", "承認してよい主体の目安", "SaaS 連携は account で承認する", "行き先を既知にする (assume_destinations)", "監査する側のアカウント (audit_account)", "外部アカウント root の見方", "arn_pattern の使いどころ",
			"期限付き承認の使いどころ", "tags の語彙", "access_denied が鳴ったとき", "principal_new_source・secret_access が鳴ったとき", "approve ではなく ack / snooze / resolve にするもの"},
		"ai runtime":       {"使い方", "リポジトリと fork", "ワークフローのトリガー", "OIDC の信頼", "main の保護と書き込み権限", "secrets", "Actions の設定", "ワークフローの形", "監査対象の前提 (context_file) の下書き", "報告の書き方"},
		"ai onboarding":    {"流れ", "最初の run で出るもの", "1 件ずつ片付ける", "ack・snooze・resolve の使い分け", "導入作業の記録を拾う", "定時の通知を始める", "チェックやソースを後から足すとき", "設定の値は、推測せずに実データとアプリのコードで決める"},
		"ai logs":          {"使い方", "チェックと記録の対応", "記録ごとの集め方", "保存期間と費用", "設定の書き方", "確かめ方", "よく詰まる点", "外部の拠り所"},
		"ai request_lines": {"使い方", "見本 (Rails の既定のログ)", "書き方の決まり", "鍵 (request.id) の書き方", "ステータスの行が複数あるリクエスト (Devise のログインの失敗)", "ユーザー ID と auth の行 (アプリに足す行)", "確かめ方", "送る側が選べる値", "数え方"},
		"ai user_id":       {"使い方", "アプリに足す行", "出す時点と読み方 (Rails + Devise の例)", "設定の書き方", "debug_sql (消えうる取り方)", "確かめ方と出る場所"},
		"ai playbook":      {"使い方", "一覧"},
	}
	for _, tp := range Topics {
		d := tp.Parse()
		var got []string
		for _, s := range d.Sections {
			got = append(got, s.Title)
			if s.Body == "" {
				t.Errorf("%s: section %q is empty", tp.Name, s.Title)
			}
		}
		if strings.Join(got, "|") != strings.Join(want[tp.Name], "|") {
			t.Errorf("%s sections:\n got %v\nwant %v", tp.Name, got, want[tp.Name])
		}
		if d.Title == "" {
			t.Errorf("%s: no title", tp.Name)
		}
		if n := strings.Count(tp.Markdown(), "\n"); n > 150 {
			t.Errorf("%s: %d lines (keep it within about 150)", tp.Name, n)
		}
	}
}

func TestLookup(t *testing.T) {
	for _, sub := range []string{"", "report", "approve", "runtime", "onboarding", "logs", "request_lines", "user_id", "playbook", "playbook root_usage"} {
		if _, err := Lookup(sub); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Lookup("nope"); err == nil || !strings.Contains(err.Error(), "arata help ai report") || !strings.Contains(err.Error(), "arata help ai playbook") {
		t.Fatalf("%v", err)
	}
	if _, err := Lookup("playbook nope"); err == nil || !strings.Contains(err.Error(), "root_usage") {
		t.Fatalf("unknown playbook must list the checks: %v", err)
	}
}

// TestCodesDocumented は help ai に固定語彙の code が全部書かれていることを確かめる。
func TestCodesDocumented(t *testing.T) {
	idx, _ := Lookup("")
	for _, code := range []string{"ACCESS_DENIED", "LOG_GROUP_MISSING", "FORMAT_MISMATCH", "FORMAT_DRIFT", "QUERY_LIMIT", "QUERY_INVALID", "STORE_LOCKED", "STORE_CORRUPT", "RUN_MISSED", "COLLECT_FAILED", "CONFIG_INVALID"} {
		if !strings.Contains(idx.Markdown(), "`"+code+"`") {
			t.Errorf("code %s is not documented", code)
		}
	}
}

// TestPlaybooks は playbook の書式を固定する。見出しは aratam が LLM の system に埋め込むときの約束でもある。
func TestPlaybooks(t *testing.T) {
	names := PlaybookNames()
	if len(names) == 0 {
		t.Fatal("no playbooks")
	}
	acct := regexp.MustCompile(`\b\d{12}\b`)
	email := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	for _, name := range names {
		body, ok := Playbook(name)
		if !ok || body == "" {
			t.Fatalf("%s: Playbook() is empty", name)
		}
		tp, err := Lookup("playbook " + name)
		if err != nil {
			t.Fatal(err)
		}
		if tp.Markdown() != body {
			t.Fatalf("%s: help ai playbook differs from Playbook()", name)
		}
		d := tp.Parse()
		if !strings.HasPrefix(d.Title, name+": ") {
			t.Errorf("%s: title %q must start with %q", name, d.Title, name+": ")
		}
		var got []string
		for _, s := range d.Sections {
			got = append(got, s.Title)
			if s.Body == "" {
				t.Errorf("%s: section %q is empty", name, s.Title)
			}
		}
		if strings.Join(got, "|") != strings.Join(PlaybookSections, "|") {
			t.Errorf("%s sections:\n got %v\nwant %v", name, got, PlaybookSections)
		}
		sec := map[string]string{}
		for _, s := range d.Sections {
			sec[s.Title] = s.Body
		}
		if !strings.Contains(sec["まず確かめること"], "\n2. ") && !strings.HasPrefix(sec["まず確かめること"], "1. ") {
			t.Errorf("%s: まず確かめること must be a numbered list", name)
		}
		if !strings.Contains(sec["まず確かめること"], "arata ") {
			t.Errorf("%s: まず確かめること must name an arata command", name)
		}
		// 封じ込めや状態の変更は人が判断する (approve と同じ方針)
		if !strings.Contains(sec["対処の選択肢"], "人が") {
			t.Errorf("%s: 対処の選択肢 must say that a person decides", name)
		}
		// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスは書かない
		for _, id := range acct.FindAllString(body, -1) {
			if id != "123456789012" && id != "111122223333" {
				t.Errorf("%s: account id %s (use 123456789012 / 111122223333)", name, id)
			}
		}
		if m := email.FindString(body); m != "" {
			t.Errorf("%s: email address %q", name, m)
		}
		if n := strings.Count(body, "\n"); n > 120 {
			t.Errorf("%s: %d lines (keep it within about 120)", name, n)
		}
	}
	if _, ok := Playbook("nope"); ok {
		t.Fatal("unknown check must not have a playbook")
	}
	idx, _ := Lookup("playbook")
	for _, name := range names {
		if !strings.Contains(idx.Markdown(), "`arata help ai playbook "+name+"`") {
			t.Errorf("playbook index lacks %s", name)
		}
	}
}

// TestRuntimeChecklist は実行環境 (GitHub Actions) のチェックリストが、確かめる設定の名前と守る規則を持つことを固定する。
func TestRuntimeChecklist(t *testing.T) {
	tp, err := Lookup("runtime")
	if err != nil {
		t.Fatal(err)
	}
	body := tp.Markdown()
	for _, want := range []string{
		// 確かめる設定 (GitHub の API の項目名とエンドポイント)
		"allow_forking", "members_can_fork_private_repositories", "fork-pr-workflows-private-repos",
		"pull_request_target", "actions/oidc/customization/sub", "use_immutable_subject", "rules/branches/main",
		"default_workflow_permissions", "sha_pinning_required", "selected-actions", "persist-credentials: false",
		"aws-actions/configure-aws-credentials@*", "deployment_branch_policy",
		// sub の形 (ID 入り、1 つのブランチ)
		"repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("help ai runtime lacks %q", want)
		}
	}
	sec := map[string]string{}
	for _, s := range tp.Parse().Sections {
		sec[s.Title] = s.Body
	}
	// 設定を変えるのは人 (LLM は読むだけ。approve と同じ方針)
	if !strings.Contains(sec["使い方"], "人が") || !strings.Contains(sec["使い方"], "読み取り") {
		t.Errorf("使い方 must say that the LLM only reads and a person changes the settings")
	}
	// 環境を作るときは context_file の下書きまで行う。マージは人、前提は承認の代わりにならない
	for _, want := range []string{"llm.context_file", "下書き", "人が", "allowlist", "未確認"} {
		if !strings.Contains(sec["監査対象の前提 (context_file) の下書き"], want) {
			t.Errorf("the context_file section lacks %q", want)
		}
	}
	// 読み取りの例だけを書く: 設定を書き換える gh api の呼び出し (-X / --method / -f / -F) を載せない
	if m := regexp.MustCompile(`gh api[^\n]*\s(-X|--method|-f|-F|--field|--raw-field|--input)\s`).FindString(body); m != "" {
		t.Errorf("help ai runtime must show read-only gh api calls only: %q", m)
	}
	// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスは書かない
	for _, id := range regexp.MustCompile(`\b\d{12}\b`).FindAllString(body, -1) {
		if id != "123456789012" && id != "111122223333" {
			t.Errorf("account id %s (use 123456789012 / 111122223333)", id)
		}
	}
	// 入口から案内している
	idx, _ := Lookup("")
	if !strings.Contains(idx.Markdown(), "arata help ai runtime") {
		t.Errorf("help ai must point to arata help ai runtime")
	}
}

// TestPlaybookMentioned は help ai と help ai report から playbook へ案内していることを確かめる。
func TestPlaybookMentioned(t *testing.T) {
	for _, sub := range []string{"", "report"} {
		tp, _ := Lookup(sub)
		if !strings.Contains(tp.Markdown(), "arata help ai playbook") {
			t.Errorf("help %s must point to arata help ai playbook", tp.Name)
		}
	}
}

// TestOnboarding は導入の流れ (arata help ai onboarding) が、手順の順番と、片付け方の規則を持つことを固定する。
func TestOnboarding(t *testing.T) {
	tp, err := Lookup("onboarding")
	if err != nil {
		t.Fatal(err)
	}
	body := tp.Markdown()
	sec := map[string]string{}
	for _, s := range tp.Parse().Sections {
		sec[s.Title] = s.Body
	}
	// 流れ: この順に並ぶ (config init → doctor → init → 通知なしの run (daily と weekly) → review → もう一度 daily → 定時の通知)
	pos := -1
	for _, want := range []string{"arata config init", "arata doctor", "arata init", "arata run --profile daily", "arata run --profile weekly", "arata review", "arata run --profile daily", "aratam"} {
		i := strings.Index(sec["流れ"][pos+1:], want)
		if i < 0 {
			t.Fatalf("流れ lacks %q (or it is out of order)", want)
		}
		pos += 1 + i
	}
	if !strings.Contains(sec["流れ"], "通知") {
		t.Errorf("流れ must say that the first runs are not notified")
	}
	// 片付け方: 4 つの手段と、承認は人がすること
	for _, want := range []string{"arata approve", "arata ack", "arata snooze", "--until", "allowlist.yaml", "人が"} {
		if !strings.Contains(sec["1 件ずつ片付ける"], want) {
			t.Errorf("1 件ずつ片付ける lacks %q", want)
		}
	}
	// 使い分け: 3 つの状態の違い (設計書 6 章の規則と同じ)
	for _, want := range []string{"`ack`", "`snooze --until", "`resolve`", "再報告しない", "期日", "新規"} {
		if !strings.Contains(sec["ack・snooze・resolve の使い分け"], want) {
			t.Errorf("ack・snooze・resolve の使い分け lacks %q", want)
		}
	}
	// 選び方: 直すつもりなら snooze、ack は正規の動きか終わった出来事だけ。報告が来なくなると困るものを ack にしない
	for _, want := range []string{"直すつもりなら snooze", "正規の動き", "終わった出来事", "二度と報告されない", "報告が来なくなると困るものを ack にしない", "重大度"} {
		if !strings.Contains(sec["ack・snooze・resolve の使い分け"], want) {
			t.Errorf("ack・snooze・resolve の使い分け lacks %q", want)
		}
	}
	// 「重大度が上がれば再報告」を当てにできない場面: 最も重い重大度で出たものを ack すると二度と報告されない
	for _, want := range []string{"最も重い重大度", "上がる余地が無い", "当てにできない"} {
		if !strings.Contains(sec["ack・snooze・resolve の使い分け"], want) {
			t.Errorf("ack・snooze・resolve の使い分け lacks %q", want)
		}
	}
	// secret_access の一括読み出し (導入直後は min_distinct だけで判定される): snooze で待つ。ack しない。secrets_access では消えない
	for _, want := range []string{"min_distinct", "baseline_days", "baseline_median_distinct", "arata snooze", "ack しない", "初出", "書いても high は消えない"} {
		if !strings.Contains(sec["最初の run で出るもの"], want) {
			t.Errorf("最初の run で出るもの lacks %q", want)
		}
	}
	if strings.Contains(body, "残ったら ack する") {
		t.Errorf("must not tell to ack whatever remains")
	}
	// 導入作業の記録: CloudTrail の配信遅れ (最大 15 分) を待ってからもう一度流す
	for _, want := range []string{"15 分", "arata run --profile daily"} {
		if !strings.Contains(sec["導入作業の記録を拾う"], want) {
			t.Errorf("導入作業の記録を拾う lacks %q", want)
		}
	}
	// 理由: 通知が雑音ばかりだと読まれなくなる。だから通知の前に片付ける
	if !strings.Contains(sec["流れ"], "雑音") {
		t.Errorf("流れ must say why the findings are settled before notifying")
	}
	// 後から足すとき: 最初の導入と同じ順 (手元の設定で doctor → 試しの実行 → 定時の実行が読む設定に入れる → 通知なしのふつうの run → 片付け → 定時)。
	// 落とし穴 (足した後の最初の定時の実行が通知つきだと、溜まっていた指摘がそのまま出る) と、足す時機を書く
	pos = -1
	for _, want := range []string{"arata config check", "arata doctor", "--dry-run --window", "定時の実行が読む設定に入れる", "通知をつながずに", "arata review", "定時の実行に任せる"} {
		i := strings.Index(sec["チェックやソースを後から足すとき"][pos+1:], want)
		if i < 0 {
			t.Fatalf("チェックやソースを後から足すとき lacks %q (or it is out of order)", want)
		}
		pos += 1 + i
	}
	for _, want := range []string{"落とし穴", "定時の実行の直後", "examples/github-actions", "`dry_run`"} {
		if !strings.Contains(sec["チェックやソースを後から足すとき"], want) {
			t.Errorf("チェックやソースを後から足すとき lacks %q", want)
		}
	}
	// 設定の値: 実データとアプリのコードで決める。詳しい内容は request_lines と logs に任せ、ここには書き写さない
	for _, want := range []string{"failure_statuses", "request_id", "実際のステータスと見比べる", "arata help ai request_lines", "arata help ai logs", "request.id", "取り違え", "param_fields", "filter_parameters", "ライブラリの版"} {
		if !strings.Contains(sec["設定の値は、推測せずに実データとアプリのコードで決める"], want) {
			t.Errorf("設定の値は、推測せずに実データとアプリのコードで決める lacks %q", want)
		}
	}
	// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスも IP アドレスも書かない
	for _, id := range regexp.MustCompile(`\b\d{12}\b`).FindAllString(body, -1) {
		if id != "123456789012" && id != "111122223333" {
			t.Errorf("account id %s (use 123456789012 / 111122223333)", id)
		}
	}
	if m := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`).FindString(body); m != "" {
		t.Errorf("email address %q", m)
	}
	if m := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`).FindString(body); m != "" {
		t.Errorf("ip address %q", m)
	}
	// 入口と、状態を変える判断の文書から案内している
	for _, sub := range []string{"", "approve"} {
		other, _ := Lookup(sub)
		if !strings.Contains(other.Markdown(), "arata help ai onboarding") {
			t.Errorf("help %s must point to arata help ai onboarding", other.Name)
		}
	}
}

// TestDeviseStatus は Devise のログの 401 を、版と条件を付けた事実として書いていることを固定する。
// 決定: 「HTTP の 401 ではない」と言い切らない (API や XHR のログインでは本当の 401 を返す)。確かめ方を必ず添える。
func TestDeviseStatus(t *testing.T) {
	for _, sub := range []string{"request_lines", "logs", "onboarding"} {
		tp, err := Lookup(sub)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"HTTP の 401 ではない", "`[401]` は書かない"} {
			if strings.Contains(tp.Markdown(), bad) {
				t.Errorf("help %s must not state %q unconditionally", tp.Name, bad)
			}
		}
	}
	tp, _ := Lookup("request_lines")
	var body string
	for _, s := range tp.Parse().Sections {
		if s.Title == "ステータスの行が複数あるリクエスト (Devise のログインの失敗)" {
			body = s.Body
		}
	}
	for _, want := range []string{
		"devise 4.9.4", "違うことがある", "throw :warden", // 版と、ログの 401 が入る仕組み
		"recall", "redirect", "http_auth", "本当の 401", "XHR", // failure app の場合分け
		"error_status", "navigational_formats", "http_authenticatable", "failure app や strategy", // 変わり得る設定
		"見比べる", "ALB", // 確かめ方
		"recall と分かった場合", "`[200]`", "`[422]`", // failure_statuses の勧めは条件付き
		"確かめたアプリでは", // 401 だけで終わる場合も条件付き
	} {
		if !strings.Contains(body, want) {
			t.Errorf("request_lines (Devise) lacks %q", want)
		}
	}
}

// TestRequestUserLines は、アプリに足す行 (actor / auth) の見本と設定の書き方が文書にあることを固定する (ADR 0052)。
// request_lines には見本と設定の書き方を短く、user_id には行の意味・出し方・値の決まり・確かめ方を書く。
// 見本の正規表現は、収集のテスト (internal/collect/cwlogs の actorRegex / authRegex) が実際に流しているものと同じ。
func TestRequestUserLines(t *testing.T) {
	regexes := []string{
		`regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] actor kind=(?P<user_kind>[a-z_]{1,32}) id=(?P<user_id>[A-Za-z0-9_-]{1,64})(?: by=(?P<by_kind>[a-z_]{1,32}):(?P<by_id>[A-Za-z0-9_-]{1,64}))?$'`,
		`regex: ' -- : \[[A-Za-z0-9_@-]{1,255}\] auth result=(?P<auth_result>success|failure|impersonate) kind=(?P<auth_kind>[a-z_]{1,32}) id=(?P<auth_id>[A-Za-z0-9_-]{1,64})(?: via=(?P<auth_via>password|remember))?(?: by=(?P<auth_by_kind>[a-z_]{1,32}):(?P<auth_by_id>[A-Za-z0-9_-]{1,64}))?(?: reason=(?P<auth_reason>[a-z_]{1,64}))?$'`,
	}
	tp, _ := Lookup("request_lines")
	var body string
	for _, s := range tp.Parse().Sections {
		if s.Title == "ユーザー ID と auth の行 (アプリに足す行)" {
			body = s.Body
		}
	}
	for _, want := range append([]string{
		"actor kind=user id=42 by=staff:5", "auth result=failure kind=user id=none reason=not_found_in_database", // アプリに足す行の見本
		"from: app_line", "debug_sql", "`$` で終える", "前の区切り", "捨てて数だけ残す", "0 件の run", "skip", "coverage.checks_skipped", // 設定の書き方と決まり
		"メールアドレス・氏名・ログイン名は出さない", "arata help ai user_id",
	}, regexes...) {
		if !strings.Contains(body, want) {
			t.Errorf("request_lines (ユーザー ID) lacks %q", want)
		}
	}
	tp, _ = Lookup("user_id")
	md := tp.Markdown()
	for _, want := range append([]string{
		// アプリに足す行の見本
		"] actor kind=user id=42\n", "actor kind=user id=42 by=staff:5", "auth result=success kind=user id=42 via=password",
		"auth result=failure kind=user id=none reason=not_found_in_database", "auth result=impersonate kind=user id=42 by=staff:5",
		"認可に使った、ログインした身元の 1 人だけ", "`by` が実際に操作した人", "`result` → `kind` → `id` → `via` → `by` → `reason`",
		// 出す時点と読み方
		"prepend_around_action", "ensure", "warden.user(scope: :user, run_callbacks: false)", "after_action は動かない", "副作用なしに読む",
		// 出さないもの
		"メールアドレス・氏名・ログイン名", "パスの中の ID (操作の対象) は出さない",
		// 設定と決まり
		"from: app_line", "`$` で終える", "前の区切りから書く", "捨てて数だけ残す", "`auth_` が付くのは",
		// 消えうる取り方と、0 件の run
		"消えうる取り方", "ずっと warn", "0 件の run", "skip", "coverage.checks_skipped",
		// 出る場所
		"coverage.formats[].requests.users", "user_rate", "user_id_invalid", "本数とスキャン量は増えない", "arata config check",
	}, regexes...) {
		if !strings.Contains(md, want) {
			t.Errorf("user_id lacks %q", want)
		}
	}
	// 個人を特定できる値を出す例を載せない。副作用のある読み方 (current_user) を例のコードに使わない
	for _, bad := range []string{"email=", "name=", "current_user.id"} {
		if strings.Contains(md, bad) || strings.Contains(body, bad) {
			t.Errorf("the docs must not show %q", bad)
		}
	}
}

// TestLogs は記録の集め方 (arata help ai logs) が、記録ごとの勧め・確かめ方・詰まりやすい点を持つことを固定する。
// チェックと記録の対応表がコードと合っていることは internal/engine の TestLogsGuideTable が確かめる。
func TestLogs(t *testing.T) {
	tp, err := Lookup("logs")
	if err != nil {
		t.Fatal(err)
	}
	body := tp.Markdown()
	sec := map[string]string{}
	for _, s := range tp.Parse().Sections {
		sec[s.Title] = s.Body
	}
	for title, wants := range map[string][]string{
		// 記録ごとの勧め: ALB は配信 (plain・既定の項目)、WAF はロググループ名の決まり、nginx は combined、アプリは 1 行の JSON
		"記録ごとの集め方": {"alb_access", "Integrations", "plain", "aws-waf-logs-", "combined", "awslogs", "lograge", "remote_ip", "slog", "pino", "cloudtrail-lookup", "90 日"},
		// 保存期間は平常帯より長く。短くする操作は defense_evasion が報告する。WAF は上限を必ず置く
		"保存期間と費用": {"baseline_days", "min_log_retention_days", "defense_evasion", "max_scan_gb", "QUERY_LIMIT", "USD"},
		"設定の書き方":  {"kind: cloudwatch-logs", "prod-nginx-access", "format: json", "fields:", "expected_match_rate", "stream_prefix"},
		"確かめ方":    {"arata doctor", "match_rate", "FORMAT_MISMATCH", "LOG_GROUP_MISSING", "skip", "coverage.formats"},
		// 一般化した詰まりやすい点: Devise の 200、配信先のロググループ名、複数行のログ、証跡が無くても動くこと
		"よく詰まる点": {"Devise", "failure_statuses: [200]", "devise 4.9.4", "実際の応答と違うことがある", "本当の 401", "見比べ", "最後の値", "`[422]`", "error_status", "/aws/vendedlogs/", "複数行", "LookupEvents", "X-Forwarded-For"},
		"外部の拠り所": {"Well-Architected", "CIS AWS Foundations Benchmark"},
	} {
		for _, want := range wants {
			if !strings.Contains(sec[title], want) {
				t.Errorf("%s lacks %q", title, want)
			}
		}
	}
	// arata は読み取り専用。記録を出す設定を変えるのは人 (LLM は読んで提案するまで)
	if !strings.Contains(sec["使い方"], "人が") || !strings.Contains(sec["使い方"], "読み取り") {
		t.Errorf("使い方 must say that arata only reads and a person changes the logging settings")
	}
	// 顧客の情報を書かない: アカウント ID は架空の値だけ、メールアドレスは書かない
	for _, id := range regexp.MustCompile(`\b\d{12}\b`).FindAllString(body, -1) {
		if id != "123456789012" && id != "111122223333" {
			t.Errorf("account id %s (use 123456789012 / 111122223333)", id)
		}
	}
	if m := regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`).FindString(body); m != "" {
		t.Errorf("email address %q", m)
	}
	// 入口と導入の流れから案内している
	for _, sub := range []string{"", "onboarding"} {
		other, _ := Lookup(sub)
		if !strings.Contains(other.Markdown(), "arata help ai logs") {
			t.Errorf("help %s must point to arata help ai logs", other.Name)
		}
	}
}

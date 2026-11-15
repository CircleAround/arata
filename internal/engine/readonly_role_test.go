package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
)

// 顧客に配る読み取り専用ロール (deploy/iam/readonly-role.yaml) の権限が、doctor が列挙する action と過不足なく一致することを固定する。
// collector に API を足したらロールにも足す (足し忘れると顧客の環境で ACCESS_DENIED になる)。書き込み系は iam:GenerateCredentialReport だけ。
func TestReadonlyRoleActionsMatchRequiredActions(t *testing.T) {
	want := map[string]bool{"cloudtrail:LookupEvents": true}
	for _, a := range cwlogs.RequiredActions {
		want[a] = true
	}
	for _, as := range account.RequiredActions {
		for _, a := range as {
			want[a] = true
		}
	}

	// 決定 (ADR 0062): ロググループを一覧に絞っても (1 つ・複数)、全部 (*) でも、collector に要る action は揃う
	for _, allowed := range []string{"*", "prod-nginx-access", "prod-nginx-access,prod-api"} {
		got := map[string]bool{}
		for _, st := range roleStatements(t, map[string]string{"DeniedLogGroupNames": "prod-mail-delivery", "AllowedLogGroupNames": allowed}) {
			// 許可を数える。Deny の文 (DeniedLogGroupNames) の action は、権限を足さないので doctor の一覧と突き合わせない
			if st.effect != "Allow" {
				continue
			}
			for _, a := range st.actions {
				got[a] = true
			}
		}

		if diff := setDiff(want, got); len(diff) > 0 {
			t.Errorf("AllowedLogGroupNames=%s: ロールに無い action: %v", allowed, diff)
		}
		if diff := setDiff(got, want); len(diff) > 0 {
			t.Errorf("AllowedLogGroupNames=%s: doctor の一覧に無い action がロールにある: %v", allowed, diff)
		}
	}
}

// 決定 (ADR 0053): DeniedLogGroupNames が空なら Deny の文を出さない (これまでのロールと同じポリシーになる)。
func TestReadonlyRoleNoDenyByDefault(t *testing.T) {
	sts := roleStatements(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": "*"})
	if len(sts) == 0 {
		t.Fatal("文が 1 つも無い")
	}
	for _, st := range sts {
		if st.effect != "Allow" {
			t.Errorf("既定 (空) なのに %s の文がある: %+v", st.effect, st)
		}
	}
	tmpl := readRoleTemplate(t)
	if d := tmpl.param(t, "DeniedLogGroupNames")["Default"]; d != "" {
		t.Errorf("DeniedLogGroupNames の既定は空のはず: %q", d)
	}
}

// 指定したロググループの中身を読む操作を、明示の Deny で止める。Allow から外すだけにはしない (ほかのポリシーが付いても効く)。
func TestReadonlyRoleDeniesLogGroups(t *testing.T) {
	sts := roleStatements(t, map[string]string{"DeniedLogGroupNames": "prod-mail-delivery,/app/prod/mail-bounce", "AllowedLogGroupNames": "*"})
	var deny []roleStatement
	for _, st := range sts {
		if st.effect != "Allow" {
			deny = append(deny, st)
		}
	}
	if len(deny) != 1 || deny[0].effect != "Deny" {
		t.Fatalf("Deny の文が 1 つのはず: %+v", deny)
	}
	st := deny[0]
	if st.hasNot {
		t.Error("Deny の文に NotAction / NotResource / Condition を使わない (当たる範囲を読み違えやすい)")
	}

	// ロググループそのもの (StartQuery・FilterLogEvents など) と、その下のログストリーム (GetLogEvents) の両方。
	// リージョン・アカウント・パーティションは * (どのリージョンの同じ名前も読ませない)。
	wantRes := []string{
		"arn:*:logs:*:*:log-group:prod-mail-delivery",
		"arn:*:logs:*:*:log-group:/app/prod/mail-bounce",
		"arn:*:logs:*:*:log-group:prod-mail-delivery:*",
		"arn:*:logs:*:*:log-group:/app/prod/mail-bounce:*",
	}
	if !reflect.DeepEqual(st.resources, wantRes) {
		t.Errorf("Resource\n got %q\nwant %q", st.resources, wantRes)
	}

	// ログの行・項目の値を返す操作 (AWS の Service Authorization Reference で log-group / log-stream を対象に取る Read)。
	got := map[string]bool{}
	for _, a := range st.actions {
		if strings.ContainsAny(a, "*?") {
			t.Errorf("Deny の action にワイルドカードを使わない (DescribeLogGroups まで止めると doctor の log_group が読めなくなる): %s", a)
		}
		got[a] = true
	}
	for _, a := range []string{
		"logs:StartQuery", "logs:GetQueryResults", "logs:GetLogRecord", "logs:GetLogEvents",
		"logs:FilterLogEvents", "logs:StartLiveTail", "logs:GetLogGroupFields", "logs:Unmask",
	} {
		if !got[a] {
			t.Errorf("Deny に %s が無い", a)
		}
	}
	// arata が中身を読む action (StartQuery・GetQueryResults) は必ず Deny に入っている。一覧 (DescribeLogGroups) と StopQuery は中身を返さないので入れない
	for _, a := range []string{cwlogs.ActionDescribeLogGroups, cwlogs.ActionStopQuery} {
		if got[a] {
			t.Errorf("Deny に %s を入れない", a)
		}
	}
}

// 名前はそのまま ARN に入るので、ワイルドカード・空白・コロン・空の要素を CloudFormation の検証 (AllowedPattern) で弾く。
// `*` 1 つで全部のロググループを止めてしまう・前後の空白で 1 つも当たらない、を黙って通さない。
func TestReadonlyRoleDeniedLogGroupNamesPattern(t *testing.T) {
	p := readRoleTemplate(t).param(t, "DeniedLogGroupNames")
	if p["Type"] != "String" {
		t.Fatalf("Type = %q", p["Type"])
	}
	pat := p["AllowedPattern"]
	if !strings.HasPrefix(pat, "^") || !strings.HasSuffix(pat, "$") {
		t.Fatalf("AllowedPattern は全体に固定する: %q", pat)
	}
	re := regexp.MustCompile(pat)
	for _, ok := range []string{"", "prod-mail-delivery", "prod-mail-delivery,prod-mail-bounce", "/aws/lambda/mail_sender.v2", "/app/prod#1,a"} {
		if !re.MatchString(ok) {
			t.Errorf("通るはず: %q", ok)
		}
	}
	for _, ng := range []string{
		"*", "prod-*", "prod-mail-?", "a,*", "a, b", " a", "a ", "a,", ",a", "a,,b",
		"a:b", "a:*", "arn:aws:logs:ap-northeast-1:123456789012:log-group:a", "a\nb", "a\n", "a;b", "${AWS::AccountId}",
	} {
		if re.MatchString(ng) {
			t.Errorf("弾くはず: %q", ng)
		}
	}
}

// 決定 (ADR 0062): AllowedLogGroupNames に並べたロググループだけ、ログの中身を読める (StartQuery・GetQueryResults の Allow を絞る)。
// 一覧に無いロググループは Allow が無いので暗黙の拒否。DescribeLogGroups・StopQuery はリソースの型を持たないので * のまま (中身を返さない)。
func TestReadonlyRoleAllowedLogGroups(t *testing.T) {
	cases := []struct {
		allowed string
		want    []string
	}{
		{"*", []string{"*"}},
		{"prod-nginx-access", []string{
			"arn:*:logs:*:*:log-group:prod-nginx-access",
			"arn:*:logs:*:*:log-group:prod-nginx-access:*",
		}},
		{"prod-nginx-access,/app/prod/api", []string{
			"arn:*:logs:*:*:log-group:prod-nginx-access",
			"arn:*:logs:*:*:log-group:/app/prod/api",
			"arn:*:logs:*:*:log-group:prod-nginx-access:*",
			"arn:*:logs:*:*:log-group:/app/prod/api:*",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.allowed, func(t *testing.T) {
			read, list := logsStatements(t, roleStatements(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": tc.allowed}))
			if got := sortedCopy(read.actions); !reflect.DeepEqual(got, []string{cwlogs.ActionGetQueryResults, cwlogs.ActionStartQuery}) {
				t.Errorf("中身を読む文の action = %q", got)
			}
			if !reflect.DeepEqual(read.resources, tc.want) {
				t.Errorf("Resource\n got %q\nwant %q", read.resources, tc.want)
			}
			if read.hasNot {
				t.Error("Allow の文に NotAction / NotResource / Condition を使わない")
			}
			if got := sortedCopy(list.actions); !reflect.DeepEqual(got, []string{cwlogs.ActionDescribeLogGroups, cwlogs.ActionStopQuery}) {
				t.Errorf("一覧の文の action = %q", got)
			}
			if !reflect.DeepEqual(list.resources, []string{"*"}) {
				t.Errorf("一覧の文の Resource は * のはず: %q", list.resources)
			}
		})
	}
}

// 決定 (ADR 0062): AllowedLogGroupNames=none (値の全体がこの 1 語のときだけ) は、どのロググループの中身も読ませない。
// StartQuery・GetQueryResults の文を出さない (Resource を空にはできない)。一覧の文 (DescribeLogGroups・StopQuery) は残り、ほかの action は変わらない。
func TestReadonlyRoleAllowedLogGroupsNone(t *testing.T) {
	all := map[string]bool{}
	for _, st := range roleStatements(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": "*"}) {
		for _, a := range st.actions {
			all[a] = true
		}
	}
	got := map[string]bool{}
	var list int
	for _, st := range roleStatements(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": "none"}) {
		if st.effect != "Allow" {
			continue
		}
		for _, a := range st.actions {
			got[a] = true
			if a == cwlogs.ActionDescribeLogGroups && reflect.DeepEqual(st.resources, []string{"*"}) {
				list++
			}
		}
	}
	if diff := setDiff(all, got); strings.Join(diff, " ") != cwlogs.ActionGetQueryResults+" "+cwlogs.ActionStartQuery {
		t.Errorf("none で無くなる action は StartQuery・GetQueryResults だけのはず: %v", diff)
	}
	if list != 1 {
		t.Error("none でも DescribeLogGroups (* ) の文は残す")
	}
	if c := mapGet(mapGet(readRoleTemplate(t).root, "Conditions"), "AllowNoLogGroups"); c == nil {
		t.Error("Conditions に AllowNoLogGroups が無い")
	}
}

// Deny と併用できる。どちらの文も出て、Deny は Allow の一覧と独立に組み立てる (両方に書いた名前は、IAM の評価で Deny が勝つ)。
func TestReadonlyRoleAllowedAndDeniedTogether(t *testing.T) {
	sts := roleStatements(t, map[string]string{"DeniedLogGroupNames": "prod-api", "AllowedLogGroupNames": "prod-nginx-access,prod-api"})
	read, _ := logsStatements(t, sts)
	if len(read.resources) != 4 {
		t.Fatalf("Allow の Resource: %q", read.resources)
	}
	var deny []roleStatement
	for _, st := range sts {
		if st.effect == "Deny" {
			deny = append(deny, st)
		}
	}
	if len(deny) != 1 || !reflect.DeepEqual(deny[0].resources, []string{"arn:*:logs:*:*:log-group:prod-api", "arn:*:logs:*:*:log-group:prod-api:*"}) {
		t.Fatalf("Deny: %+v", deny)
	}
}

// 決定 (ADR 0062): AllowedLogGroupNames は既定を持たない (更新でも値が要る)。全部を読ませるには * 1 文字だけを書く。
// 名前の文字の規則は DeniedLogGroupNames と同じ。空・部分的なワイルドカード・空白・コロン・ARN は弾く。
func TestReadonlyRoleAllowedLogGroupNamesPattern(t *testing.T) {
	tmpl := readRoleTemplate(t)
	p := tmpl.param(t, "AllowedLogGroupNames")
	if p["Type"] != "String" {
		t.Fatalf("Type = %q", p["Type"])
	}
	if _, ok := p["Default"]; ok {
		t.Errorf("AllowedLogGroupNames に Default を書かない (暗黙の既定を持たない): %q", p["Default"])
	}
	if p["ConstraintDescription"] == "" || p["Description"] == "" {
		t.Error("ConstraintDescription と Description を書く")
	}
	pat := p["AllowedPattern"]
	if denied := tmpl.param(t, "DeniedLogGroupNames")["AllowedPattern"]; pat != `^\*$|`+strings.TrimPrefix(denied, "^$|") {
		t.Errorf("名前の規則は DeniedLogGroupNames と同じにする: %q (Deny は %q)", pat, denied)
	}
	re := regexp.MustCompile(pat)
	for _, ok := range []string{"*", "none", "prod-nginx-access", "prod-nginx-access,prod-api", "/aws/lambda/mail_sender.v2", "/app/prod#1,a"} {
		if !re.MatchString(ok) {
			t.Errorf("通るはず: %q", ok)
		}
	}
	for _, ng := range []string{
		"", "**", "prod-*", "prod-?", "a,*", "*,a", " *", "* ", "a, b", " a", "a ", "a,", ",a", "a,,b",
		"a:b", "a:*", "arn:aws:logs:ap-northeast-1:123456789012:log-group:a", "a\nb", "*\n", "a;b", "${AWS::AccountId}",
	} {
		if re.MatchString(ng) {
			t.Errorf("弾くはず: %q", ng)
		}
	}
}

// role_params.go の名前の規則は、テンプレートの AllowedPattern の 1 要素と同じ。
func TestRoleLogGroupNameMatchesTemplate(t *testing.T) {
	pat := readRoleTemplate(t).param(t, "AllowedLogGroupNames")["AllowedPattern"]
	elem := strings.TrimSuffix(strings.TrimPrefix(roleLogGroupName.String(), "^"), "$")
	if want := `^\*$|^` + elem + `(,` + elem + `)*$`; pat != want {
		t.Fatalf("AllowedPattern %q, role_params.go から作ると %q", pat, want)
	}
}

// role_params.go のポリシーの大きさの見積もりは、実際のテンプレートが作るポリシー (空白を除いた JSON) 以上で、離れすぎない。
func TestRolePolicySizeEstimate(t *testing.T) {
	base := rolePolicySize(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": "*"})
	if base > rolePolicyBase || rolePolicyBase-base > 300 {
		t.Errorf("全部 (*) のポリシーは %d 文字。rolePolicyBase (%d) を合わせる", base, rolePolicyBase)
	}
	for _, names := range [][]string{{"prod-nginx-access"}, {"a", "/app/prod/api", strings.Repeat("x", 200)}} {
		got := rolePolicySize(t, map[string]string{"DeniedLogGroupNames": "", "AllowedLogGroupNames": strings.Join(names, ",")})
		est := rolePolicyBase
		for _, n := range names {
			est += 2*len(n) + rolePolicyPerName
		}
		if got > est || est-got > 300+20*len(names) {
			t.Errorf("%v: 実際 %d 文字、見積もり %d 文字", names, got, est)
		}
	}
}

// rolePolicySize は、パラメータを当てたポリシーの文書を JSON にした大きさ (IAM は空白を数えない)。
func rolePolicySize(t *testing.T, params map[string]string) int {
	t.Helper()
	r := readRoleTemplate(t)
	policies := mapGet(mapGet(mapGet(mapGet(r.root, "Resources"), "Role"), "Properties"), "Policies")
	ev := cfnEval{t: t, params: params, conds: mapGet(r.root, "Conditions")}
	doc := ev.eval(mapGet(policies.Content[0], "PolicyDocument"))
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// logsStatements は、Logs の中身を読む文 (StartQuery を持つ Allow) と、一覧の文 (DescribeLogGroups を持つ Allow) を返す。
func logsStatements(t *testing.T, sts []roleStatement) (read, list roleStatement) {
	t.Helper()
	var nRead, nList int
	for _, st := range sts {
		if st.effect != "Allow" {
			continue
		}
		for _, a := range st.actions {
			switch a {
			case cwlogs.ActionStartQuery:
				read, nRead = st, nRead+1
			case cwlogs.ActionDescribeLogGroups:
				list, nList = st, nList+1
			}
		}
	}
	if nRead != 1 || nList != 1 {
		t.Fatalf("StartQuery の文 %d 個・DescribeLogGroups の文 %d 個 (どちらも 1 個のはず)", nRead, nList)
	}
	return read, list
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// roleStatement はロールのポリシーの 1 文 (組み込み関数を解いた後)。
type roleStatement struct {
	sid       string
	effect    string
	actions   []string
	resources []string
	hasNot    bool
}

type roleTemplate struct{ root *yaml.Node }

func readRoleTemplate(t *testing.T) roleTemplate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "iam", "readonly-role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return roleTemplate{root: doc.Content[0]}
}

func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// param はパラメータの定義 (スカラーの項目だけ) を返す。
func (r roleTemplate) param(t *testing.T, name string) map[string]string {
	t.Helper()
	n := mapGet(mapGet(r.root, "Parameters"), name)
	if n == nil {
		t.Fatalf("パラメータ %s が無い", name)
	}
	out := map[string]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i+1].Kind == yaml.ScalarNode {
			out[n.Content[i].Value] = n.Content[i+1].Value
		}
	}
	return out
}

// roleStatements はテンプレートのポリシーの文を、パラメータを当てて解いて返す (CloudFormation には接続しない)。
// 解く関数は、このテンプレートが使う !Ref・!If・!Not・!Equals・!Join・!Split だけ。知らない関数があればテストを落とす。
func roleStatements(t *testing.T, params map[string]string) []roleStatement {
	t.Helper()
	r := readRoleTemplate(t)
	policies := mapGet(mapGet(mapGet(mapGet(r.root, "Resources"), "Role"), "Properties"), "Policies")
	if policies == nil || len(policies.Content) != 1 {
		t.Fatal("Policies が 1 個のはず")
	}
	ev := cfnEval{t: t, params: params, conds: mapGet(r.root, "Conditions")}
	raw, _ := ev.eval(mapGet(mapGet(policies.Content[0], "PolicyDocument"), "Statement")).([]any)
	var out []roleStatement
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			t.Fatalf("文が mapping でない: %#v", x)
		}
		st := roleStatement{}
		for k, v := range m {
			switch k {
			case "Sid":
				st.sid, _ = v.(string)
			case "Effect":
				st.effect, _ = v.(string)
			case "Action":
				st.actions = toStrings(t, v)
			case "Resource":
				st.resources = toStrings(t, v)
			default: // NotAction・NotResource・Condition・Principal など
				st.hasNot = true
			}
		}
		out = append(out, st)
	}
	return out
}

func toStrings(t *testing.T, v any) []string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				t.Fatalf("文字列でない要素: %#v", e)
			}
			out = append(out, s)
		}
		return out
	}
	t.Fatalf("文字列でも並びでもない: %#v", v)
	return nil
}

type cfnNoValue struct{}

type cfnEval struct {
	t      *testing.T
	params map[string]string
	conds  *yaml.Node
}

func (e cfnEval) eval(n *yaml.Node) any {
	e.t.Helper()
	if n == nil {
		e.t.Fatal("ノードが無い")
	}
	switch n.Tag {
	case "!Ref":
		if n.Value == "AWS::NoValue" {
			return cfnNoValue{}
		}
		v, ok := e.params[n.Value]
		if !ok {
			e.t.Fatalf("テストが値を渡していないパラメータ: %s", n.Value)
		}
		return v
	case "!If":
		if e.cond(n.Content[0].Value) {
			return e.eval(n.Content[1])
		}
		return e.eval(n.Content[2])
	case "!Join":
		parts := toStrings(e.t, e.eval(n.Content[1]))
		return strings.Join(parts, n.Content[0].Value)
	case "!Split":
		s, ok := e.eval(n.Content[1]).(string)
		if !ok {
			e.t.Fatal("!Split の対象が文字列でない")
		}
		var out []any
		for _, p := range strings.Split(s, n.Content[0].Value) {
			out = append(out, p)
		}
		return out
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		e.t.Fatalf("テストが解けない組み込み関数: %s (cfnEval に足す)", n.Tag)
	}
	return e.evalPlain(n)
}

// evalPlain はタグを見ずに、ノードの種類だけで解く (関数の引数の並びにも使う)。
func (e cfnEval) evalPlain(n *yaml.Node) any {
	e.t.Helper()
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value
	case yaml.SequenceNode:
		var out []any
		for _, c := range n.Content {
			v := e.eval(c)
			if _, drop := v.(cfnNoValue); drop {
				continue
			}
			out = append(out, v)
		}
		return out
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			v := e.eval(n.Content[i+1])
			if _, drop := v.(cfnNoValue); drop {
				continue
			}
			out[n.Content[i].Value] = v
		}
		return out
	}
	e.t.Fatalf("解けないノード: kind=%d", n.Kind)
	return nil
}

func (e cfnEval) cond(name string) bool {
	e.t.Helper()
	n := mapGet(e.conds, name)
	if n == nil {
		e.t.Fatalf("Conditions に %s が無い", name)
	}
	return e.condNode(n)
}

func (e cfnEval) condNode(n *yaml.Node) bool {
	e.t.Helper()
	switch n.Tag {
	case "!Not":
		return !e.condNode(n.Content[0])
	case "!Equals":
		return reflect.DeepEqual(e.eval(n.Content[0]), e.eval(n.Content[1]))
	}
	e.t.Fatalf("テストが解けない条件: %s", n.Tag)
	return false
}

// findKey は mapping の中から key の値のノードを再帰的に集める。
func findKey(n *yaml.Node, key string, out *[]*yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				*out = append(*out, n.Content[i+1])
			}
		}
	}
	for _, c := range n.Content {
		findKey(c, key, out)
	}
}

func collectScalars(n *yaml.Node, out map[string]bool) {
	if n.Kind == yaml.ScalarNode {
		out[n.Value] = true
		return
	}
	for _, c := range n.Content {
		collectScalars(c, out)
	}
}

func setDiff(a, b map[string]bool) []string {
	var d []string
	for k := range a {
		if !b[k] {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

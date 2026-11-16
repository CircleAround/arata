package checks

import (
	"sort"
	"strings"
	"unicode"

	"github.com/CircleAround/arata/internal/collect/account"
)

// 目印のルール (ADR 0070): 後ろのルールが使うラベルを付けるために COUNT にしているルール。BLOCK にする候補ではないので、
// count_rule_status (BLOCK にするかの材料) から外し、label_rule の observation として出す。
//
// 決定 (AWS の公式文書で確かめた規則。ADR 0070 に出典):
//   - ラベルを使えるのは、そのルールより後ろ (Priority が大きい) のルールだけ
//   - WebACL のルールのラベルの完全な名前は awswaf:<アカウント>:webacl:<名前>:<RuleLabels の名前>。LabelMatchStatement の鍵は前の名前空間を省ける
//     (省くと同じ WebACL のラベルだけに、区間の単位で後ろから一致する)。awswaf: から書けば完全な名前で一致する
//   - Scope が NAMESPACE の鍵は名前空間 (末尾が ":")。ラベルの名前空間 (名前を除いた部分) が鍵で終わる、または鍵で始まる (完全な名前のとき) なら一致する
//   - マネージドのルールグループのラベルは awswaf:managed:<vendor>:<グループ>: (DescribeManagedRuleGroup の LabelNamespace) の下。どのルールが
//     どのラベルを付けるかは API で分からないので、使われているラベルのうち名前空間の下の部分を英数字だけにしたものが、ルール名を英数字だけにしたもので
//     終わるとき (CategoryHttpLibrary ↔ bot:category:http_library、SizeRestrictions_BODY ↔ SizeRestrictions_Body)、そのルールのラベルとみなす。
//     NAMESPACE の鍵は、その最後の区間でルール名が始まるとき (signal: ↔ SignalAutomatedBrowser)、またはグループの名前空間全体を覆うときに一致とみなす
//   - 見分けられないもの: 名前空間を読めなかったマネージドのグループ、自分のルールグループ (中のルールのラベルを読んでいない)。今までどおり BLOCK にするかの材料として出す

type labelUse struct {
	// labels は使われているラベル (完全な名前か、使う側の鍵)、consumers は使っているルールの名前 (どちらも名前順)。
	labels, consumers []string
}

// labelRuleOf は COUNT のルール cr が目印のルールか (使っているルールがあれば目印)。known が false なら見分けられない。
func labelRuleOf(a *wafACLConf, cr countRule) (use labelUse, known bool) {
	rc, ok := a.rules[cr.rule]
	if !ok {
		return use, false
	}
	prio := rc.Number("priority")
	labels, consumers := map[string]bool{}, map[string]bool{}
	match := func(f func(m string) (string, bool)) {
		for name, q := range a.rules {
			if q.Number("priority") <= prio || q.String("label_matches") == "" {
				continue
			}
			for _, m := range strings.Split(q.String("label_matches"), ",") {
				if l, ok := f(m); ok {
					labels[l], consumers[name] = true, true
				}
			}
		}
	}
	switch {
	case rc.String("type") == account.WAFRuleManagedGroup:
		ns := rc.String("label_namespace")
		if ns == "" || rc.Bool("label_namespace_unknown") {
			return use, false
		}
		match(func(m string) (string, bool) { return managedLabelMatches(m, ns, cr.inner) })
	case rc.String("type") == account.WAFRuleGroup:
		return use, false
	case cr.inner == "":
		for _, l := range splitList(rc.String("labels")) {
			full := a.labelPrefix + l
			match(func(m string) (string, bool) { return full, ownLabelMatches(m, full, a.labelPrefix) })
		}
	}
	return labelUse{labels: sortedSet(labels), consumers: sortedSet(consumers)}, true
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ownLabelMatches は LabelMatchStatement (m = "<LABEL|NAMESPACE>:<鍵>") が WebACL のルールのラベル full (完全な名前) に一致するか。prefix は WebACL の名前空間。
func ownLabelMatches(m, full, prefix string) bool {
	scope, key, ok := strings.Cut(m, ":")
	if !ok || key == "" {
		return false
	}
	qualified := strings.HasPrefix(key, "awswaf:")
	switch scope {
	case "LABEL":
		if qualified {
			return full == key
		}
		return strings.HasPrefix(full, prefix) && (full == prefix+key || strings.HasSuffix(full, ":"+key))
	case "NAMESPACE":
		ns := full[:strings.LastIndex(full, ":")+1]
		if qualified {
			return strings.HasPrefix(ns, key)
		}
		return strings.HasPrefix(full, prefix) && (ns == prefix+key || strings.HasSuffix(ns, ":"+key))
	}
	return false
}

// managedLabelMatches は LabelMatchStatement m が、マネージドのグループ (名前空間 ns) のルール inner のラベルを使っているか。一致したら使われているラベル (鍵) を返す。
// inner が空ならグループ全体を COUNT にしたもので、グループのどのラベルでも一致とみなす。前の名前空間を省いた鍵は同じ WebACL のラベルだけに一致するので、見ない。
func managedLabelMatches(m, ns, inner string) (string, bool) {
	scope, key, ok := strings.Cut(m, ":")
	if !ok || !strings.HasPrefix(key, "awswaf:") {
		return "", false
	}
	switch scope {
	case "LABEL":
		if !strings.HasPrefix(key, ns) {
			return "", false
		}
		if inner == "" || strings.HasSuffix(alnum(key[len(ns):]), alnum(inner)) {
			return key, true
		}
	case "NAMESPACE":
		if strings.HasPrefix(ns, key) {
			return key, true // グループの名前空間全体を覆う
		}
		if !strings.HasPrefix(key, ns) {
			return "", false
		}
		segs := strings.Split(strings.TrimSuffix(key[len(ns):], ":"), ":")
		if inner == "" || strings.HasPrefix(alnum(inner), alnum(segs[len(segs)-1])) {
			return key, true
		}
	}
	return "", false
}

// alnum は英数字だけを小文字にして残す (ラベルとルール名の大小文字・区切りの違いを除く)。
func alnum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

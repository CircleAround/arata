package allowlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// NewEntry は approve が principals に追記する 1 件。主体の指定は ARN / Account / ARNPattern のどれか 1 つ。
type NewEntry struct {
	ARN        string
	Account    string
	ARNPattern string
	Note       string
	ApprovedBy string
	ApprovedAt string // YYYY-MM-DD
	Expires    string // YYYY-MM-DD、空なら無期限
	Tags       []string
	// ExpectedDenied は access_denied で数えない拒否 (「サービス:操作」の glob。ADR 0022)。
	ExpectedDenied []string
}

// principals[].tags の語彙。
const (
	TagDeploy = "deploy" // 既知のデプロイ主体。iam_changes を info に下げる (ADR 0008)
	TagAI     = "ai"     // 監査ロール・AI 用の主体。ai_path_usage が利用を毎回 info に出す (自己監査。設計書 3-4)
)

// KnownTags は principals[].tags の語彙 (ADR 0008)。approve はこれ以外を拒否する。
var KnownTags = []string{TagDeploy, TagAI}

// ErrAlreadyListed は同じ対象のエントリが既にあるときに返る (期限の延長などは人が直接編集する)。
var ErrAlreadyListed = errors.New("allowlist: already listed")

// Subject は追記する対象の表示 (PrincipalEntry.Subject と同じ形)。
func (e NewEntry) Subject() string {
	p := PrincipalEntry{ARN: e.ARN, Account: e.Account, ARNPattern: e.ARNPattern}
	return p.Subject()
}

// Append は path の allowlist.yaml の principals の末尾に e を追記し、追記したテキストを返す。
// ファイルが無ければ作る。書き込みは一時ファイル + rename で行い、書いた結果が Parse できることを確かめてから置き換える。
func Append(path string, e NewEntry) (string, error) {
	src, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("allowlist: %w", err)
	}
	out, added, err := AppendBytes(src, e)
	if err != nil {
		return "", err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".allowlist-*.yaml")
	if err != nil {
		return "", fmt.Errorf("allowlist: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return "", fmt.Errorf("allowlist: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("allowlist: %w", err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return "", fmt.Errorf("allowlist: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("allowlist: %w", err)
	}
	return added, nil
}

// AppendBytes は allowlist.yaml のテキストに e を追記した結果と、追記した部分を返す。
//
// 決定 (ADR 0010): YAML を構造として読み直して書き出すと、空行・コメントの位置・引用符・フロー形式が変わり、
// git の差分が承認と無関係な行に広がる。そこで yaml.v3 の Node で principals の位置 (行番号) だけを特定し、
// 元のテキストはそのまま残して行を差し込む。
//   - principals がブロック形式の列: 最後の要素の後ろ (次のトップレベルのキーの直前。その直前にある 0 桁目のコメントと空行は次のキーのものとして残す)
//   - principals が `[]` / 値なし: その行を `principals:` にして直後に差し込む
//   - principals が無い: ファイルの末尾に `principals:` ごと足す
//   - principals が中身のあるフロー形式 (`[{...}]`): 書き換えずにエラー (人がブロック形式に直す)
func AppendBytes(src []byte, e NewEntry) ([]byte, string, error) {
	if err := e.validate(); err != nil {
		return nil, "", err
	}
	before, err := Parse(src)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: current file is invalid: %w", err)
	}
	for i := range before.Principals {
		if before.Principals[i].Subject() == e.Subject() {
			return nil, "", fmt.Errorf("%w: %s (edit the entry directly to change note / expires / tags)", ErrAlreadyListed, e.Subject())
		}
	}
	text := strings.ReplaceAll(string(src), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // 末尾の改行
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		return nil, "", fmt.Errorf("allowlist: %w", err)
	}
	var doc *yaml.Node
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 && root.Content[0].Kind == yaml.MappingNode {
		doc = root.Content[0]
	}
	var out []string
	var added string
	keyIdx := -1
	if doc != nil {
		for i := 0; i+1 < len(doc.Content); i += 2 {
			if doc.Content[i].Value == "principals" {
				keyIdx = i
			}
		}
	}
	switch {
	case keyIdx < 0:
		added = e.render("  ")
		out = append(out, lines...)
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "principals:")
		out = append(out, strings.Split(strings.TrimSuffix(added, "\n"), "\n")...)
	default:
		key, val := doc.Content[keyIdx], doc.Content[keyIdx+1]
		indent := "  "
		switch {
		case val.Kind == yaml.SequenceNode && val.Style&yaml.FlowStyle == 0 && len(val.Content) > 0:
			first := val.Content[0]
			line := lines[first.Line-1]
			dash := strings.LastIndex(line[:first.Column-1], "-")
			if dash < 0 {
				return nil, "", fmt.Errorf("allowlist: cannot locate the principals list")
			}
			indent = line[:dash]
			added = e.render(indent)
			at := len(lines)
			if keyIdx+2 < len(doc.Content) {
				at = doc.Content[keyIdx+2].Line - 1
			}
			for at > first.Line && (strings.TrimSpace(lines[at-1]) == "" || strings.HasPrefix(lines[at-1], "#")) {
				at--
			}
			out = append(out, lines[:at]...)
			out = append(out, strings.Split(strings.TrimSuffix(added, "\n"), "\n")...)
			out = append(out, lines[at:]...)
		case val.Kind == yaml.SequenceNode && len(val.Content) > 0:
			return nil, "", fmt.Errorf("allowlist: principals is written in flow style; rewrite it as a block list (- arn: ...) before approve")
		case val.Kind == yaml.SequenceNode || val.Tag == "!!null":
			// `principals: []` / `principals:` (値なし)。キーの行を `principals:` (行末コメントは残す) にして直後に差し込む
			line := lines[key.Line-1]
			comment := ""
			if val.LineComment != "" {
				comment = " " + val.LineComment
			} else if key.LineComment != "" {
				comment = " " + key.LineComment
			}
			added = e.render(indent)
			out = append(out, lines[:key.Line-1]...)
			out = append(out, line[:key.Column-1]+"principals:"+comment)
			out = append(out, strings.Split(strings.TrimSuffix(added, "\n"), "\n")...)
			out = append(out, lines[key.Line:]...)
		default:
			return nil, "", fmt.Errorf("allowlist: principals must be a list")
		}
	}
	result := []byte(strings.Join(out, "\n") + "\n")
	after, err := Parse(result)
	if err != nil {
		return nil, "", fmt.Errorf("allowlist: refusing to write an invalid file: %w", err)
	}
	if len(after.Principals) != len(before.Principals)+1 || after.Principals[len(after.Principals)-1].Subject() != e.Subject() {
		return nil, "", fmt.Errorf("allowlist: refusing to write: the new entry did not land at the end of principals")
	}
	return result, added, nil
}

func (e NewEntry) validate() error {
	n := 0
	for _, v := range []string{e.ARN, e.Account, e.ARNPattern} {
		if v != "" {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("allowlist: exactly one of arn, account, arn_pattern is required")
	}
	for _, g := range e.ExpectedDenied {
		if err := CheckDeniedGlob(g); err != nil {
			return fmt.Errorf("allowlist: expected_denied %w", err)
		}
	}
	for _, t := range e.Tags {
		ok := false
		for _, k := range KnownTags {
			ok = ok || t == k
		}
		if !ok {
			return fmt.Errorf("allowlist: unknown tag %q (known: %s)", t, strings.Join(KnownTags, ", "))
		}
	}
	return nil
}

// render は列の 1 要素を indent 付きで書く (末尾改行あり)。
func (e NewEntry) render(indent string) string {
	type kv struct{ k, v string }
	var fields []kv
	switch {
	case e.ARN != "":
		fields = append(fields, kv{"arn", scalar(e.ARN)})
	case e.Account != "":
		fields = append(fields, kv{"account", `"` + e.Account + `"`}) // 数字だけなので文字列として引用する
	default:
		fields = append(fields, kv{"arn_pattern", scalar(e.ARNPattern)})
	}
	if e.Note != "" {
		fields = append(fields, kv{"note", scalar(e.Note)})
	}
	if e.ApprovedBy != "" {
		fields = append(fields, kv{"approved_by", scalar(e.ApprovedBy)})
	}
	if e.ApprovedAt != "" {
		fields = append(fields, kv{"approved_at", e.ApprovedAt})
	}
	if e.Expires != "" {
		fields = append(fields, kv{"expires", e.Expires})
	}
	if len(e.Tags) > 0 {
		fields = append(fields, kv{"tags", "[" + strings.Join(e.Tags, ", ") + "]"})
	}
	if len(e.ExpectedDenied) > 0 {
		fields = append(fields, kv{"expected_denied", FormatExpectedDenied(e.ExpectedDenied)})
	}
	var b strings.Builder
	for i, f := range fields {
		if i == 0 {
			b.WriteString(indent + "- ")
		} else {
			b.WriteString(indent + "  ")
		}
		b.WriteString(f.k + ": " + f.v + "\n")
	}
	return b.String()
}

// scalar は 1 行の文字列を YAML のスカラーとして安全に書く (必要なときだけ引用する)。改行は空白にする。
func scalar(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	b, err := yaml.Marshal(s)
	if err != nil {
		return `""`
	}
	return strings.TrimSuffix(string(b), "\n")
}

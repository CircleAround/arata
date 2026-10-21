package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// 標準の flag だけで書いた小さなサブコマンド層。
// 決定: cobra (と pflag / mousetrap) は使わない。使っていたのはサブコマンド・--x / -x の短縮形・ヘルプ表示・引数の数の検査だけで、
// 標準の flag で無理なく書けるため (設計書 1 章、ADR 0019)。ヘルプの書式は cobra と同じにして、ルートのヘルプのゴールデンを保つ。

// command は 1 つのサブコマンド。Run が nil のものはサブコマンドを束ねるだけで、引数なしならヘルプを出す。
type command struct {
	Use   string // 先頭の語がコマンド名。残りは使い方の表示に使う (例: "approve <finding-id>")
	Short string
	Long  string
	Args  func(c *command, args []string) error
	Run   func(ctx context.Context, args []string) error

	Version string // ルートだけ。空でなければ -v, --version を足す

	parent     *command
	subs       []*command
	flags      []*flagSpec // このコマンドのフラグ (登録順。表示は名前順)
	persistent []*flagSpec // 子孫にも効くフラグ
	required   []string
	stdout     io.Writer
}

type flagSpec struct {
	name, short, typ, usage string
	value                   flag.Value
	defaultText             string // 空ならヘルプに (default ...) を出さない
}

func (c *command) name() string {
	n, _, _ := strings.Cut(c.Use, " ")
	return n
}

func (c *command) path() string {
	if c.parent == nil {
		return c.name()
	}
	return c.parent.path() + " " + c.name()
}

func (c *command) AddCommand(cmds ...*command) {
	for _, s := range cmds {
		s.parent = c
		c.subs = append(c.subs, s)
	}
}

func (c *command) out() io.Writer {
	for x := c; x != nil; x = x.parent {
		if x.stdout != nil {
			return x.stdout
		}
	}
	return io.Discard
}

// --- フラグの登録 ---

func (c *command) StringVar(p *string, name, def, usage string) {
	c.StringVarP(p, name, "", def, usage)
}

func (c *command) StringVarP(p *string, name, short, def, usage string) {
	*p = def
	c.flags = append(c.flags, &flagSpec{name: name, short: short, typ: "string", usage: usage, value: (*stringValue)(p), defaultText: quoteIfSet(def)})
}

// PersistentStringVarP は子孫のコマンドでも使える文字列フラグ (例: -c, --config)。
func (c *command) PersistentStringVarP(p *string, name, short, def, usage string) {
	c.StringVarP(p, name, short, def, usage)
	c.persistent = append(c.persistent, c.flags[len(c.flags)-1])
}

func (c *command) BoolVar(p *bool, name string, def bool, usage string) {
	*p = def
	c.flags = append(c.flags, &flagSpec{name: name, typ: "bool", usage: usage, value: (*boolValue)(p)})
}

// StringArrayVar は繰り返し指定できるフラグ (--tag a --tag b)。カンマでは分けない。
func (c *command) StringArrayVar(p *[]string, name string, usage string) {
	c.flags = append(c.flags, &flagSpec{name: name, typ: "stringArray", usage: usage, value: &listValue{p: p}})
}

// StringSliceVar は繰り返し指定でき、値をカンマで分けるフラグ (--status open,acked)。
func (c *command) StringSliceVar(p *[]string, name string, usage string) {
	c.flags = append(c.flags, &flagSpec{name: name, typ: "strings", usage: usage, value: &listValue{p: p, split: true}})
}

func (c *command) MarkFlagRequired(name string) {
	c.required = append(c.required, name)
}

func quoteIfSet(s string) string {
	if s == "" {
		return ""
	}
	return fmt.Sprintf("%q", s)
}

type stringValue string

func (s *stringValue) Set(v string) error { *s = stringValue(v); return nil }
func (s *stringValue) String() string     { return string(*s) }

type boolValue bool

func (b *boolValue) Set(v string) error {
	x, err := strconv.ParseBool(v)
	*b = boolValue(x)
	return err
}
func (b *boolValue) String() string   { return fmt.Sprint(bool(*b)) }
func (b *boolValue) IsBoolFlag() bool { return true }

type listValue struct {
	p     *[]string
	split bool
}

func (l *listValue) Set(v string) error {
	if l.split {
		*l.p = append(*l.p, strings.Split(v, ",")...)
	} else {
		*l.p = append(*l.p, v)
	}
	return nil
}
func (l *listValue) String() string {
	if l.p == nil {
		return ""
	}
	return strings.Join(*l.p, ",")
}

// --- 引数の検査 (cobra と同じ文言) ---

func noArgs(c *command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown command %q for %q", args[0], c.path())
	}
	return nil
}

func exactArgs(n int) func(*command, []string) error {
	return func(_ *command, args []string) error {
		if len(args) != n {
			return fmt.Errorf("accepts %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}

func maximumNArgs(n int) func(*command, []string) error {
	return func(_ *command, args []string) error {
		if len(args) > n {
			return fmt.Errorf("accepts at most %d arg(s), received %d", n, len(args))
		}
		return nil
	}
}

// --- 実行 ---

// inheritedFlags は祖先の persistent フラグ。
func (c *command) inheritedFlags() []*flagSpec {
	var out []*flagSpec
	for x := c.parent; x != nil; x = x.parent {
		out = append(out, x.persistent...)
	}
	return out
}

// execute は args を解釈してサブコマンドへ降り、実行する。
func (c *command) execute(ctx context.Context, args []string) error {
	var help, version bool
	specs := append(append([]*flagSpec{}, c.flags...), c.inheritedFlags()...)
	fs := flag.NewFlagSet(c.path(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	for _, s := range specs {
		fs.Var(s.value, s.name, s.usage)
		if s.short != "" {
			fs.Var(s.value, s.short, s.usage)
		}
	}
	fs.Var((*boolValue)(&help), "help", "")
	fs.Var((*boolValue)(&help), "h", "")
	if c.Version != "" {
		fs.Var((*boolValue)(&version), "version", "")
		fs.Var((*boolValue)(&version), "v", "")
	}

	var positional []string
	if len(c.subs) > 0 {
		// サブコマンドを束ねるコマンドは、最初の非フラグ引数 (サブコマンド名) で止める
		if err := fs.Parse(args); err != nil {
			return flagError(err)
		}
		positional = fs.Args()
	} else {
		// 末端のコマンドはフラグと位置引数が混ざってよい (approve <id> --note x)
		for {
			if err := fs.Parse(args); err != nil {
				return flagError(err)
			}
			rest := fs.Args()
			if len(rest) == 0 {
				break
			}
			if rest[0] == "--" {
				positional = append(positional, rest[1:]...)
				break
			}
			positional = append(positional, rest[0])
			args = rest[1:]
		}
	}

	if help {
		c.writeHelp(c.out())
		return nil
	}
	if version {
		_, err := fmt.Fprintf(c.out(), "%s version %s\n", c.name(), c.Version)
		return err
	}
	if len(c.subs) > 0 {
		if len(positional) == 0 {
			if c.Run == nil {
				c.writeHelp(c.out())
				return nil
			}
		} else if sub := c.find(positional[0]); sub != nil {
			return sub.execute(ctx, positional[1:])
		} else if c.Run == nil {
			return fmt.Errorf("unknown command %q for %q", positional[0], c.path())
		}
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, s := range specs {
		if s.short != "" && set[s.short] {
			set[s.name] = true
		}
	}
	for _, name := range c.required {
		if !set[name] {
			return fmt.Errorf("required flag(s) %q not set", name)
		}
	}
	if c.Args != nil {
		if err := c.Args(c, positional); err != nil {
			return err
		}
	}
	return c.Run(ctx, positional)
}

// flagError は flag パッケージのエラーを pflag (cobra 時代) と同じ文言にする。ログの msg を変えないため。
func flagError(err error) error {
	msg := err.Error()
	for _, p := range []struct{ prefix, long, short string }{
		{"flag provided but not defined: -", "unknown flag: --%s", "unknown shorthand flag: '%s' in -%[1]s"},
		{"flag needs an argument: -", "flag needs an argument: --%s", "flag needs an argument: '%s' in -%[1]s"},
	} {
		name, ok := strings.CutPrefix(msg, p.prefix)
		if !ok {
			continue
		}
		name = strings.TrimPrefix(name, "-")
		if len(name) == 1 {
			return fmt.Errorf(p.short, name)
		}
		return fmt.Errorf(p.long, name)
	}
	if m := invalidValue.FindStringSubmatch(msg); m != nil {
		return fmt.Errorf("invalid argument %s for \"--%s\" flag: %s", m[1], m[2], m[3])
	}
	return err
}

// invalidValue は flag の値エラー (bool とそれ以外で文言が違う)。
var invalidValue = regexp.MustCompile(`^invalid (?:boolean )?value ("(?:[^"\\]|\\.)*") for (?:flag )?-(\S+): (.*)$`)

func (c *command) find(name string) *command {
	for _, s := range c.subs {
		if s.name() == name {
			return s
		}
	}
	return nil
}

// findPath は help [command...] の対象を探す。見つからなければ nil。
func (c *command) findPath(names []string) *command {
	x := c
	for _, n := range names {
		if x = x.find(n); x == nil {
			return nil
		}
	}
	return x
}

// --- ヘルプ (cobra の既定テンプレートと同じ書式) ---

func (c *command) writeHelp(w io.Writer) {
	var b strings.Builder
	text := c.Long
	if text == "" {
		text = c.Short
	}
	if text != "" {
		b.WriteString(strings.TrimRightFunc(text, unicode.IsSpace))
		b.WriteString("\n\n")
	}
	b.WriteString("Usage:")
	if c.Run != nil {
		b.WriteString("\n  " + c.useLine())
	}
	if len(c.subs) > 0 {
		b.WriteString("\n  " + c.path() + " [command]")
		subs := append([]*command{}, c.subs...)
		sort.Slice(subs, func(i, j int) bool { return subs[i].name() < subs[j].name() })
		pad := 11
		for _, s := range subs {
			pad = max(pad, len(s.name()))
		}
		b.WriteString("\n\nAvailable Commands:")
		for _, s := range subs {
			fmt.Fprintf(&b, "\n  %-*s %s", pad, s.name(), s.Short)
		}
	}
	local := append([]*flagSpec{}, c.flags...)
	local = append(local, &flagSpec{name: "help", short: "h", typ: "bool", usage: "help for " + c.name()})
	if c.Version != "" {
		local = append(local, &flagSpec{name: "version", short: "v", typ: "bool", usage: "version for " + c.name()})
	}
	b.WriteString("\n\nFlags:\n")
	b.WriteString(flagUsages(local))
	if inh := c.inheritedFlags(); len(inh) > 0 {
		b.WriteString("\n\nGlobal Flags:\n")
		b.WriteString(flagUsages(inh))
	}
	if len(c.subs) > 0 {
		fmt.Fprintf(&b, "\n\nUse \"%s [command] --help\" for more information about a command.", c.path())
	}
	b.WriteString("\n")
	_, _ = io.WriteString(w, b.String())
}

func (c *command) useLine() string {
	use := c.Use
	if c.parent != nil {
		use = c.parent.path() + " " + use
	}
	return use + " [flags]"
}

// flagUsages は pflag の FlagUsages と同じ書式で、名前順に並べ説明の列を揃える。
func flagUsages(specs []*flagSpec) string {
	specs = append([]*flagSpec{}, specs...)
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	heads := make([]string, len(specs))
	width := 0
	for i, s := range specs {
		h := "      --" + s.name
		if s.short != "" {
			h = "  -" + s.short + ", --" + s.name
		}
		if s.typ != "bool" {
			h += " " + s.typ
		}
		heads[i] = h
		width = max(width, len(h))
	}
	lines := make([]string, len(specs))
	for i, s := range specs {
		u := s.usage
		if s.defaultText != "" {
			u += " (default " + s.defaultText + ")"
		}
		lines[i] = heads[i] + strings.Repeat(" ", width-len(heads[i])+3) + u
	}
	return strings.Join(lines, "\n")
}

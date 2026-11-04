package notify

import (
	"strings"
	"unicode/utf8"
)

// 通知の書式 (slack.format。ADR 0029)。
const (
	FormatBlocks = "blocks" // Block Kit (blocks + 通知用の text)
	FormatText   = "text"   // mrkdwn の本文だけ (v0.3.0 までの書式)
)

// Slack の Block Kit の上限 (https://api.slack.com/reference/block-kit)。
const (
	MaxBlocks       = 50
	MaxSectionRunes = 3000
	MaxHeaderRunes  = 150
	MaxFields       = 10
	MaxFieldRunes   = 2000
	maxContextRunes = 2000
	// maxNotifyRunes は通知用の text (プッシュ通知・検索に使われる 1 行) の上限。
	maxNotifyRunes = 300
)

// Message は Slack に送る 1 通。Blocks が空なら text だけを送る (slack.format: text)。
// Blocks があるとき Text は通知 (プッシュ通知・検索) 用の短い 1 行。
//
// 決定 (ADR 0037): ログ由来の URL を Slack に取りに行かせない (プレビューの偽装を防ぐ)。ゼロ値の false のまま payload に出す。
type Message struct {
	Text        string  `json:"text"`
	Blocks      []Block `json:"blocks,omitempty"`
	UnfurlLinks bool    `json:"unfurl_links"`
	UnfurlMedia bool    `json:"unfurl_media"`
}

// Block は Block Kit のブロック (aratam が使う header / section / divider / context だけ)。
type Block struct {
	Type     string     `json:"type"`
	Text     *TextObj   `json:"text,omitempty"`
	Fields   []*TextObj `json:"fields,omitempty"`
	Elements []*TextObj `json:"elements,omitempty"`
}

// TextObj は Block Kit のテキストオブジェクト (plain_text / mrkdwn)。
type TextObj struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
	// Verbatim は mrkdwn で URL・チャンネル名・メンションを自動で解釈させない。書式と、設定に書いた <!channel> は効く (ADR 0037)。
	Verbatim bool `json:"verbatim,omitempty"`
}

func mrkdwn(s string) *TextObj { return &TextObj{Type: "mrkdwn", Text: s, Verbatim: true} }

func headerBlock(s string) Block {
	return Block{Type: "header", Text: &TextObj{Type: "plain_text", Text: clipRunes(oneLine(s), MaxHeaderRunes-1), Emoji: true}}
}

// sectionBlock は mrkdwn の section。3000 字を超えたら行の境目で切る。
func sectionBlock(s string) Block {
	return Block{Type: "section", Text: mrkdwn(clipLines(s, MaxSectionRunes))}
}

func fieldsBlock(fs ...string) Block {
	b := Block{Type: "section"}
	for i, f := range fs {
		if i == MaxFields {
			break
		}
		b.Fields = append(b.Fields, mrkdwn(clipLines(f, MaxFieldRunes)))
	}
	return b
}

func dividerBlock() Block { return Block{Type: "divider"} }

func contextBlock(es ...string) Block {
	b := Block{Type: "context"}
	for _, e := range es {
		b.Elements = append(b.Elements, mrkdwn(clipLines(e, maxContextRunes)))
	}
	return b
}

// clipLines は s を n 文字までにする。超えたら行の境目で切り (1 行目が長すぎれば文字で切り)、末尾に … を付ける。
func clipLines(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	var kept []string
	used := 0
	for _, l := range strings.Split(s, "\n") {
		c := utf8.RuneCountInString(l) + 1
		if used+c > n-2 {
			break
		}
		kept = append(kept, l)
		used += c
	}
	if len(kept) == 0 {
		return string([]rune(s)[:n-1]) + "…"
	}
	return strings.Join(kept, "\n") + "\n…"
}

// PlainText は --dry-run 用の、人が読む簡易表示。Blocks が無ければ text をそのまま返す。
// header は「# 」、divider は「---」、context は「(小) 」を付け、fields は「 | 」でつなぐ。
func PlainText(m Message) string {
	if len(m.Blocks) == 0 {
		return m.Text
	}
	var out []string
	out = append(out, "[通知] "+m.Text)
	for _, b := range m.Blocks {
		switch b.Type {
		case "header":
			out = append(out, "# "+b.Text.Text)
		case "divider":
			out = append(out, "---")
		case "context":
			var es []string
			for _, e := range b.Elements {
				es = append(es, e.Text)
			}
			out = append(out, "(小) "+strings.Join(es, " | "))
		case "section":
			if b.Text != nil {
				out = append(out, b.Text.Text)
			}
			var fs []string
			for _, f := range b.Fields {
				fs = append(fs, strings.ReplaceAll(f.Text, "\n", " "))
			}
			if len(fs) > 0 {
				out = append(out, strings.Join(fs, " | "))
			}
		}
	}
	return strings.Join(out, "\n")
}

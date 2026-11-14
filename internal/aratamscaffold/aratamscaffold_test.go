package aratamscaffold

import (
	"bytes"
	"strings"
	"testing"
)

func TestNamedReplacesOnlyTheName(t *testing.T) {
	if n := bytes.Count(scaffold, []byte(nameLine)); n != 1 {
		t.Fatalf("the template must have exactly one %q line, got %d", nameLine, n)
	}
	got := string(Named("prod"))
	want := strings.Replace(string(Scaffold()), "name: example", "name: prod   ", 1)
	if got != want {
		t.Fatalf("Named must change only the name and keep the comment column:\n%s", strings.SplitN(got, "\n", 5)[3])
	}
	if long := string(Named("a-very-long-account-name-for-the-audit")); !strings.Contains(long, "name: a-very-long-account-name-for-the-audit #") {
		t.Fatalf("a long name must keep one space before the comment")
	}
}

func TestScaffoldReturnsACopy(t *testing.T) {
	b := Scaffold()
	b[0] = 'X'
	if Scaffold()[0] == 'X' {
		t.Fatal("Scaffold must return a copy")
	}
}

// Bot は name とチャンネル ID だけを書き入れる (ADR 0060)。ほかの行とコメントの桁は変えない。
func TestBotFillsTheChannels(t *testing.T) {
	for _, key := range []string{channelLine, urgentChannelLine} {
		if n := bytes.Count(scaffold, []byte(key)); n != 1 {
			t.Fatalf("the template must have exactly one %q line, got %d", key, n)
		}
	}
	got := string(Bot("prod", "C0123456789", "C0123456780"))
	want := string(Named("prod"))
	want = strings.Replace(want, `  channel: ""           `, `  channel: "C0123456789"`, 1)
	want = strings.Replace(want, `  urgent_channel: ""           `, `  urgent_channel: "C0123456780"`, 1)
	if got != want {
		t.Fatalf("Bot must change only the name and the channels:\n%s", got)
	}
	// 緊急用を分けない (空) なら、urgent_channel の行は雛形のまま
	same := string(Bot("prod", "C0123456789", ""))
	if !strings.Contains(same, `  urgent_channel: ""  `) || !strings.Contains(same, `  channel: "C0123456789"`) {
		t.Fatalf("an empty urgent channel must keep the template line:\n%s", same)
	}
	if strings.Count(got, "\n") != strings.Count(string(Scaffold()), "\n") {
		t.Fatal("Bot must not add or remove lines")
	}
}

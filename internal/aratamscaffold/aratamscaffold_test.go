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

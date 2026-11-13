package allowlist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var entry = NewEntry{ARN: "arn:aws:iam::123456789012:user/mallory", Note: "外注: 調査用 #2", ApprovedBy: "alice", ApprovedAt: "2026-10-21", Expires: "2026-12-31", Tags: []string{"deploy"}}

const rendered = `  - arn: arn:aws:iam::123456789012:user/mallory
    note: '外注: 調査用 #2'
    approved_by: alice
    approved_at: 2026-10-21
    expires: 2026-12-31
    tags: [deploy]
`

func TestAppendKeepsEverythingElse(t *testing.T) {
	src := `# 既知リスト (git 管理)
principals:
  # 社員
  - arn: arn:aws:iam::123456789012:role/switch_role
    note: "社員の switch role"   # 行末コメント
    tags: [deploy]

  - arn: arn:aws:iam::123456789012:user/contractor-x
    expires: 2026-12-31
    # 契約終了で外す

# 本社など
source_ips:
  - cidr: 203.0.113.0/24
admin_users: [113, 2048]
`
	want := `# 既知リスト (git 管理)
principals:
  # 社員
  - arn: arn:aws:iam::123456789012:role/switch_role
    note: "社員の switch role"   # 行末コメント
    tags: [deploy]

  - arn: arn:aws:iam::123456789012:user/contractor-x
    expires: 2026-12-31
    # 契約終了で外す
` + rendered + `
# 本社など
source_ips:
  - cidr: 203.0.113.0/24
admin_users: [113, 2048]
`
	got, added, err := AppendBytes([]byte(src), entry)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if added != rendered {
		t.Fatalf("added:\n%s", added)
	}
}

func TestAppendVariants(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"no file", "", "principals:\n" + rendered},
		{"no principals key", "source_ips: []\n", "source_ips: []\n\nprincipals:\n" + rendered},
		{"empty flow", "principals: []   # まだ無い\nsource_ips: []\n", "principals: # まだ無い\n" + rendered + "source_ips: []\n"},
		{"null", "principals:\nsource_ips: []\n", "principals:\n" + rendered + "source_ips: []\n"},
		{"last key without trailing newline", "principals:\n- arn: arn:aws:iam::1:user/a", "principals:\n- arn: arn:aws:iam::1:user/a\n" + strings.ReplaceAll(rendered, "\n  ", "\n")[2:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := AppendBytes([]byte(tc.src), entry)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestAppendSubjects(t *testing.T) {
	got, _, err := AppendBytes(nil, NewEntry{Account: "111122223333", Note: "SaaS", ApprovedAt: "2026-10-21"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `- account: "111122223333"`) {
		t.Fatalf("%s", got)
	}
	got, _, err = AppendBytes(got, NewEntry{ARNPattern: "arn:aws:iam::123456789012:role/github-actions-*", ApprovedAt: "2026-10-21"})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := Parse(got)
	if len(l.Principals) != 2 || l.Principals[1].ARNPattern != "arn:aws:iam::123456789012:role/github-actions-*" {
		t.Fatalf("%+v", l.Principals)
	}
}

func TestAppendRefuses(t *testing.T) {
	if _, _, err := AppendBytes([]byte("principals:\n  - arn: arn:aws:iam::123456789012:user/mallory\n"), entry); !errors.Is(err, ErrAlreadyListed) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, _, err := AppendBytes([]byte("principals: [{arn: 'arn:aws:iam::1:user/a'}]\n"), entry); err == nil || !strings.Contains(err.Error(), "flow style") {
		t.Fatalf("flow: %v", err)
	}
	if _, _, err := AppendBytes(nil, NewEntry{ARN: "arn:aws:iam::1:user/a", Tags: []string{"admin"}}); err == nil || !strings.Contains(err.Error(), "unknown tag") {
		t.Fatalf("tag: %v", err)
	}
	if _, _, err := AppendBytes([]byte("principals: : :\n"), entry); err == nil {
		t.Fatal("broken yaml must be refused")
	}
}

func TestAppendFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := os.WriteFile(p, []byte("# head\nprincipals: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(p, entry); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil || len(l.Principals) != 1 {
		t.Fatalf("%v %+v", err, l)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode must be kept: %v", st.Mode())
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), "# head\n") {
		t.Fatalf("%s", b)
	}
}

func TestAppendExpectedDenied(t *testing.T) {
	const ai = "arn:aws:iam::123456789012:role/ai-investigation-readonly"
	got, added, err := AppendBytes(nil, NewEntry{ARN: ai, Note: "個人情報のロググループは Deny", ApprovedBy: "alice", ApprovedAt: "2026-11-03",
		ExpectedDenied: []string{"logs:StartQuery", "logs:Get*", "secretsmanager:*"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(added, `    expected_denied: ["logs:StartQuery", "logs:Get*", "secretsmanager:*"]`+"\n") {
		t.Fatalf("added:\n%s", added)
	}
	l, err := Parse(got)
	if err != nil || !l.DeniedExpected(ai, "logs:GetLogEvents", time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("round trip: %v\n%s", err, got)
	}
	if _, _, err := AppendBytes(nil, NewEntry{ARN: ai, Note: "x", ExpectedDenied: []string{"StartQuery"}}); err == nil || !strings.Contains(err.Error(), `expected_denied "StartQuery": want service:Action`) {
		t.Fatalf("bad glob: %v", err)
	}
}

// TestWrite は config init が使う書き込みを確かめる: 壊れた中身は書かず、既にあるファイルの権限を保つ。
func TestWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "allowlist.yaml")
	if err := Write(p, []byte("principals:\n  - note: 主体が無い\n")); err == nil {
		t.Fatal("an invalid allowlist must not be written")
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("file was created")
	}
	body := []byte("principals:\n  - account: \"111122223333\"\n")
	if err := Write(p, body); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, append(body, []byte("source_ips: []\n")...)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	if b, _ := os.ReadFile(p); !strings.HasSuffix(string(b), "source_ips: []\n") {
		t.Fatalf("%s", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

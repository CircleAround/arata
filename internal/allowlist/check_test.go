package allowlist

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		name, body string
		want       []Problem // Msg は部分一致
	}{
		{name: "ok", body: "principals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n    note: deploy\nsource_ips:\n  - cidr: 203.0.113.0/24\n"},
		{name: "empty", body: ""},
		{name: "entry error has the line of the entry",
			body: "# 既知リスト\nprincipals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n\n  - arn: arn:aws:iam::123456789012:role/Ops\n    account: \"111122223333\"\n",
			want: []Problem{{Line: 5, Msg: "principals[1]: exactly one of arn, account, arn_pattern is required"}}},
		{name: "expires",
			body: "principals:\n  - account: \"111122223333\"\n    expires: 2026/12/31\n",
			want: []Problem{{Line: 2, Msg: `principals[0]: expires "2026/12/31": want YYYY-MM-DD`}}},
		{name: "expected_denied",
			body: "principals:\n  - account: \"111122223333\"\n    note: 監視\n    expected_denied: [\"logs\"]\n",
			want: []Problem{{Line: 2, Msg: "principals[0]: expected_denied[0]"}}},
		{name: "source_ips",
			body: "principals: []\nsource_ips:\n  - cidr: 203.0.113.0/24\n  - cidr: 203.0.113.300/24\n",
			want: []Problem{{Line: 4, Msg: "source_ips[1]: "}}},
		{name: "secrets_access",
			body: "secrets_access:\n  - principal: arn:aws:iam::123456789012:role/App\n",
			want: []Problem{{Line: 2, Msg: "secrets_access[0]: principal and secrets are required"}}},
		{name: "unknown key keeps the line of the YAML error",
			body: "principals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n    expire: 2026-12-31\n",
			want: []Problem{{Msg: "line 3: field expire not found"}}},
		{name: "duplicates are warnings",
			body: "principals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n  - account: \"111122223333\"\n  - arn: arn:aws:iam::123456789012:role/Deploy\n    expires: 2026-12-31\n  - account: \"111122223333\"\n  - arn: arn:aws:iam::123456789012:role/Deploy\n",
			want: []Problem{
				{Line: 4, Warn: true, Msg: "principals[2]: duplicate of principals[0] (line 2): arn:aws:iam::123456789012:role/Deploy"},
				{Line: 6, Warn: true, Msg: "principals[3]: duplicate of principals[1] (line 3): account:111122223333"},
				{Line: 7, Warn: true, Msg: "principals[4]: duplicate of principals[0] (line 2): arn:aws:iam::123456789012:role/Deploy"},
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, got := Check([]byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			errs := 0
			for i, w := range tc.want {
				if got[i].Line != w.Line || got[i].Warn != w.Warn || !strings.Contains(got[i].Msg, w.Msg) {
					t.Errorf("[%d] got %+v, want %+v", i, got[i], w)
				}
				if !w.Warn {
					errs++
				}
			}
			// Parse と同じ規則: エラーがあるときだけ List は nil
			if _, perr := Parse([]byte(tc.body)); (perr != nil) != (errs > 0) || (l == nil) != (errs > 0) {
				t.Fatalf("Check must agree with Parse: parse err %v, problems %+v", perr, got)
			}
		})
	}
}

// ファズテスト (ADR 0041)。Check は利用者が書いたファイルを読む。規則:
//   - エラーの有無は Parse と一致する (config check が通した allowlist は run でも読める。逆も同じ)
//   - エラーは多くても 1 件。警告は Parse が通ったときだけで、重複した項目の数と一致する
//   - 行番号は負にならず、ファイルの行数を超えない
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		"principals:\n  - arn: arn:aws:iam::123456789012:role/Deploy\n  - arn: arn:aws:iam::123456789012:role/Deploy\n",
		"principals:\n  - account: \"111122223333\"\n    expires: 2026/12/31\n",
		"principals: [{account: \"111122223333\"}, {account: \"111122223333\"}]\nsource_ips: [{cidr: x}]\n",
		"principals: &a\n  - arn: a\nsource_ips: *a\n",
		"principals:\n  - arn: a\nprincipals:\n  - arn: a\n",
		"secrets_access:\n  - principal: p\n", "- x\n", "principals: 1\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, ps := Check(b)
		pl, perr := Parse(b)
		errs, warns := 0, 0
		maxLine := strings.Count(string(b), "\n") + 1
		for _, p := range ps {
			if p.Warn {
				warns++
			} else {
				errs++
			}
			if p.Line < 0 || p.Line > maxLine || p.Msg == "" {
				t.Fatalf("行番号か文言がおかしい: %+v (%d 行)", p, maxLine)
			}
		}
		if (perr != nil) != (errs == 1) || errs > 1 || (l == nil) != (perr != nil) {
			t.Fatalf("Parse と一致しない: parse err %v, problems %+v", perr, ps)
		}
		if perr != nil {
			if warns != 0 {
				t.Fatalf("エラーのときに警告を出した: %+v", ps)
			}
			return
		}
		subjects := map[string]bool{}
		for i := range pl.Principals {
			subjects[pl.Principals[i].Subject()] = true
		}
		if want := len(pl.Principals) - len(subjects); warns != want {
			t.Fatalf("重複の警告が %d 件 (重複は %d 件): %+v", warns, want, ps)
		}
	})
}

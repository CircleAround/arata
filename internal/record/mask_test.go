package record

import "testing"

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:iam::123456789012:user/alice@example.com":                      "arn:aws:iam::123456789012:user/<email>",
		"no_mfa|alice%40example.com":                                            "no_mfa|<email>",
		"arn:aws:sts::123456789012:assumed-role/Audit/alice@example.com is not": "arn:aws:sts::123456789012:assumed-role/Audit/<session> is not",
		"arn:aws:sts::123456789012:assumed-role/Audit/alice-session is not":     "arn:aws:sts::123456789012:assumed-role/Audit/<session> is not",
		"arn:aws:iam::123456789012:role/app":                                    "arn:aws:iam::123456789012:role/app",
	} {
		if got := MaskIdentity(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

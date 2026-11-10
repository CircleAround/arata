package record

import "testing"

func TestServiceName(t *testing.T) {
	for in, want := range map[string]string{
		"sso.amazonaws.com":             "sso.amazonaws.com",
		"ops.apigateway.amazonaws.com":  "ops.apigateway.amazonaws.com",
		"AWS Internal":                  "AWS Internal",
		"":                              "",
		"198.51.100.7":                  "",
		"amazonaws.com":                 "",
		".amazonaws.com":                "",
		"SSO.amazonaws.com":             "",
		"sso.amazonaws.com.example.com": "",
		"evil) [x](http://example.com) (.amazonaws.com": "",
		"a\nb.amazonaws.com":                            "",
		"sso.amazonaws.com\n":                           "",
		"aws internal":                                  "",
	} {
		got, ok := ServiceName(in)
		if got != want || ok != (want != "") {
			t.Errorf("ServiceName(%q) = %q, %v (want %q)", in, got, ok, want)
		}
	}
}

func TestServiceLinkedRole(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling":      "autoscaling.amazonaws.com",
		"arn:aws-cn:iam::123456789012:role/aws-service-role/ops.apigateway.amazonaws.com/AWSServiceRoleForAPIGateway": "ops.apigateway.amazonaws.com",
		"arn:aws:iam::123456789012:role/Admin":                                    "",
		"arn:aws:iam::123456789012:role/aws-service-role/Admin":                   "",
		"arn:aws:iam::123456789012:role/app/aws-service-role/sso.amazonaws.com/x": "",
		"arn:aws:iam::123456789012:user/aws-service-role/sso.amazonaws.com/x":     "",
		"arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/":      "",
		"arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/a/b":   "",
		"arn:aws:iam::123456789012:role/aws-service-role/AWS Internal/x":          "",
		"arn:aws:iam::12345:role/aws-service-role/sso.amazonaws.com/x":            "",
		"x arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/x":   "",
		"arn:aws:iam::123456789012:role/aws-service-role/sso.amazonaws.com/x\n":   "",
		"": "",
	} {
		got, ok := ServiceLinkedRole(in)
		if got != want || ok != (want != "") {
			t.Errorf("ServiceLinkedRole(%q) = %q, %v (want %q)", in, got, ok, want)
		}
	}
}

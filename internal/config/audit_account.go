package config

import "fmt"

// AuditAccountNone は audit_account / --audit-account の「外から監査しない」の値。
const AuditAccountNone = "none"

// ParseAuditAccount は「監査する側のアカウント」の指定 (設定の audit_account、`arata config init --audit-account`) を解釈する。
//
// 決定 (ADR 0045): 受け付けるのは次の 2 つだけ。空・大文字・前後の空白・ARN は受け付けない (利用者の入力を推測で直さない)。
//   - ASCII の数字ちょうど 12 桁: 別のアカウントのロールが監査対象の読み取り専用ロールを引き受けて監査する。id にその ID を返す
//   - none: 外から監査しない (監査対象と同じアカウントの中で動かす・手元の認証で直接動かす)。none に true を返す
func ParseAuditAccount(s string) (id string, none bool, err error) {
	if s == AuditAccountNone {
		return "", true, nil
	}
	if len(s) != 12 {
		return "", false, auditAccountErr(s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", false, auditAccountErr(s)
		}
	}
	return s, false, nil
}

func auditAccountErr(s string) error {
	return fmt.Errorf("audit account %q: want a 12-digit AWS account ID (the account whose role assumes this target's read-only role) or %q (the audit runs inside the target account or with your own credentials)", s, AuditAccountNone)
}

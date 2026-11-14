package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/report"
)

// 以前の版で集めた OIDC の引き受けの記録 (プロバイダと sub の項目が無い) は finding にせず、件数を coverage.notes に出す (ADR 0055)。
func TestOIDCLegacyEventsAreNotedNotReported(t *testing.T) {
	h := newHarness(t)
	e := h.open(t)
	ctx := context.Background()
	for i, d := range []map[string]any{
		{"role_arn": "arn:aws:iam::" + acct + ":role/gha-deploy", "recipient_account": acct},
		{"recipient_account": acct},
	} {
		ev := record.TrailEvent{EventID: "legacy-" + string(rune('a'+i)), Time: h.now.Add(-time.Duration(i+1) * time.Hour), Source: "trail", Name: "AssumeRoleWithWebIdentity",
			EventSource: "sts.amazonaws.com", PrincipalKind: record.PrincipalAssumedRole, IP: "203.0.113.9", Data: d, ReadOnly: true}
		if i == 1 {
			ev.ErrorCode = "AccessDenied"
		}
		if err := e.st.InsertEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	r, err := e.Run(ctx, "daily")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range append(append([]report.Finding{}, r.Report.Findings.New...), r.Report.Info...) {
		if f.Check == "oidc_assume_role" || f.Check == "unknown_assume_role" {
			t.Fatalf("以前の版の記録が finding になった: %+v", f)
		}
	}
	notes := r.Report.Coverage.Notes
	if len(notes) != 1 || !strings.Contains(notes[0], "oidc_assume_role") || !strings.Contains(notes[0], "2 件") {
		t.Fatalf("coverage.notes: %q", notes)
	}
}

package config

import (
	"testing"
	"time"
)

// signin_session の設定 (ADR 0092 の 5 節)。session_lookback には既定を持たない (サインインの長さの上限に合わせて利用者が決める。ADR 0014)。
func TestSigninSessionConfig(t *testing.T) {
	cfg, err := Load(write(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Checks.SigninSession; got != (SigninSession{BaselineDays: 14, MinBaselineDays: 7, MinFailures: 3, MinSessions: 3}) {
		t.Fatalf("defaults: %+v", got)
	}
	if _, ok := cfg.Checks.SigninSession.Lookback(); ok {
		t.Fatal("session_lookback must have no default")
	}
	cfg, err = Load(write(t, minimal+"checks:\n  signin_session:\n    session_lookback: 3d\n    baseline_days: 30\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := cfg.Checks.SigninSession.Lookback(); !ok || d != 72*time.Hour {
		t.Fatalf("session_lookback: %v %v", d, ok)
	}
	if got := cfg.Checks.SigninSession.MinBaselineDays; got != 7 {
		t.Fatalf("min_baseline_days: %d", got)
	}
	for _, body := range []string{
		minimal + "checks:\n  signin_session:\n    session_lookback: soon\n",
		minimal + "checks:\n  signin_session:\n    session_lookback: -1h\n",
		minimal + "checks:\n  signin_session:\n    session_lookback: 91d\n",
		minimal + "checks:\n  signin_session:\n    baseline_days: 5\n    min_baseline_days: 6\n",
		minimal + "checks:\n  signin_session:\n    min_failures: -1\n",
		minimal + "checks:\n  signin_session:\n    min_sessions: -1\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("expected error for %q", body)
		}
	}
}

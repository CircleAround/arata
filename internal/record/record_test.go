package record

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 21, 1, 2, 3, 0, time.UTC)
	cases := []struct {
		name string
		rec  Record
	}{
		{"trail_event", TrailEvent{EventID: "e1", Time: ts, Source: "trail", Name: "AssumeRole", PrincipalARN: "arn:aws:iam::1:user/x", PrincipalKind: PrincipalUser, Data: map[string]any{"role_arn": "arn:aws:iam::1:role/r"}}},
		{"principal_seen", PrincipalSeen{Time: ts, FirstTime: ts, Source: "trail", ARN: "arn:aws:iam::1:root", Kind: PrincipalRoot, IP: "203.0.113.1", Count: 2}},
		{"snapshot", SnapshotItem{Kind: KindPostureItem, Time: ts, Source: "posture", Key: "root_mfa", Data: map[string]any{"status": "ng"}}},
		{"metric", Metric{Date: "2026-10-21", Source: "nginx", From: KindHTTPAccess, Metric: "sign_in_failures", Key: "198.51.100.7", Value: 12}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Marshal(tc.rec)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Unmarshal(b)
			if err != nil {
				t.Fatal(err)
			}
			want := ts
			if _, ok := tc.rec.(Metric); ok {
				want = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) // 日次集計は日付の 0 時
			}
			if got.RecordKind() != tc.rec.RecordKind() || !got.RecordTime().Equal(want) {
				t.Fatalf("round trip mismatch: %+v", got)
			}
		})
	}
	if _, err := Unmarshal([]byte(`{"kind":"nope","time":"2026-01-01T00:00:00Z","data":{}}`)); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestExternalAccount(t *testing.T) {
	if l := PrincipalLabel("arn:aws:iam::111122223333:root", PrincipalUnknown); l != "外部アカウント 111122223333" {
		t.Fatal(l)
	}
	if l := PrincipalLabel("arn:aws:iam::123456789012:root", PrincipalRoot); l != "arn:aws:iam::123456789012:root" {
		t.Fatal(l)
	}
	if _, ok := ExternalAccount("arn:aws:iam::111122223333:role/x", PrincipalRole); ok {
		t.Fatal("role is not an account")
	}
}

func TestSnapshotItemAccessors(t *testing.T) {
	b, _ := Marshal(SnapshotItem{Kind: KindGuardDuty, Source: "gd", Key: "f1", Data: map[string]any{"severity": 7.5, "count": 3, "type": "Recon:EC2/PortProbeUnprotectedPort", "archived": true}})
	r, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	it := r.(SnapshotItem)
	if it.Number("severity") != 7.5 || it.Number("count") != 3 || it.String("type") == "" || !it.Bool("archived") || it.String("nope") != "" {
		t.Fatalf("%+v", it)
	}
}

func TestSourcePrefix(t *testing.T) {
	cases := []struct {
		ip, want string
		ok       bool
	}{
		{"198.51.100.7", "198.51.100.0/24", true},
		{"::ffff:198.51.100.7", "198.51.100.0/24", true},
		{"2001:db8:1234:5678::1", "2001:db8:1234::/48", true},
		{"ec2.amazonaws.com", "", false},
		{"AWS Internal", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := SourcePrefix(tc.ip)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%q: got %q %v", tc.ip, got, ok)
		}
	}
	k := ActivityKey("arn:aws:iam::123456789012:user/alice", "198.51.100.0/24")
	arn, v, ok := SplitActivityKey(k)
	if !ok || arn != "arn:aws:iam::123456789012:user/alice" || v != "198.51.100.0/24" {
		t.Fatalf("split: %q %q %v", arn, v, ok)
	}
}

// rebuild 用の拡張 (ADR 0033): principal_seen の collected_at と、スナップショットを置き換えた印。
func TestRebuildFieldsRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 21, 9, 0, 0, 123, time.UTC)
	b, err := Marshal(PrincipalSeen{Time: at, Source: "trail", ARN: "arn:aws:iam::123456789012:user/alice", Kind: PrincipalUser, IP: "203.0.113.1", Count: 1, CollectedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Unmarshal(b)
	if err != nil || !r.(PrincipalSeen).CollectedAt.Equal(at) {
		t.Fatalf("principal_seen collected_at: %+v %v", r, err)
	}
	// 以前の版で書いた行 (collected_at なし) はゼロ値で読める
	old := []byte(`{"kind":"principal_seen","time":"2026-10-21T09:00:00Z","data":{"time":"2026-10-21T09:00:00Z","first_time":"2026-10-21T08:00:00Z","source":"trail","arn":"arn:aws:iam::123456789012:user/alice","kind":"user","count":2}}`)
	r, err = Unmarshal(old)
	if err != nil || !r.(PrincipalSeen).CollectedAt.IsZero() || r.(PrincipalSeen).Count != 2 {
		t.Fatalf("old principal_seen: %+v %v", r, err)
	}
	b, err = Marshal(SnapshotReplaced{SnapshotKind: KindGuardDuty, Source: "gd", Time: at, Count: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"kind":"snapshot_replaced"`) {
		t.Fatalf("envelope kind: %s", b)
	}
	r, err = Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := r.(SnapshotReplaced)
	if !ok || m.SnapshotKind != KindGuardDuty || m.Source != "gd" || !m.Time.Equal(at) || m.Count != 0 || !m.RecordTime().Equal(at) {
		t.Fatalf("snapshot_replaced: %+v", r)
	}
	if SnapshotKinds[KindSnapshotReplaced] {
		t.Fatal("the marker is not a snapshot kind")
	}
}

package allowlist

import (
	"reflect"
	"testing"
)

// 期限のある項目を、節・対象・期限で、期限の早い順に返す (ADR 0068 の 3 節)。期限の無い項目は返さない。
func TestExpiring(t *testing.T) {
	l, err := Parse([]byte(`principals:
  - arn: arn:aws:iam::123456789012:user/alice
    note: 調査の委託
    expires: 2026-12-31
  - arn: arn:aws:iam::123456789012:role/Deploy
    tags: [deploy]
  - account: "111122223333"
    note: SaaS
    expires: 2026-11-20
assume_destinations:
  - account: "111122223333"
    note: 受託
    approved_by: alice
    approved_at: 2026-11-13
    expires: 2027-01-10
oidc_subjects:
  - provider: token.actions.githubusercontent.com
    role: arn:aws:iam::123456789012:role/gha-deploy
    repo: example-org/example-repo
    refs: ["refs/heads/main"]
    note: デプロイ
    expires: 2026-11-01
`))
	if err != nil {
		t.Fatal(err)
	}
	got := l.Expiring()
	var short []string
	for _, e := range got {
		short = append(short, e.Section+"|"+e.Expires)
		if e.Subject == "" {
			t.Errorf("subject is empty: %+v", e)
		}
	}
	want := []string{"oidc_subjects|2026-11-01", "principals|2026-11-20", "principals|2026-12-31", "assume_destinations|2027-01-10"}
	if !reflect.DeepEqual(short, want) {
		t.Fatalf("got %v\nwant %v", short, want)
	}
}

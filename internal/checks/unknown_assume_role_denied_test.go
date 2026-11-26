package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
)

// 断られた AssumeRole (AccessDenied) は requestParameters が null で resources も無く、引き受け先が roleArn にも Resource にも無い。
// 決定 (設計書 6 章):
//   - collector が errorMessage の決まった形から取った引き受け先 (denied_role_arn) があれば、それを引き受け先にする (role_identity: error_message)。
//     向きは今の規則 (newAssumeParties) で決まる
//   - 無ければ呼び出し元と混ぜず、見出しに「引き受け先は記録に無い」と書く (role_identity: not_recorded)。向きは決めない。role_arn は出さない
func TestUnknownAssumeRoleDeniedWithoutTarget(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	const adminRole = "arn:aws:iam::123456789012:role/AdminRole"
	const deniedRole = "arn:aws:iam::111122223333:role/none"
	denied := func(id, caller string, data map[string]any) record.TrailEvent {
		data["recipient_account"], data["session_mfa"], data["account_id"] = ownAcct, "false", ownAcct
		return record.TrailEvent{EventID: id, Time: now.Add(-time.Hour), Source: "trail", Name: "AssumeRole", EventSource: "sts.amazonaws.com",
			PrincipalARN: caller, PrincipalKind: record.PrincipalAssumedRole, IP: "203.0.113.2", ErrorCode: "AccessDenied", Data: data, ReadOnly: true}
	}
	for _, e := range []record.TrailEvent{
		denied("d1", adminRole, map[string]any{"denied_role_arn": deniedRole}),
		denied("d2", ownRole, map[string]any{}),
		// 形に合わない値 (ストアから読み戻した値なので、チェックの側でもロールの ARN の形のときだけ使う)
		denied("d3", ownRole2, map[string]any{"denied_role_arn": "arn:aws:iam::111122223333:user/x <!here>"}),
	} {
		if err := st.InsertEvent(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := UnknownAssumeRole{}.Evaluate(ctx, st, w, &allowlist.List{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Observation{}
	for _, o := range obs {
		by[o.Key] = o
	}
	if len(by) != 3 {
		t.Fatalf("keys: %s", keys(obs))
	}
	// エラー文から取れた: Key は引き受け先の ARN になり、向きが決まる
	o, ok := by[adminRole+"->"+deniedRole]
	if !ok {
		t.Fatalf("エラー文から取った引き受け先の Key が無い: %s", keys(obs))
	}
	if want := "既知リストに無い自アカウントの role/AdminRole が外部アカウント 111122223333 のロール none を 1 回引き受け (外向き、MFA なし、断られた引き受け。引き受け先はエラーの文から)"; o.Summary != want {
		t.Fatalf("summary\n got: %s\nwant: %s", o.Summary, want)
	}
	for k, want := range map[string]any{"role_arn": deniedRole, "role_identity": "error_message", "direction": "outbound", "role_account": otherAcct, "caller_account": ownAcct, "has_errors": true} {
		if o.Data[k] != want {
			t.Fatalf("data.%s = %v, want %v", k, o.Data[k], want)
		}
	}
	// 取れない: Key は今までどおり (ロールの部分が空)。見出しでロールの位置に呼び出し元が入ったと読めないようにする
	for _, caller := range []string{ownRole, ownRole2} {
		o, ok := by[caller+"->"]
		if !ok {
			t.Fatalf("Key が変わった: %q が無い (%s)", caller+"->", keys(obs))
		}
		if want := "既知リストに無い " + caller + " の引き受け 1 回 (引き受け先は記録に無い。断られた引き受け、MFA なし)"; o.Summary != want {
			t.Fatalf("summary\n got: %s\nwant: %s", o.Summary, want)
		}
		if o.Data["role_identity"] != "not_recorded" || o.Data["caller"] != caller {
			t.Fatalf("data: %v", o.Data)
		}
		for _, k := range []string{"role_arn", "direction", "role_account", "caller_account"} {
			if _, has := o.Data[k]; has {
				t.Fatalf("data.%s は出さない: %v", k, o.Data[k])
			}
		}
		if strings.Contains(o.Summary, "<!here>") || strings.Contains(o.Summary, "  ") {
			t.Fatalf("見出しの形: %q", o.Summary)
		}
		// Fingerprint は変えない (重大度 + IP 集合 + allowlist 状態)
		if o.Fingerprint != "high|203.0.113.2|unknown" {
			t.Fatalf("fingerprint: %q", o.Fingerprint)
		}
	}
}

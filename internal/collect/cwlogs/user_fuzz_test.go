package cwlogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/cwlogs/cwlogstest"
)

// ユーザー ID と auth の行のファズテスト (ADR 0041・0052)。対象は、アプリのログから取り出した値 (ログ由来) と Insights の結果を解釈する関数。

// 値の形の規則。Go の判定は、クエリの中で突き合わせる正規表現と同じものを受ける (どちらかだけが通す値が無い)。
func FuzzUserValues(f *testing.F) {
	for _, s := range []string{"user", "staff_member", "42", "a-b_C9", "alice@example.com", "none", "", "User", "x\n", strings.Repeat("a", 33), strings.Repeat("9", 65),
		"success", "failure", "impersonate", "password", "remember", "not_found_in_database", "user:42", "a|b", "ユーザー"} {
		f.Add(s)
	}
	rules := []struct {
		name    string
		pattern string
		valid   func(string) bool
	}{
		{"kind", userKindPattern, ValidUserKind}, {"id", userIDPattern, ValidUserID}, {"result", authResultPattern, validAuthResult},
		{"via", authViaPattern, validAuthVia}, {"reason", authReasonPattern, validAuthReason},
	}
	res := make([]*regexp.Regexp, len(rules))
	for i, r := range rules {
		res[i] = regexp.MustCompile("^(?:" + r.pattern + ")$")
	}
	f.Fuzz(func(t *testing.T, s string) {
		for i, r := range rules {
			if got, want := r.valid(s), res[i].MatchString(s); got != want {
				t.Fatalf("%s: Go の判定 %v、クエリの正規表現 %v: %q", r.name, got, want, s)
			}
		}
		// 主体の key (<kind>:<id>) を一意に分けられる: 形に合った値は : も | も含まない
		if (ValidUserKind(s) || ValidUserID(s)) && strings.ContainsAny(s, ":|@ \n") {
			t.Fatalf("形に合った値に区切りの文字がある: %q", s)
		}
	})
}

// 解釈率のクエリの結果の 1 行 (Insights の値。任意の文字列) のうち、ユーザー ID と auth の列の解釈。
// 守る規則: 形に合わない値は、集計の key にも結果にも現れず、捨てた数に入る。数は負でなく JSON にでき、
// ID の付いた数 ≤ 数えたリクエストの数、by の数 ≤ ID の付いた数、種類ごとの和 = ID の付いた数、理由ごとの和 = 失敗の数。key の数に上限がある。
func FuzzUserRows(f *testing.F) {
	f.Add("user", "1", "1", "0", "success", "password", "", "1", "30", "1")
	f.Add("staff", "1", "1", "1", "impersonate", "", "", "1", "2", "1")
	f.Add("alice@example.com", "0", "1", "0", "failure", "sso", "not_found_in_database", "1", "5", "3")
	f.Add("", "NaN", "-1", "1e99", "denied", "password", "Bad Reason", "Inf", "1e30", "0")
	f.Add("user:42", "2", "x", "", "", "", "invalid", "0", "", "2")
	f.Fuzz(func(t *testing.T, kind, users, userLines, bys, result, via, reason, authLines, requests, starts string) {
		row := map[string]string{"day": "2026-10-21 00:00:00.000", rlRequests: requests, rlStarts: starts, MetricLinesTotal: "10", MetricLinesMatched: "10",
			"user_kind": kind, rlUsers: users, rlUserLines: userLines, rlBys: bys, "auth_result": result, "auth_via": via, "auth_reason": reason, rlAuthLines: authLines}
		rr := readRequestRow(row)
		if rr.UserKind != "" && (!rr.User || !ValidUserKind(rr.UserKind)) || rr.User && rr.UserInvalid || rr.By && !rr.User {
			t.Fatalf("readRequestRow(%v) = %+v", row, rr)
		}
		if rr.Auth != "" && !validAuthResult(rr.Auth) || rr.Auth != "" && rr.AuthInvalid ||
			rr.AuthVia != "" && (rr.Auth != authSuccess || !validAuthVia(rr.AuthVia)) || rr.AuthReason != "" && (rr.Auth != authFailure || !validAuthReason(rr.AuthReason)) {
			t.Fatalf("readRequestRow(%v) = %+v", row, rr)
		}
		// 同じ行を、種類と理由を変えて何度も足す (key の数の上限)
		rows := []map[string]string{row}
		for i := 0; i < 2*maxUserKeys; i++ {
			r := map[string]string{}
			for k, v := range row {
				r[k] = v
			}
			r["user_kind"], r["auth_reason"] = fmt.Sprintf("k_%s", strings.Repeat("a", i%30+1)+string(rune('a'+i%26))), fmt.Sprintf("r_%s", strings.Repeat("b", i%40+1)+string(rune('a'+i%26)))
			rows = append(rows, r)
		}
		st := requestStats(rows, 0.8, &requestStage{userFrom: "app_line", userFields: []string{"user_kind", "user_id", "by_kind", "by_id"}, authFields: []string{"auth_result", "auth_via", "auth_reason"}})
		if _, err := json.Marshal(st); err != nil {
			t.Fatalf("JSON にできない: %v", err)
		}
		u, a := st.Users, st.Auth
		if u.Requests < 0 || u.Invalid < 0 || u.By < 0 || u.Requests > st.Starts || u.By > u.Requests || u.Requests+u.Invalid > st.Starts {
			t.Fatalf("users: %+v (starts %d)", u, st.Starts)
		}
		sum := func(m map[string]int64, valid func(string) bool) (n int64) {
			if len(m) > maxUserKeys+1 {
				t.Fatalf("key の数が上限を超えた: %d", len(m))
			}
			for k, v := range m {
				if k != "" && !valid(k) || v <= 0 {
					t.Fatalf("形に合わない key か、0 以下の値: %q = %d", k, v)
				}
				n += v
			}
			return n
		}
		if sum(u.Kinds, ValidUserKind) != u.Requests || sum(a.Via, validAuthVia) != a.Success || sum(a.Reasons, validAuthReason) != a.Failure {
			t.Fatalf("和が合わない: %+v %+v", u, a)
		}
		if _, ok := u.Kinds[""]; ok {
			t.Fatalf("種類の無い ID を数えた: %+v", u)
		}
		if a.Success < 0 || a.Failure < 0 || a.Impersonate < 0 || a.Invalid < 0 || a.Success+a.Failure+a.Impersonate+a.Invalid > st.Starts {
			t.Fatalf("auth: %+v (starts %d)", a, st.Starts)
		}
		if rate, ok := st.UserRate(); ok && (rate < 0 || rate > 1) {
			t.Fatalf("ID の付いた割合が 0〜1 でない: %v", rate)
		}
	})
}

// ログの行から収集の全体を通す (cwlogstest.Sim。実 AWS には接続しない)。設定の正規表現は緩く、種類・ID・auth の結果は任意の文字列。
// 守る規則 (ADR 0052): 形に合った種類と ID のリクエストだけが ID つきに数えられ、形に合わない値のリクエストは捨てた数に入る (ちょうど)。
// 形に合わない値は、record のどこにも残らない。段 0 の数 (リクエストの数) は、足した行で変わらない。
func FuzzUserCollect(f *testing.F) {
	f.Add("user", "42", "success", byte(3))
	f.Add("staff", "5 by=staff:5", "failure", byte(1))
	f.Add("user", "alice@example.com", "denied", byte(2))
	f.Add("User", strings.Repeat("9", 65), "", byte(4))
	f.Add("", "", "impersonate", byte(0))
	f.Add("a b", "x\ny", "success x", byte(5))
	actorRe, authRe := regexp.MustCompile(looseActor), regexp.MustCompile(looseAuth)
	f.Fuzz(func(t *testing.T, kind, id, result string, n byte) {
		count := int(n%8) + 1
		var ev []cwlogstest.Event
		actor, auth := "actor kind="+kind+" id="+id, "auth result="+result
		for i := 0; i < count; i++ {
			ev = append(ev, userReq(day21(1, 0, i), rid(i), "GET", "/", "192.0.2.200", 200, actor, auth)...)
		}
		for i := count; i < count+3; i++ {
			ev = append(ev, userReq(day21(1, 1, i), rid(i), "GET", "/", "192.0.2.200", 200)...)
		}
		sink, col, _, err := collectRequests(t, userSource(looseActor, looseAuth), checksCfg(), ev, userWindow)
		var ce *collect.Error
		if errors.As(err, &ce) && ce.Code == collect.CodeFormatMismatch {
			return // 足した行に改行があると、タグの無い行が増えて行の解釈率が落ちる
		}
		if err != nil {
			t.Fatal(err)
		}
		rs := col.FormatStats().Requests
		if rs.Starts != int64(count+3) {
			t.Fatalf("段 0 の数が変わった: %+v", rs)
		}
		// 同じ規則を Go で書いた見本: 行が設定の正規表現に当たり、取り出した値が形に合えば ID つき
		wantUser, wantInvalid := int64(0), int64(0)
		line := ev[3].Fields["@message"]
		if m := actorRe.FindStringSubmatch(line); m != nil {
			if ValidUserKind(m[1]) && ValidUserID(m[2]) {
				wantUser = int64(count)
			} else {
				wantInvalid = int64(count)
			}
		}
		if rs.Users.Requests != wantUser || rs.Users.Invalid != wantInvalid {
			t.Fatalf("kind=%q id=%q: ID つき %d・捨てた数 %d のはずが %+v", kind, id, wantUser, wantInvalid, rs.Users)
		}
		wantAuth, wantAuthInvalid := int64(0), int64(0)
		if m := authRe.FindStringSubmatch(ev[4].Fields["@message"]); m != nil {
			if validAuthResult(m[1]) {
				wantAuth = int64(count)
			} else {
				wantAuthInvalid = int64(count)
			}
		}
		if got := rs.Auth.Success + rs.Auth.Failure + rs.Auth.Impersonate; got != wantAuth || rs.Auth.Invalid != wantAuthInvalid {
			t.Fatalf("result=%q: auth %d・捨てた数 %d のはずが %+v", result, wantAuth, wantAuthInvalid, rs.Auth)
		}
		if (col.Unavailable() == nil) != (wantUser > 0) {
			t.Fatalf("0 件の run の扱いが違う: users=%d unavailable=%v", wantUser, col.Unavailable())
		}
		// 形に合わない値は record に残らない
		var secrets []string
		if !ValidUserKind(kind) && len(kind) > 3 {
			secrets = append(secrets, kind)
		}
		if !ValidUserID(id) && len(id) > 3 {
			secrets = append(secrets, id)
		}
		if !validAuthResult(result) && len(result) > 3 {
			secrets = append(secrets, result)
		}
		for _, s := range secrets {
			if b, _ := json.Marshal(s); strings.Contains("lines_total lines_matched requests_total requests_complete request_id_reused user_requests user_requests_by user_id_invalid auth_success auth_failures auth_impersonate auth_invalid http_access http_user 2026-10-21 web", strings.Trim(string(b), `"`)) {
				return // 値が metric の名前などの一部と同じ文字の並び
			}
		}
		checkRecords(t, sink.recs, secrets...)
	})
}

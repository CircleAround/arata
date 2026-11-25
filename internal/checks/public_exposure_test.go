package checks

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/config"
	"github.com/CircleAround/arata/internal/record"
)

const (
	pabBPA = "BlockPublicAcls"
	pabIPA = "IgnorePublicAcls"
	pabBPP = "BlockPublicPolicy"
	pabRPB = "RestrictPublicBuckets"
)

// pabPut は今の collector が残す Put*PublicAccessBlock の data (ADR 0086 の 3 節)。bucket が空ならアカウント単位。
func pabPut(bucket string, enabled ...string) map[string]any {
	on := map[string]bool{}
	for _, n := range enabled {
		on[n] = true
	}
	var en, dis []any
	for _, n := range pabFields {
		if on[n] {
			en = append(en, n)
		} else {
			dis = append(dis, n)
		}
	}
	d := map[string]any{"pab_parsed": true}
	if bucket != "" {
		d["bucket"] = bucket
	}
	if len(en) > 0 {
		d["pab_enabled"] = en
	}
	if len(dis) > 0 {
		d["pab_disabled"] = dis
	}
	return d
}

type pabEv struct {
	ago  time.Duration // now からの時間
	name string
	code string
	data map[string]any
}

type pabCase struct {
	name     string
	snapAgo  time.Duration // 0 なら snapshot なし
	snapData map[string]any
	evs      []pabEv
	want     map[string]Severity
	data     map[string]map[string]any // Key → 確かめる data の値
}

func runPABCase(t *testing.T, tc pabCase) []Observation {
	t.Helper()
	st := newStore(t)
	ctx := context.Background()
	if tc.snapAgo != 0 {
		it := record.SnapshotItem{Kind: record.KindPostureItem, Key: account.PostureS3PublicAccess, Data: tc.snapData}
		if err := st.ReplaceSnapshot(ctx, record.KindPostureItem, "posture", []record.SnapshotItem{it}, now.Add(-tc.snapAgo)); err != nil {
			t.Fatal(err)
		}
	}
	for i, e := range tc.evs {
		te := record.TrailEvent{EventID: "e" + string(rune('a'+i)), Time: now.Add(-e.ago), Source: "trail", Name: e.name, EventSource: "s3.amazonaws.com",
			PrincipalARN: secUser, PrincipalKind: record.PrincipalUser, IP: "198.51.100.1", ErrorCode: e.code, Data: e.data}
		if err := st.InsertEvent(ctx, te); err != nil {
			t.Fatal(err)
		}
	}
	al, err := allowlist.Parse([]byte(secAllowlist))
	if err != nil {
		t.Fatal(err)
	}
	w := collect.Window{From: now.Add(-24 * time.Hour), To: now}
	obs, err := PublicExposure{Config: config.DefaultChecks().PublicExposure}.Evaluate(ctx, st, w, al)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

func TestPublicExposurePABTransition(t *testing.T) {
	const putAcct, putBucket, delAcct, delBucket = "PutAccountPublicAccessBlock", "PutBucketPublicAccessBlock", "DeleteAccountPublicAccessBlock", "DeleteBucketPublicAccessBlock"
	allTrue := map[string]any{"configured": true, "block_public_acls": true, "ignore_public_acls": true, "block_public_policy": true, "restrict_public_buckets": true}
	h := time.Hour
	cases := []pabCase{
		{
			name: "設定なしの snapshot から 2 項目を有効にした: 締めた (info)", snapAgo: 48 * h, snapData: map[string]any{"configured": false},
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|tightened:BlockPublicPolicy=true,RestrictPublicBuckets=true": Info},
			data: map[string]map[string]any{"s3:PutAccountPublicAccessBlock|account|tightened:BlockPublicPolicy=true,RestrictPublicBuckets=true": {
				"transition": "tightened", "prior_source": "snapshot", "prior_time": now.Add(-48 * h).Format(time.RFC3339), "prior_configured": false,
				"prior_enabled": []string{}, "enabled": []string{pabBPP, pabRPB}, "newly_enabled": []string{pabBPP, pabRPB},
				"still_disabled": []string{pabBPA, pabIPA}, "exposure": "tightened:BlockPublicPolicy=true,RestrictPublicBuckets=true"}},
		},
		{
			name: "4 項目 true の snapshot から 2 項目を外した: 開けた (high、今と同じ Key)", snapAgo: 48 * h, snapData: allTrue,
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|BlockPublicAcls=false,IgnorePublicAcls=false": High},
			data: map[string]map[string]any{"s3:PutAccountPublicAccessBlock|account|BlockPublicAcls=false,IgnorePublicAcls=false": {
				"transition": "opened", "prior_source": "snapshot", "prior_configured": true, "prior_enabled": []string{pabBPA, pabIPA, pabBPP, pabRPB},
				"newly_disabled": []string{pabBPA, pabIPA}, "still_disabled": []string{}}},
		},
		{
			name: "snapshot が操作の後: 使わない (前が分からない、medium)", snapAgo: 1 * h, snapData: map[string]any{"configured": false},
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": Medium},
			data: map[string]map[string]any{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": {
				"transition": "prior_unknown", "prior_source": "none", "prior_time": nil, "prior_configured": nil, "prior_enabled": nil}},
		},
		{
			name: "snapshot と操作が同じ時刻: 使わない", snapAgo: 2 * h, snapData: map[string]any{"configured": false},
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": Medium},
		},
		{
			name: "snapshot の項目が unknown: 読めない (medium)", snapAgo: 48 * h, snapData: map[string]any{"unknown": true, "action": account.ActionGetPublicAccessBlock},
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": Medium},
			data: map[string]map[string]any{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": {
				"prior_source": "unreadable", "prior_time": now.Add(-48 * h).Format(time.RFC3339)}},
		},
		{
			name: "snapshot の値の型が違う: 読めない", snapAgo: 48 * h, snapData: map[string]any{"configured": true, "block_public_acls": "true"},
			evs:  []pabEv{{2 * h, putAcct, "", pabPut("", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": Medium},
		},
		{
			name: "snapshot の後の記録を使う", snapAgo: 72 * h, snapData: allTrue,
			evs:  []pabEv{{48 * h, putAcct, "", pabPut("")}, {2 * h, putAcct, "", pabPut("", pabIPA, pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|tightened:IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true": Info},
			data: map[string]map[string]any{"s3:PutAccountPublicAccessBlock|account|tightened:IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true": {
				"prior_source": "event", "prior_api": "s3:PutAccountPublicAccessBlock", "prior_time": now.Add(-48 * h).Format(time.RFC3339), "prior_enabled": []string{}}},
		},
		{
			name: "記録と snapshot が同じ時刻: 記録を使う", snapAgo: 48 * h, snapData: allTrue,
			evs:  []pabEv{{48 * h, putAcct, "", pabPut("")}, {2 * h, putAcct, "", pabPut("", pabBPA)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|tightened:BlockPublicAcls=true": Info},
		},
		{
			name: "操作の後の snapshot は使わず、その前の記録と比べる (snapshot より前の記録も引く)", snapAgo: 3 * h, snapData: allTrue,
			evs:  []pabEv{{48 * h, putAcct, "", pabPut("", pabBPA, pabIPA, pabBPP, pabRPB)}, {5 * h, putAcct, "", pabPut("", pabIPA, pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutAccountPublicAccessBlock|account|BlockPublicAcls=false": High},
		},
		{
			name: "同じ窓の先の操作と比べる (バケット単位は記録だけ)",
			evs:  []pabEv{{5 * h, putBucket, "", pabPut("example-bucket", pabBPA, pabIPA, pabRPB)}, {2 * h, putBucket, "", pabPut("example-bucket", pabIPA, pabRPB)}},
			want: map[string]Severity{
				"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:BlockPublicPolicy=false":         Medium,
				"s3:PutBucketPublicAccessBlock|example-bucket|BlockPublicAcls=false,BlockPublicPolicy=false": High,
			},
			data: map[string]map[string]any{"s3:PutBucketPublicAccessBlock|example-bucket|BlockPublicAcls=false,BlockPublicPolicy=false": {
				"newly_disabled": []string{pabBPA}, "still_disabled": []string{pabBPP}, "prior_source": "event"}},
		},
		{
			name: "バケット単位の Put は、アカウントの snapshot を使わない", snapAgo: 48 * h, snapData: map[string]any{"configured": false},
			evs:  []pabEv{{2 * h, putBucket, "", pabPut("example-bucket", pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:BlockPublicAcls=false,IgnorePublicAcls=false": Medium},
		},
		{
			name: "何も変わらない: 報告しない",
			evs:  []pabEv{{48 * h, putBucket, "", pabPut("example-bucket", pabBPP)}, {2 * h, putBucket, "", pabPut("example-bucket", pabBPP)}},
			want: map[string]Severity{},
		},
		{
			name: "4 項目すべて true: 報告しない",
			evs:  []pabEv{{2 * h, putBucket, "", pabPut("example-bucket", pabBPA, pabIPA, pabBPP, pabRPB)}},
			want: map[string]Severity{},
		},
		{
			name: "削除の後の Put は設定なしと比べる",
			evs:  []pabEv{{48 * h, delBucket, "", map[string]any{"bucket": "example-bucket"}}, {2 * h, putBucket, "", pabPut("example-bucket", pabBPA)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|tightened:BlockPublicAcls=true": Info},
			data: map[string]map[string]any{"s3:PutBucketPublicAccessBlock|example-bucket|tightened:BlockPublicAcls=true": {
				"prior_configured": false, "prior_api": "s3:DeleteBucketPublicAccessBlock"}},
		},
		{
			name: "最も新しい記録が読めない (前の版で pab_disabled なし): 古い記録に戻らない",
			evs: []pabEv{{72 * h, putBucket, "", pabPut("example-bucket", pabBPA, pabIPA, pabBPP, pabRPB)}, {48 * h, putBucket, "", map[string]any{"bucket": "example-bucket"}},
				{2 * h, putBucket, "", pabPut("example-bucket", pabIPA, pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:BlockPublicAcls=false": Medium},
			data: map[string]map[string]any{"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:BlockPublicAcls=false": {
				"prior_source": "unreadable", "prior_api": "s3:PutBucketPublicAccessBlock"}},
		},
		{
			name: "前の版の記録 (pab_disabled だけ): 残りを true とみなす",
			evs: []pabEv{{48 * h, putBucket, "", map[string]any{"bucket": "example-bucket", "pab_disabled": []any{pabBPP}}},
				{2 * h, putBucket, "", pabPut("example-bucket", pabIPA, pabRPB)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|BlockPublicAcls=false,BlockPublicPolicy=false": High},
		},
		{
			name: "今回の要求が前の版の形 (pab_disabled だけ) でも判定する",
			evs: []pabEv{{48 * h, putBucket, "", pabPut("example-bucket")},
				{2 * h, putBucket, "", map[string]any{"bucket": "example-bucket", "pab_disabled": []any{pabBPP}}}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|tightened:BlockPublicAcls=true,IgnorePublicAcls=true,RestrictPublicBuckets=true": Info},
		},
		{
			name: "失敗した前の記録は使わない",
			evs:  []pabEv{{48 * h, putBucket, "AccessDenied", pabPut("example-bucket", pabBPA, pabIPA, pabBPP, pabRPB)}, {2 * h, putBucket, "", pabPut("example-bucket", pabIPA, pabBPP, pabRPB)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:BlockPublicAcls=false": Medium},
		},
		{
			name: "別のバケットの記録は使わない",
			evs:  []pabEv{{48 * h, putBucket, "", pabPut("other-bucket")}, {2 * h, putBucket, "", pabPut("example-bucket", pabBPA)}},
			want: map[string]Severity{"s3:PutBucketPublicAccessBlock|example-bucket|prior_unknown:IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false": Medium},
		},
		{
			name: "削除は前の状態を問わず開けた (high)", snapAgo: 48 * h, snapData: map[string]any{"configured": false},
			evs:  []pabEv{{2 * h, delAcct, "", nil}},
			want: map[string]Severity{"s3:DeleteAccountPublicAccessBlock|account|deleted": High},
			data: map[string]map[string]any{"s3:DeleteAccountPublicAccessBlock|account|deleted": {"transition": "opened", "prior_source": "snapshot"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := runPABCase(t, tc)
			got := bySev(obs)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			byKey := byKeyObs(obs)
			for k, want := range tc.data {
				d := byKey[k].Data
				for dk, dv := range want {
					if dv == nil {
						if _, has := d[dk]; has {
							t.Errorf("%s: data.%s must be absent: %v", k, dk, d[dk])
						}
						continue
					}
					if !reflect.DeepEqual(d[dk], dv) {
						t.Errorf("%s: data.%s = %#v, want %#v", k, dk, d[dk], dv)
					}
				}
			}
			for _, o := range obs {
				if !strings.HasPrefix(o.Summary, "公開設定の変更") || o.Fingerprint == "" {
					t.Errorf("obs: %+v", o)
				}
			}
		})
	}
}

// 見出しの中身 (人向け。ADR 0086 の 2 節の表)。
func TestPublicExposurePABSummary(t *testing.T) {
	for _, tc := range []struct {
		d    map[string]any
		want string
	}{
		{map[string]any{"exposure": "tightened:BlockPublicPolicy=true", "transition": "tightened", "newly_enabled": []string{pabBPP}, "still_disabled": []string{pabBPA}},
			"BlockPublicPolicy=true で締めた (無効のまま: BlockPublicAcls)"},
		{map[string]any{"exposure": "tightened:BlockPublicPolicy=true", "transition": "tightened", "newly_enabled": []string{pabBPP}, "still_disabled": []string{}},
			"BlockPublicPolicy=true で締めた"},
		{map[string]any{"exposure": "prior_unknown:BlockPublicAcls=false", "transition": "prior_unknown"}, "前の状態が分からない。今は BlockPublicAcls=false"},
		{map[string]any{"exposure": "BlockPublicAcls=false", "transition": "opened"}, "BlockPublicAcls=false で開けた"},
	} {
		if got := describeExposure(tc.d); !strings.Contains(got, tc.want) {
			t.Errorf("%v: got %q want %q", tc.d, got, tc.want)
		}
	}
}

// 同じ要求でも、判定 (exposure) が違えば Fingerprint も違う。前の状態の時刻は Fingerprint に入れない (ADR 0086 の 5 節)。
func TestPublicExposurePABFingerprint(t *testing.T) {
	h := time.Hour
	fp := func(snapAgo time.Duration, snap map[string]any) string {
		obs := runPABCase(t, pabCase{snapAgo: snapAgo, snapData: snap, evs: []pabEv{{2 * h, "PutAccountPublicAccessBlock", "", pabPut("", pabBPP, pabRPB)}}})
		if len(obs) != 1 {
			t.Fatalf("obs: %+v", obs)
		}
		return obs[0].Fingerprint
	}
	a, b := fp(48*h, map[string]any{"configured": false}), fp(30*h, map[string]any{"configured": false})
	if a != b {
		t.Errorf("snapshot の時刻で Fingerprint が揺れた: %q %q", a, b)
	}
	if c := fp(1*h, map[string]any{"configured": false}); c == a {
		t.Errorf("判定が違うのに Fingerprint が同じ: %q", c)
	}
}

// ファズテスト (ADR 0041・0086 の 7 節)。前の状態 (snapshot か前の記録の data) と今回の要求の data は、ストアから読み戻した値 (ログ由来)。
// 形が想定と違っても、開けた操作を締めた (info) と言う方向に倒れないことを確かめる。
func FuzzPABTransition(f *testing.F) {
	f.Add(`{"configured":false}`, true, `{"pab_parsed":true,"pab_enabled":["BlockPublicPolicy","RestrictPublicBuckets"],"pab_disabled":["BlockPublicAcls","IgnorePublicAcls"]}`, false)
	f.Add(`{"configured":true,"block_public_acls":true,"ignore_public_acls":true,"block_public_policy":true,"restrict_public_buckets":true}`, true, `{"pab_parsed":true,"pab_disabled":["BlockPublicAcls"]}`, false)
	f.Add(`{"pab_parsed":true,"pab_enabled":["BlockPublicAcls","BlockPublicAcls"],"pab_disabled":["BlockPublicAcls"]}`, false, `{"pab_disabled":["BlockPublicPolicy","x"]}`, false)
	f.Add(`{"pab_disabled":["BlockPublicPolicy"]}`, false, `{"pab_parsed":"true","pab_enabled":["IgnorePublicAcls"]}`, false)
	f.Add(`{"unknown":true}`, true, `{}`, true)
	f.Add(`{"configured":true,"block_public_acls":"true"}`, true, `{"pab_parsed":true,"pab_enabled":[1,null],"pab_disabled":{}}`, false)
	f.Fuzz(func(t *testing.T, priorJSON string, fromSnapshot bool, reqJSON string, deleted bool) {
		var pd, rd map[string]any
		if json.Unmarshal([]byte(priorJSON), &pd) != nil || json.Unmarshal([]byte(reqJSON), &rd) != nil {
			return
		}
		var m pabMaterial
		if fromSnapshot {
			m = pabMaterialOfSnapshot(record.SnapshotItem{Time: now.Add(-time.Hour), Data: pd})
		} else {
			m = pabMaterialOfEvent(record.TrailEvent{Time: now.Add(-time.Hour), Name: "PutBucketPublicAccessBlock", Data: pd})
		}
		cur, readable := pabRequestOf(rd)
		j := pabJudge(m, deleted, cur, readable)
		if deleted {
			if j.transition != pabOpened || j.sev != High {
				t.Fatalf("削除が opened (high) でない: %+v", j)
			}
			return
		}
		if !readable {
			if j.sev != "" {
				t.Fatalf("読めない要求を報告した: %+v", j)
			}
			return
		}
		valid := map[string]bool{}
		for _, n := range pabFields {
			valid[n] = true
		}
		seen := map[string]bool{}
		for _, l := range [][]string{j.enabled, j.stillDisabled, j.newlyDisabled} {
			for _, n := range l {
				if !valid[n] || seen[n] {
					t.Fatalf("enabled %v / still_disabled %v / newly_disabled %v が重なるか、知らない名前がある", j.enabled, j.stillDisabled, j.newlyDisabled)
				}
				seen[n] = true
			}
		}
		for _, n := range j.newlyEnabled {
			if !valid[n] || !cur[n] {
				t.Fatalf("newly_enabled %v に今 true でない項目がある", j.newlyEnabled)
			}
		}
		var off []string
		for _, n := range pabFields {
			if !cur[n] {
				off = append(off, n)
			}
		}
		if len(off) == 0 {
			if j.sev != "" {
				t.Fatalf("4 項目 true を報告した: %+v", j)
			}
			return
		}
		if !m.known {
			if j.transition != pabPriorUnknown || j.sev.Rank() < Medium.Rank() {
				t.Fatalf("前が分からない Put が medium より下: %+v", j)
			}
			return
		}
		opened := false
		for _, n := range off {
			if m.enabled[n] {
				opened = true
			}
		}
		switch {
		case opened:
			if j.transition != pabOpened || j.sev != High || len(j.newlyDisabled) == 0 {
				t.Fatalf("前の true が false になったのに opened (high) でない: %+v (前 %v)", j, m.enabled)
			}
		case j.transition == pabTightened:
			if j.sev != Info || len(j.newlyEnabled) == 0 || len(j.newlyDisabled) != 0 {
				t.Fatalf("tightened の条件に合わない: %+v", j)
			}
		case j.sev != "":
			t.Fatalf("変化なしを報告した: %+v", j)
		}
		if !opened && j.transition != pabTightened && len(j.newlyEnabled) > 0 {
			t.Fatalf("有効にした項目があるのに tightened でない: %+v", j)
		}
	})
}

package allowlist

import "sort"

// ExpiringEntry は期限 (expires) のある項目 1 件。
type ExpiringEntry struct {
	// Section は allowlist.yaml の節の名前。
	Section string
	// Subject は項目の対象の表示 (各項目の Subject())。
	Subject string
	// Expires は YYYY-MM-DD。
	Expires string
}

// Expiring は期限のある項目 (principals・assume_destinations・oidc_subjects・shared_sources) を、期限の早い順に返す (ADR 0068 の 3 節)。
// 期限の近さで絞るのは呼び出し側 (報告の作り手) が行う。
func (l *List) Expiring() []ExpiringEntry {
	var out []ExpiringEntry
	for i := range l.Principals {
		if e := &l.Principals[i]; e.Expires != "" {
			out = append(out, ExpiringEntry{Section: "principals", Subject: e.Subject(), Expires: e.Expires})
		}
	}
	for i := range l.AssumeDestinations {
		if e := &l.AssumeDestinations[i]; e.Expires != "" {
			out = append(out, ExpiringEntry{Section: "assume_destinations", Subject: e.Subject(), Expires: e.Expires})
		}
	}
	for i := range l.OIDCSubjects {
		if e := &l.OIDCSubjects[i]; e.Expires != "" {
			out = append(out, ExpiringEntry{Section: "oidc_subjects", Subject: e.Subject(), Expires: e.Expires})
		}
	}
	for i := range l.SharedSources {
		if e := &l.SharedSources[i]; e.Expires != "" {
			out = append(out, ExpiringEntry{Section: "shared_sources", Subject: e.Subject(), Expires: e.Expires})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Expires < out[j].Expires })
	return out
}

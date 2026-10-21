package checks

import (
	"context"
	"fmt"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// GuardDutyFindings はアーカイブされていない GuardDuty の findings を 1 件ずつ報告する (週次、state)。Key は finding ID。
// 重大度は GuardDuty の値で決める: 7 以上 (High / Critical) → high、4 以上 (Medium) → medium、それ未満 → low。
// 件数 (count) の増加は Fingerprint に入れ、changed として報告する。アーカイブされると観測されなくなり resolved。
// GuardDuty が無効なら collector が取れない理由を返し、このチェックは skip される (無効であること自体は posture が報告する)。
type GuardDutyFindings struct{}

func (GuardDutyFindings) Name() string         { return "guardduty_findings" }
func (GuardDutyFindings) Cadence() Cadence     { return Weekly }
func (GuardDutyFindings) Mode() Mode           { return ModeState }
func (GuardDutyFindings) Needs() []record.Kind { return []record.Kind{record.KindGuardDuty} }

// GuardDutySeverity は GuardDuty の重大度 (0〜10) を arata の重大度にする。
func GuardDutySeverity(score float64) Severity {
	switch {
	case score >= 7:
		return High
	case score >= 4:
		return Medium
	}
	return Low
}

func (c GuardDutyFindings) Evaluate(ctx context.Context, q store.Query, _ collect.Window, _ *allowlist.List) ([]Observation, error) {
	items, err := q.Snapshot(ctx, record.KindGuardDuty)
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, it := range items {
		score, count := it.Number("severity"), int(it.Number("count"))
		sev := GuardDutySeverity(score)
		obs = append(obs, Observation{Check: c.Name(), Key: it.Key, Severity: sev,
			Summary:     fmt.Sprintf("GuardDuty: %s (%s、%s、重大度 %.1f、%d 回)", it.String("type"), it.String("resource_type"), it.String("region"), score, count),
			Fingerprint: fingerprint(sev, nil, count),
			Data: map[string]any{"type": it.String("type"), "title": it.String("title"), "severity_score": score, "count": count,
				"region": it.String("region"), "resource_type": it.String("resource_type"), "updated_at": it.String("updated_at")}})
	}
	return obs, nil
}

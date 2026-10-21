package checks

import (
	"context"
	"fmt"

	"github.com/CircleAround/arata/internal/allowlist"
	"github.com/CircleAround/arata/internal/collect"
	"github.com/CircleAround/arata/internal/record"
	"github.com/CircleAround/arata/internal/store"
)

// AccessAnalyzer は IAM Access Analyzer の ACTIVE な findings (外部からアクセスできるリソース) を報告する (週次、state)。
// 公開 (is_public) なら high、それ以外 (特定の外部アカウントなど) は medium。アーカイブ・解消されたら resolved。
// アナライザーが無ければ collector が取れない理由を返し、このチェックは skip される。
type AccessAnalyzer struct{}

func (AccessAnalyzer) Name() string         { return "access_analyzer" }
func (AccessAnalyzer) Cadence() Cadence     { return Weekly }
func (AccessAnalyzer) Mode() Mode           { return ModeState }
func (AccessAnalyzer) Needs() []record.Kind { return []record.Kind{record.KindAccessAnalyzer} }

func (c AccessAnalyzer) Evaluate(ctx context.Context, q store.Query, _ collect.Window, _ *allowlist.List) ([]Observation, error) {
	items, err := q.Snapshot(ctx, record.KindAccessAnalyzer)
	if err != nil {
		return nil, err
	}
	var obs []Observation
	for _, it := range items {
		sev, label := Medium, "外部アカウントからアクセスできる"
		if it.Bool("is_public") {
			sev, label = High, "公開されている"
		}
		obs = append(obs, Observation{Check: c.Name(), Key: it.Key, Severity: sev,
			Summary:     fmt.Sprintf("%s: %s %s (%s、許可: %s)", label, it.String("resource_type"), it.String("resource"), it.String("principal"), it.String("actions")),
			Fingerprint: fingerprint(sev, nil, it.String("resource"), it.String("principal"), it.String("actions")),
			Data: map[string]any{"resource": it.String("resource"), "resource_type": it.String("resource_type"), "is_public": it.Bool("is_public"),
				"principal": it.String("principal"), "actions": it.String("actions"), "analyzer": it.String("analyzer"), "region": it.String("region")}})
	}
	return obs, nil
}

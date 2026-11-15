package config

import "testing"

// TestExampleConfig は examples/arata.yaml と examples/arata-trail-s3.yaml が読めることを保証する (サンプルの陳腐化を防ぐ)。
// cloudtrail-s3 は cloudtrail-lookup と同じ設定に並べられないので、別のファイルで見せる (ADR 0063)。2 つを合わせて全部の種類を見せる。
func TestExampleConfig(t *testing.T) {
	kinds := map[string]bool{}
	for _, p := range []string{"../../examples/arata.yaml", "../../examples/arata-trail-s3.yaml"} {
		cfg, err := Load(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range cfg.Sources {
			kinds[s.Kind] = true
		}
	}
	if len(kinds) != len(SupportedKinds) {
		t.Fatalf("the example must show every source kind: %v", kinds)
	}
}

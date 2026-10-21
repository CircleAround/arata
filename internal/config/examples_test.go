package config

import "testing"

// TestExampleConfig は examples/config.yaml が読めることを保証する (サンプルの陳腐化を防ぐ)。
func TestExampleConfig(t *testing.T) {
	cfg, err := Load("../../examples/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, s := range cfg.Sources {
		kinds[s.Kind] = true
	}
	if len(kinds) != len(SupportedKinds) {
		t.Fatalf("the example must show every source kind: %v", kinds)
	}
}

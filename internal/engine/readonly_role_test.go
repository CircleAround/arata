package engine

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/CircleAround/arata/internal/collect/account"
	"github.com/CircleAround/arata/internal/collect/cwlogs"
)

// 顧客に配る読み取り専用ロール (deploy/iam/readonly-role.yaml) の権限が、doctor が列挙する action と過不足なく一致することを固定する。
// collector に API を足したらロールにも足す (足し忘れると顧客の環境で ACCESS_DENIED になる)。書き込み系は iam:GenerateCredentialReport だけ。
func TestReadonlyRoleActionsMatchRequiredActions(t *testing.T) {
	want := map[string]bool{"cloudtrail:LookupEvents": true}
	for _, a := range cwlogs.RequiredActions {
		want[a] = true
	}
	for _, as := range account.RequiredActions {
		for _, a := range as {
			want[a] = true
		}
	}

	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "iam", "readonly-role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	var policies []*yaml.Node
	findKey(&doc, "Policies", &policies)
	if len(policies) != 1 {
		t.Fatalf("Policies が %d 個 (1 個のはず)", len(policies))
	}
	var actions []*yaml.Node
	findKey(policies[0], "Action", &actions)
	for _, n := range actions {
		collectScalars(n, got)
	}

	if diff := setDiff(want, got); len(diff) > 0 {
		t.Errorf("ロールに無い action: %v", diff)
	}
	if diff := setDiff(got, want); len(diff) > 0 {
		t.Errorf("doctor の一覧に無い action がロールにある: %v", diff)
	}
}

// findKey は mapping の中から key の値のノードを再帰的に集める。
func findKey(n *yaml.Node, key string, out *[]*yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				*out = append(*out, n.Content[i+1])
			}
		}
	}
	for _, c := range n.Content {
		findKey(c, key, out)
	}
}

func collectScalars(n *yaml.Node, out map[string]bool) {
	if n.Kind == yaml.ScalarNode {
		out[n.Value] = true
		return
	}
	for _, c := range n.Content {
		collectScalars(c, out)
	}
}

func setDiff(a, b map[string]bool) []string {
	var d []string
	for k := range a {
		if !b[k] {
			d = append(d, k)
		}
	}
	sort.Strings(d)
	return d
}

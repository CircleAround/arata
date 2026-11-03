package checks

import (
	"testing"

	"github.com/CircleAround/arata/docs/ai"
)

// TestEveryCheckHasPlaybook は登録済みのチェックすべてに対処手順 (docs/ai/playbooks/<check>.md) があり、
// 逆に登録されていないチェックの playbook が無いことを固定する。新しいチェックを足したら playbook も書く。
func TestEveryCheckHasPlaybook(t *testing.T) {
	reg := NewRegistry()
	for _, name := range reg.Names() {
		if _, ok := ai.Playbook(name); !ok {
			t.Errorf("check %s has no playbook (write docs/ai/playbooks/%s.md)", name, name)
		}
	}
	for _, name := range ai.PlaybookNames() {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("playbook %s has no registered check", name)
		}
	}
}

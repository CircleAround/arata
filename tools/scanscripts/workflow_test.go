package scanscripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// stepScript は secrets-scan.yml の「run: |」のうち、marker を含むものの中身を返す。
func stepScript(t *testing.T, marker string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "secrets-scan.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const open, indent = "        run: |\n", "          "
	for _, part := range strings.Split(string(b), open)[1:] {
		var script strings.Builder
		for _, l := range strings.Split(part, "\n") {
			if !strings.HasPrefix(l, indent) {
				break
			}
			script.WriteString(strings.TrimPrefix(l, indent) + "\n")
		}
		if strings.Contains(script.String(), marker) {
			return script.String()
		}
	}
	t.Fatalf("%s を呼ぶ step が無い", marker)
	return ""
}

// PR はその PR のコミットだけ、それ以外のイベントは全部の枝を読む。
func TestWorkflowRangeByEvent(t *testing.T) {
	script := stepScript(t, "tools/scan-commits.sh")
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "tools"), 0o700); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/sh\necho \"$*\"\n"
	if err := os.WriteFile(filepath.Join(dir, "tools", "scan-commits.sh"), []byte(fake), 0o700); err != nil { // #nosec G306 -- テストが起動する偽の実行ファイル
		t.Fatal(err)
	}
	for _, c := range []struct {
		event, base, head, want string
		fail                    bool
	}{
		{event: "pull_request", base: "aaa", head: "bbb", want: "aaa..bbb"},
		{event: "push", want: "--all"},
		{event: "schedule", want: "--all"},
		{event: "workflow_dispatch", want: "--all"},
		// 空の値のまま「..」にすると 0 件で成功するので、落とす
		{event: "pull_request", head: "bbb", fail: true},
		{event: "pull_request", base: "aaa", fail: true},
	} {
		cmd := exec.Command("bash", "-eo", "pipefail", "-c", script) // #nosec G204 -- このリポジトリのワークフローの中身
		cmd.Dir = dir
		cmd.Env = append(cleanEnv(), "EVENT="+c.event, "BASE_SHA="+c.base, "HEAD_SHA="+c.head)
		out, err := cmd.Output()
		if c.fail {
			if err == nil {
				t.Errorf("%+v: 成功した: %s", c, out)
			}
			continue
		}
		if err != nil || strings.TrimSpace(string(out)) != c.want {
			t.Errorf("%+v: out=%q err=%v", c, out, err)
		}
	}
}

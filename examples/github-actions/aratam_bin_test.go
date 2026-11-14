package githubactions_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	binOnce sync.Once
	binDir  string
	binErr  error
)

// realBins は、このリポジトリの arata と aratam をビルドした置き場所 (PATH に足す)。
// ワークフローの run: を、偽の出力だけでなく、この版の本物のコマンドでも動かして確かめるために使う。
// どちらも、ここで使うコマンド (config check / repo check) は AWS にも Slack にも LLM にも GitHub にも繋がない。
func realBins(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "arata-bin-*")
		if binErr != nil {
			return
		}
		for _, name := range []string{"arata", "aratam"} {
			// 版は、見本のワークフローの ARATA_VERSION と同じにする (arata repo check は、その版の一式と比べる)
			cmd := exec.Command("go", "build", "-ldflags", "-X main.version="+exampleVersion, "-o", filepath.Join(binDir, name), "../../cmd/"+name)
			if out, err := cmd.CombinedOutput(); err != nil {
				binErr = &buildError{string(out), err}
				return
			}
		}
	})
	if binErr != nil {
		t.Fatalf("building arata and aratam: %v", binErr)
	}
	return binDir
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}

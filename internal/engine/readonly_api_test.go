package engine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 監査対象には読み取りしかしない約束 (設計書 8 章) をコードで固定する。
// collector と doctor が組み立てる AWS SDK の入力の型 (<操作>Input) を全部見て、読み取りの操作だけであることを確かめる。
// internal/store の PutObject は arata 自身のストアへの書き込みで、監査対象ではないので見ない。
var readPrefixes = []string{"Get", "List", "Describe", "Lookup", "Head"}

// nonReadOps は読み取りの名前ではないが許すもの。
var nonReadOps = map[string]string{
	"GenerateCredentialReport": "認証情報レポートの生成。唯一の書き込み系 (設計書 8 章)",
	"StartQuery":               "Logs Insights の問い合わせの開始。ログも設定も変えない",
	"StopQuery":                "自分で始めた問い合わせの中止",
}

func awsOperations(t *testing.T, root string) map[string]string {
	t.Helper()
	ops := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root && strings.HasSuffix(d.Name(), "test") {
			return filepath.SkipDir // 偽の AWS
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		sdk := map[string]bool{}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if !strings.HasPrefix(p, "github.com/aws/aws-sdk-go-v2/service/") {
				continue
			}
			name := p[strings.LastIndex(p, "/")+1:]
			if im.Name != nil {
				name = im.Name.Name
			}
			sdk[name] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := s.X.(*ast.Ident); ok && sdk[x.Name] {
					if op, ok := strings.CutSuffix(s.Sel.Name, "Input"); ok {
						ops[op] = path
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ops
}

func TestOnlyReadOperationsOnAuditTargets(t *testing.T) {
	ops := awsOperations(t, filepath.Join("..", "collect"))
	for op, path := range awsOperations(t, ".") {
		ops[op] = path
	}
	if ops["LookupEvents"] == "" || ops["GenerateCredentialReport"] == "" {
		t.Fatalf("操作を見つけられていない: %v", ops)
	}
	for op, path := range ops {
		ok := nonReadOps[op] != ""
		for _, p := range readPrefixes {
			ok = ok || strings.HasPrefix(op, p)
		}
		if !ok {
			t.Errorf("%s: 読み取りでない操作 %s を呼んでいる", path, op)
		}
	}
}

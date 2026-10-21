// aratam は arata の出力 (report.json / report.md) を読み、要約して通知するコマンド (docs/aratam.md、ADR 0018)。
package main

import (
	"os"
)

// version はビルド時に -ldflags '-X main.version=...' で埋める。
var version = "dev"

func main() {
	os.Exit(Execute(os.Args[1:], DefaultDeps()))
}

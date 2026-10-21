// arata は AWS のログを改め、前回から新しく発生したものを報せる監査エンジンの CLI。
package main

import (
	"os"
)

// version はビルド時に -ldflags '-X main.version=...' で埋める。
var version = "dev"

func main() {
	os.Exit(Execute(os.Args[1:], DefaultDeps()))
}

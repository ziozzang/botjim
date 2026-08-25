// Command botjim ferries files between machines with their attributes
// intact: server waits, client pushes or pulls, chunk-parallel with resume.
package main

import (
	"os"

	"github.com/ziozzang/botjim/internal/cli"
)

func main() {
	cli.StartUpdateRefresh()
	code := cli.Main(os.Args[1:])
	cli.MaybeNotifyUpdate()
	os.Exit(code)
}

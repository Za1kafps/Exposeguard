package main

import (
	"os"

	"github.com/Za1kafps/exposeguard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdout, os.Stderr))
}

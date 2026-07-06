package main

import (
	"os"

	"github.com/Flexipie/coffin/internal/cli"
)

func main() {
	os.Exit(cli.ExitCode(cli.Execute()))
}

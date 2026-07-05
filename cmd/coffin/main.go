package main

import (
	"os"

	"github.com/Flexipie/coffin/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

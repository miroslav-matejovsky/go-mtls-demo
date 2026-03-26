package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlsmem"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tlsmem"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-mtls-demo <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlstpm> [--config path]")
		os.Exit(1)
	}

	mode := os.Args[1]

	// Parse any flags that follow the mode argument.
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	configPath := fs.String("config", "", "path to TOML config file (overrides built-in default)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var err error
	switch mode {
	case "tlsmem":
		err = tlsmem.RunDemo()
	case "mtlsmem":
		err = mtlsmem.RunDemo()
	case "tlsfiles":
		err = tlsfiles.RunDemo(*configPath)
	case "mtlsfiles":
		err = mtlsfiles.RunDemo(*configPath)
	case "mtlstpm":
		err = runMtlsTpmDemo(*configPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q — use \"tlsmem\", \"mtlsmem\", \"tlsfiles\", \"mtlsfiles\", or \"mtlstpm\"\n", mode)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

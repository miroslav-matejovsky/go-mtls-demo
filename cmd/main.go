package main

import (
	"fmt"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/mtlsenterprise"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/mtlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/mtlsmem"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/tlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/tlsmem"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-mtls-demo <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlsenterprise|mtlsenterprisetpm|mtlstpm>")
		os.Exit(1)
	}

	mode := os.Args[1]

	var err error
	switch mode {
	case "tlsmem":
		err = tlsmem.RunDemo()
	case "mtlsmem":
		err = mtlsmem.RunDemo()
	case "tlsfiles":
		err = tlsfiles.RunDemo()
	case "mtlsfiles":
		err = mtlsfiles.RunDemo()
	case "mtlsenterprise":
		err = mtlsenterprise.RunDemo()
	case "mtlsenterprisetpm":
		err = runMtlsEnterpriseTpmDemo()
	case "mtlstpm":
		err = runMtlsTpmDemo()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q — use \"tlsmem\", \"mtlsmem\", \"tlsfiles\", \"mtlsfiles\", \"mtlsenterprise\", \"mtlsenterprisetpm\", or \"mtlstpm\"\n", mode)
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

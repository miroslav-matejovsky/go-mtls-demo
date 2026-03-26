package main

import (
	"fmt"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlsmem"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tlsfiles"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tlsmem"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-mtls-demo <tlsmem|mtlsmem|tlsfiles|mtlsfiles|mtlstpm>")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "tlsmem":
		err = tlsmem.RunDemo()
	case "mtlsmem":
		err = mtlsmem.RunDemo()
	case "tlsfiles":
		err = tlsfiles.RunDemo()
	case "mtlsfiles":
		err = mtlsfiles.RunDemo()
	case "mtlstpm":
		err = runMtlsTpmDemo()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q — use \"tlsmem\", \"mtlsmem\", \"tlsfiles\", \"mtlsfiles\", or \"mtlstpm\"\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

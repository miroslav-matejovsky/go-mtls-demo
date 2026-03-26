package main

import (
	"fmt"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlsmem"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tlsmem"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-mtls-demo <tlsmem|mtlsmem>")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "tlsmem":
		err = tlsmem.RunDemo()
	case "mtlsmem":
		err = mtlsmem.RunDemo()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q — use \"tlsmem\" or \"mtlsmem\"\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

package main

import (
	"fmt"
	"os"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtls"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tls"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-mtls-demo <tls|mtls>")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "tls":
		err = tls.RunDemo()
	case "mtls":
		err = mtls.RunDemo()
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q — use \"tls\" or \"mtls\"\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		panic(err)
	}
}

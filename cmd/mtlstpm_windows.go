//go:build windows

package main

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlstpm"

func runMtlsTpmDemo() error {
	return mtlstpm.RunDemo()
}

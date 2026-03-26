//go:build windows

package main

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlstpm"

func runMtlstpmDemo() error {
	return mtlstpm.RunDemo()
}

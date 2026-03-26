//go:build windows

package main

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/mtlstpm"

func runMtlsTpmDemo(configPath string) error {
	return mtlstpm.RunDemo(configPath)
}

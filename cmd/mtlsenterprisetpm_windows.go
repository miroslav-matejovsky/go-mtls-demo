//go:build windows

package main

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/scenarios/mtlsenterprisetpm"

func runMtlsEnterpriseTpmDemo() error {
	return mtlsenterprisetpm.RunDemo()
}

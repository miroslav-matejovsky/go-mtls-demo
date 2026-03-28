//go:build !windows

package main

import "fmt"

func runMtlsEnterpriseTpmDemo() error {
	return fmt.Errorf("mtlsenterprisetpm scenario requires Windows (Windows Certificate Store + TPM)")
}

//go:build !windows

package main

import "fmt"

func runMtlstpmDemo() error {
	return fmt.Errorf("mtlstpm scenario requires Windows (Windows Certificate Store + TPM)")
}

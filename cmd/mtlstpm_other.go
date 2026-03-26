//go:build !windows

package main

import "fmt"

func runMtlsTpmDemo() error {
	return fmt.Errorf("mtlstpm scenario requires Windows (Windows Certificate Store + TPM)")
}

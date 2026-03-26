//go:build !windows

package main

import "fmt"

func runMtlsTpmDemo(_ string) error {
	return fmt.Errorf("mtlstpm scenario requires Windows (Windows Certificate Store + TPM)")
}

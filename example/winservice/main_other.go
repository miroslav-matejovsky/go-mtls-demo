//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("This example requires Windows (cert store + TPM/NCrypt).")
	fmt.Println("On other platforms, use the standard mTLS example: go run ./example/mtls/")
}

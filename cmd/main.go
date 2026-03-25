package main

import "github.com/miroslav-matejovsky/go-mtls-demo/internal/mtls"

func main() {
	println("Creating CA...")
	ca, err := mtls.CreateCa()
	if err != nil {
		println("Error creating CA:", err)
		return
	}
	mtls.PrintCertificateInfo(ca)
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/mtls"
)

func main() {
	println("Creating CA...")
	ca, signLeaf, err := mtls.CreateCa()
	if err != nil {
		println("Error creating CA:", err)
		return
	}
	println("CA created successfully")
	mtls.PrintCertificateInfo(ca)

	// this can be replaced by certtostore store.GenerateKey()
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println("Error generating leaf key:", err)
		return
	}
	cert, err := signLeaf(&certKey.PublicKey, "go mTLS Demo Certificate")
	if err != nil {
		println("Error signing leaf certificate:", err)
		return
	}

	println("Leaf certificate created successfully")
	mtls.PrintCertificateInfo(cert)

}

package gomtlsdemo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func CreateCa() (*x509.Certificate, error) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go mTLS Demo CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// KeyUsageCertSign - allows the certificate to be used for signing other certificates (i.e. as a CA)
		// KeyUsageCRLSign - allows the certificate to be used for signing Certificate Revocation Lists (CRLs)
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return ca, nil
}

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
)

func CreateClient(ca *x509.Certificate) (*http.Client, error) {
	certpool := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	certpool.AppendCertsFromPEM(caPEM)

	clientTLSConf := &tls.Config{RootCAs: certpool}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLSConf},
	}
	return client, nil
}

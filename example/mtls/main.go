package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/example/mtls/certs"
	"github.com/miroslav-matejovsky/go-mtls-demo/example/mtls/client"
	"github.com/miroslav-matejovsky/go-mtls-demo/example/mtls/operator"
	"github.com/miroslav-matejovsky/go-mtls-demo/example/mtls/server"
)

const (
	operatorConfigPath        = "example/mtls/configs/operator.toml"
	serverConfigPath          = "example/mtls/configs/server.toml"
	clientConfigPath          = "example/mtls/configs/client.toml"
	untrustedClientConfigPath = "example/mtls/configs/untrusted_client.toml"
)

func main() {
	opCfg, err := operator.LoadOperatorConfig(operatorConfigPath)
	if err != nil {
		panic(err)
	}
	serverCfg, err := operator.LoadServerConfig(serverConfigPath)
	if err != nil {
		panic(err)
	}
	clientCfg, err := operator.LoadClientConfig(clientConfigPath)
	if err != nil {
		panic(err)
	}
	untrustedCfg, err := operator.LoadUntrustedClientConfig(untrustedClientConfigPath)
	if err != nil {
		panic(err)
	}
	if err := runDemo(opCfg, serverCfg, clientCfg, untrustedCfg); err != nil {
		panic(err)
	}
}

type demoState struct {
	op        *operator.Operator
	server    *http.Server
	serverURL string
	serverErr chan error
}

func newDemoState() *demoState {
	return &demoState{
		serverErr: make(chan error, 1),
	}
}

func (s *demoState) recordServerError(err error) {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}
	select {
	case s.serverErr <- err:
	default:
	}
}

func (s *demoState) unexpectedServerError() error {
	select {
	case err := <-s.serverErr:
		return fmt.Errorf("server stopped unexpectedly: %w", err)
	default:
		return nil
	}
}

func runDemo(opCfg operator.OperatorConfig, serverCfg operator.ServerConfig, clientCfg operator.ClientConfig, untrustedCfg operator.UntrustedClientConfig) error {
	state := newDemoState()

	// --- Step 1/8: Create Root CA ---
	fmt.Println("=== Step 1/8: Create Root CA ===")
	fmt.Println("In production the root CA is offline — it only signs intermediate CAs.")
	fmt.Println()

	op, err := operator.NewOperator(opCfg)
	if err != nil {
		return fmt.Errorf("error creating operator: %w", err)
	}
	state.op = op

	fmt.Println("[OPERATOR] Root CA certificate:")
	certs.PrintCertificateInfo(op.RootCert())
	fmt.Printf("  [OPERATOR] Root CA cert → %s\n", opCfg.RootCA.CertFile)
	fmt.Println("  [OPERATOR] Root CA key stays in memory — never written to disk.")
	fmt.Println()

	// --- Step 2/8: Create Intermediate CA ---
	fmt.Println("=== Step 2/8: Create Intermediate CA (signed by Root) ===")
	fmt.Println("The intermediate CA is the operational issuer. MaxPathLen: 0 prevents sub-intermediates.")
	fmt.Println()

	intCert := op.IntermediateCert()
	rootCert := op.RootCert()

	fmt.Println("[OPERATOR] Intermediate CA certificate:")
	certs.PrintCertificateInfo(intCert)

	fmt.Printf("  [OPERATOR] SKID/AKID linkage:\n")
	fmt.Printf("    Root SKID         : %X\n", rootCert.SubjectKeyId)
	fmt.Printf("    Intermediate AKID : %X\n", intCert.AuthorityKeyId)
	fmt.Printf("    Match             : %t\n", bytes.Equal(rootCert.SubjectKeyId, intCert.AuthorityKeyId))
	fmt.Println()

	// --- Step 3/8: Generate server certificate ---
	fmt.Println("=== Step 3/8: Generate server certificate (ServerAuth EKU, DNS SANs) ===")
	fmt.Println()

	serverCert, serverKey, err := op.SignServerCert(serverCfg.CN, serverCfg.DNSNames)
	if err != nil {
		return fmt.Errorf("error creating server certificate: %w", err)
	}
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("error marshaling server key: %w", err)
	}

	if err := op.WriteServerChain(serverCfg.ChainFile, serverCert); err != nil {
		return fmt.Errorf("error writing server chain bundle: %w", err)
	}
	if err := certs.WriteKey(serverCfg.KeyFile, serverKeyBytes); err != nil {
		return fmt.Errorf("error writing server key: %w", err)
	}
	if err := op.DistributeRootCA(serverCfg.RootCertFile); err != nil {
		return fmt.Errorf("error distributing root CA to server: %w", err)
	}

	fmt.Println("[OPERATOR] Server certificate:")
	certs.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] EKU         : ServerAuth only\n")
	fmt.Printf("  [SERVER] Chain bundle → %s\n", serverCfg.ChainFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverCfg.KeyFile)
	fmt.Printf("  [SERVER] Root CA cert → %s  (distributed by operator)\n", serverCfg.RootCertFile)
	fmt.Println()

	// --- Step 4/8: Generate client certificate ---
	fmt.Println("=== Step 4/8: Generate client certificate (ClientAuth EKU) ===")
	fmt.Println()

	clientCert, clientKey, err := op.SignClientCert(clientCfg.CN)
	if err != nil {
		return fmt.Errorf("error creating client certificate: %w", err)
	}
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return fmt.Errorf("error marshaling client key: %w", err)
	}

	if err := op.WriteClientChain(clientCfg.ChainFile, clientCert); err != nil {
		return fmt.Errorf("error writing client chain bundle: %w", err)
	}
	if err := certs.WriteKey(clientCfg.KeyFile, clientKeyBytes); err != nil {
		return fmt.Errorf("error writing client key: %w", err)
	}
	if err := op.DistributeRootCA(clientCfg.RootCertFile); err != nil {
		return fmt.Errorf("error distributing root CA to client: %w", err)
	}

	fmt.Println("[OPERATOR] Client certificate:")
	certs.PrintCertificateInfo(clientCert)
	fmt.Printf("  [CLIENT] EKU         : ClientAuth only\n")
	fmt.Printf("  [CLIENT] Chain bundle → %s\n", clientCfg.ChainFile)
	fmt.Printf("  [CLIENT] Private key  → %s\n", clientCfg.KeyFile)
	fmt.Printf("  [CLIENT] Root CA cert → %s  (distributed by operator)\n", clientCfg.RootCertFile)
	fmt.Println()

	// --- Step 5/8: Start mTLS server ---
	fmt.Println("=== Step 5/8: Start mTLS server (presenting certificate chain) ===")
	fmt.Println("Server presents: server cert + intermediate CA. Server trusts: root CA for client validation.")
	fmt.Println()

	srv, err := server.CreateServer(serverCfg.ChainFile, serverCfg.KeyFile, serverCfg.RootCertFile)
	if err != nil {
		return fmt.Errorf("error creating server: %w", err)
	}
	srv.ErrorLog = log.New(io.Discard, "", 0)

	ln, err := tls.Listen("tcp", serverCfg.Address, srv.TLSConfig)
	if err != nil {
		return fmt.Errorf("error starting TLS listener on %s: %w", serverCfg.Address, err)
	}
	go func() {
		state.recordServerError(srv.Serve(ln))
	}()

	state.server = srv
	state.serverURL = "https://" + ln.Addr().String()

	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			srv.Close()
		}
	}()

	// --- Step 6/8: Trusted mTLS request ---
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 6/8: Make request over mTLS (trusted client) ===")
	fmt.Println("Client presents: client cert + intermediate CA. Client trusts: root CA for server validation.")
	fmt.Println("Full chain verification: leaf → intermediate → root.")
	fmt.Println()

	trustedClient, err := client.CreateClient(clientCfg.RootCertFile, clientCfg.ChainFile, clientCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := trustedClient.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("error making GET request: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server certificate verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake complete  — version: %s, cipher suite: %s\n",
		certs.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Println("[CLIENT] Response:", resp.Status)
	fmt.Println()

	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	// --- Step 7/8: Untrusted client rejected ---
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 7/8: Make request with untrusted client (different PKI) ===")
	fmt.Println("This client's certificate chain originates from a completely different root CA.")
	fmt.Println()

	// Build an entirely separate PKI: root → intermediate → client leaf
	_, untrustedSignInt, err := certs.CreateRootCA(untrustedCfg.RootCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted root CA: %w", err)
	}
	untrustedIntCert, untrustedSignLeaf, err := untrustedSignInt(untrustedCfg.IntermediateCACN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("error creating untrusted intermediate CA: %w", err)
	}

	profile := certs.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	untrustedClientCert, untrustedClientKey, err := certs.CreateLeafCertWithProfile(untrustedSignLeaf, untrustedCfg.CN, profile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client certificate: %w", err)
	}
	untrustedKeyBytes, err := x509.MarshalECPrivateKey(untrustedClientKey)
	if err != nil {
		return fmt.Errorf("error marshaling untrusted client key: %w", err)
	}

	// Write untrusted chain bundle (leaf + untrusted intermediate)
	if err := certs.WriteChainBundle(untrustedCfg.ChainFile, untrustedClientCert, untrustedIntCert); err != nil {
		return fmt.Errorf("error writing untrusted client chain bundle: %w", err)
	}
	if err := certs.WriteKey(untrustedCfg.KeyFile, untrustedKeyBytes); err != nil {
		return fmt.Errorf("error writing untrusted client key: %w", err)
	}
	// The untrusted client still needs the TRUSTED server's root CA to verify the server cert
	if err := op.DistributeRootCA(untrustedCfg.RootCertFile); err != nil {
		return fmt.Errorf("error writing trusted root CA to untrusted directory: %w", err)
	}

	fmt.Printf("  [UNTRUSTED CLIENT] Chain bundle → %s\n", untrustedCfg.ChainFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Private key  → %s\n", untrustedCfg.KeyFile)
	fmt.Printf("  [UNTRUSTED CLIENT] Server root  → %s  (to verify server, but client cert chains to different root)\n", untrustedCfg.RootCertFile)
	fmt.Println()

	untrustedHTTPClient, err := client.CreateClient(untrustedCfg.RootCertFile, untrustedCfg.ChainFile, untrustedCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("error creating untrusted client: %w", err)
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedHTTPClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused the certificate because it was not signed by the trusted CA.")
		fmt.Println()
		if err := state.unexpectedServerError(); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
	}

	// --- Step 8/8: Summary ---
	fmt.Println("=== Step 8/8: Inspect certificate chain and file layout ===")
	fmt.Println()

	fmt.Println("Certificate chain (SKID → AKID linkage):")
	fmt.Printf("  Root CA          SKID: %X\n", rootCert.SubjectKeyId)
	fmt.Printf("  Intermediate CA  AKID: %X  (must match Root SKID)\n", intCert.AuthorityKeyId)
	fmt.Printf("  Intermediate CA  SKID: %X\n", intCert.SubjectKeyId)
	fmt.Println("  Leaf certs       AKID: (matches Intermediate SKID — see cert info above)")
	fmt.Println()

	fmt.Println("File layout — each directory represents a security boundary:")
	entries := []struct{ file, note string }{
		{opCfg.RootCA.CertFile, "public — root CA certificate (offline)"},
		{opCfg.IntermediateCA.CertFile, "public — intermediate CA certificate"},
		{serverCfg.ChainFile, "public — server leaf + intermediate CA bundle"},
		{serverCfg.KeyFile, "private — never leaves the server machine"},
		{serverCfg.RootCertFile, "public — root CA copy, used to verify client chains"},
		{clientCfg.ChainFile, "public — client leaf + intermediate CA bundle"},
		{clientCfg.KeyFile, "private — never leaves the client machine"},
		{clientCfg.RootCertFile, "public — root CA copy, used to verify server chain"},
		{untrustedCfg.ChainFile, "public — rejected by server, different PKI"},
		{untrustedCfg.KeyFile, "private — never leaves the untrusted client"},
		{untrustedCfg.RootCertFile, "public — trusted server's root CA copy"},
	}
	for _, entry := range entries {
		fmt.Printf("  %-60s  %s\n", entry.file, entry.note)
	}

	return nil
}

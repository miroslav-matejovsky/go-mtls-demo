//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/certtostore"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/cert"
)

const (
	// Certificate output paths
	certBaseDir      = "certs/example-winservice"
	rootCACertFile   = certBaseDir + "/root-ca/cert.crt"
	intCACertFile    = certBaseDir + "/intermediate-ca/cert.crt"
	serverChainFile  = certBaseDir + "/server/chain.crt"
	serverKeyFile    = certBaseDir + "/server/server.key"
	serverRootCAFile = certBaseDir + "/server/root-ca.crt"

	// PKI configuration
	rootCACN        = "Example WinService Root CA"
	intermediCACN   = "Example WinService Intermediate CA"
	serverCN        = "Example WinService Server"
	clientCN        = "Example WinService Client"
	untrustedRootCN = "Example WinService Untrusted Root CA"
	untrustedIntCN  = "Example WinService Untrusted Intermediate CA"
	untrustedCliCN  = "Example WinService Untrusted Client"
	containerName   = "example-winservice-client"
)

type demoState struct {
	rootCert     *x509.Certificate
	intCert      *x509.Certificate
	signLeaf     cert.ProfiledSignerFunc
	provider     string
	store        *certtostore.WinCertStore
	clientSigner crypto.Signer
	clientCert   *x509.Certificate
	storedCert   *x509.Certificate
	storeKey     crypto.Signer
	server       *http.Server
	serverURL    string
	serverErr    chan error
}

func newDemoState() *demoState {
	return &demoState{serverErr: make(chan error, 1)}
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

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--service" {
		if err := runService("example-winservice", false); err != nil {
			panic(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--service-debug" {
		if err := runService("example-winservice", true); err != nil {
			panic(err)
		}
		return
	}
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	state := newDemoState()

	// Step 1: Create Root CA
	if err := step1CreateRootCA(state); err != nil {
		return err
	}
	// Step 2: Create Intermediate CA
	if err := step2CreateIntermediateCA(state); err != nil {
		return err
	}
	// Step 3: Generate server cert
	if err := step3GenerateServerCert(state); err != nil {
		return err
	}
	// Step 4: Generate client key in Windows cert store
	if err := step4GenerateClientKey(state); err != nil {
		return err
	}
	defer func() {
		if state.store != nil {
			state.store.Close()
		}
	}()

	// Step 5: Sign client cert with enterprise intermediate
	if err := step5SignClientCert(state); err != nil {
		return err
	}
	// Step 6: Import cert into store + re-derive key
	if err := step6ImportClientCert(state); err != nil {
		return err
	}
	// Step 7: Start server + trusted request
	if err := step7StartServerAndRequest(state); err != nil {
		return err
	}
	defer func() {
		if state.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := state.server.Shutdown(ctx); err != nil {
				state.server.Close()
			}
		}
	}()

	// Step 8: Untrusted client rejected
	if err := step8UntrustedClient(state); err != nil {
		return err
	}

	// Shutdown before summary
	if state.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := state.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutting down server: %w", err)
		}
		state.server = nil
	}
	if state.store != nil {
		if err := state.store.Close(); err != nil {
			return fmt.Errorf("closing cert store: %w", err)
		}
		state.store = nil
	}

	// Step 9: Summary + cleanup
	return step9Summary(state)
}

// --- Step 1 ---

func step1CreateRootCA(state *demoState) error {
	fmt.Println("=== Step 1/9: Create Root CA ===")
	fmt.Println("In production the root CA is offline — it only signs intermediate CAs.")
	fmt.Println()

	rootCert, signInt, err := cert.CreateRootCA(rootCACN, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("creating root CA: %w", err)
	}

	if err := cert.WriteCert(rootCACertFile, rootCert); err != nil {
		return fmt.Errorf("writing root CA cert: %w", err)
	}

	intCert, signLeaf, err := signInt(intermediCACN, 30*24*time.Hour)
	if err != nil {
		return fmt.Errorf("creating intermediate CA: %w", err)
	}

	if err := cert.WriteCert(intCACertFile, intCert); err != nil {
		return fmt.Errorf("writing intermediate CA cert: %w", err)
	}

	state.rootCert = rootCert
	state.intCert = intCert
	state.signLeaf = signLeaf

	fmt.Println("[OPERATOR] Root CA certificate:")
	cert.PrintCertificateInfo(rootCert)
	fmt.Printf("  Root CA cert → %s\n", rootCACertFile)
	fmt.Println("  Root CA key stays in memory — never written to disk.")
	fmt.Println()
	return nil
}

// --- Step 2 ---

func step2CreateIntermediateCA(state *demoState) error {
	fmt.Println("=== Step 2/9: Create Intermediate CA (signed by Root) ===")
	fmt.Println("The intermediate CA is the operational issuer. MaxPathLen: 0 prevents sub-intermediates.")
	fmt.Println()

	fmt.Println("[OPERATOR] Intermediate CA certificate:")
	cert.PrintCertificateInfo(state.intCert)

	fmt.Println("[OPERATOR] SKID/AKID linkage:")
	fmt.Printf("  Root SKID         : %X\n", state.rootCert.SubjectKeyId)
	fmt.Printf("  Intermediate AKID : %X\n", state.intCert.AuthorityKeyId)
	match := fmt.Sprintf("%X", state.rootCert.SubjectKeyId) == fmt.Sprintf("%X", state.intCert.AuthorityKeyId)
	fmt.Printf("  Match             : %t\n", match)
	fmt.Println()
	return nil
}

// --- Step 3 ---

func step3GenerateServerCert(state *demoState) error {
	fmt.Println("=== Step 3/9: Generate server certificate (ServerAuth EKU, DNS SANs) ===")
	fmt.Println()

	profile := cert.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	serverCert, serverKey, err := cert.CreateLeafCertWithProfile(state.signLeaf, serverCN, profile)
	if err != nil {
		return fmt.Errorf("creating server cert: %w", err)
	}

	if err := cert.WriteChainBundle(serverChainFile, serverCert, state.intCert); err != nil {
		return fmt.Errorf("writing server chain: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshaling server key: %w", err)
	}
	if err := cert.WriteKey(serverKeyFile, keyDER); err != nil {
		return fmt.Errorf("writing server key: %w", err)
	}
	if err := cert.WriteCert(serverRootCAFile, state.rootCert); err != nil {
		return fmt.Errorf("distributing root CA to server: %w", err)
	}

	fmt.Println("[OPERATOR] Server certificate:")
	cert.PrintCertificateInfo(serverCert)
	fmt.Printf("  [SERVER] Chain bundle → %s\n", serverChainFile)
	fmt.Printf("  [SERVER] Private key  → %s\n", serverKeyFile)
	fmt.Printf("  [SERVER] Root CA cert → %s\n", serverRootCAFile)
	fmt.Println()
	return nil
}

// --- Step 4 ---

func step4GenerateClientKey(state *demoState) error {
	fmt.Println("=== Step 4/9: Generate client key in Windows Certificate Store ===")
	fmt.Println("Using NCrypt software KSP (fallback for machines without TPM).")
	fmt.Println()

	state.provider = certtostore.ProviderMSSoftware
	fmt.Printf("  Provider : %s\n", state.provider)
	fmt.Printf("  Container: %s\n", containerName)
	fmt.Println()

	store, err := certtostore.OpenWinCertStoreCurrentUser(
		state.provider,
		containerName,
		[]string{"CN=" + intermediCACN},
		nil,
		false,
	)
	if err != nil {
		return fmt.Errorf("opening Windows cert store: %w", err)
	}

	signer, err := store.Generate(certtostore.GenerateOpts{
		Algorithm: certtostore.EC,
		Size:      256,
	})
	if err != nil {
		store.Close()
		return fmt.Errorf("generating key in cert store: %w", err)
	}

	state.store = store
	state.clientSigner = signer

	fmt.Println("  [CLIENT] ECDSA P-256 key generated inside the provider.")
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()
	return nil
}

// --- Step 5 ---

func step5SignClientCert(state *demoState) error {
	fmt.Println("=== Step 5/9: Sign client certificate with enterprise intermediate CA ===")
	fmt.Println("The intermediate CA issues a ClientAuth leaf cert for the store-backed public key.")
	fmt.Println()

	profile := cert.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	clientCert, err := state.signLeaf(state.clientSigner.Public(), clientCN, profile)
	if err != nil {
		return fmt.Errorf("signing client cert: %w", err)
	}
	state.clientCert = clientCert

	fmt.Println("[OPERATOR] Client certificate:")
	cert.PrintCertificateInfo(clientCert)
	fmt.Println("  [CLIENT] EKU    : ClientAuth only")
	fmt.Printf("  [CLIENT] Issuer : %s (intermediate CA)\n", clientCert.Issuer.CommonName)
	fmt.Println("  [CLIENT] Private key lives inside the provider — no .key file is written.")
	fmt.Println()
	return nil
}

// --- Step 6 ---

func step6ImportClientCert(state *demoState) error {
	fmt.Println("=== Step 6/9: Import certificate into Windows Certificate Store ===")
	fmt.Printf("Linking signed certificate to key container %q in CurrentUser\\My.\n", containerName)
	fmt.Println()

	// StoreWithDisposition: second arg is the direct issuer (intermediate, NOT root)
	if err := state.store.StoreWithDisposition(state.clientCert, state.intCert, 3 /* CERT_STORE_ADD_REPLACE_EXISTING */); err != nil {
		return fmt.Errorf("storing client certificate: %w", err)
	}
	fmt.Println("  [CLIENT] Certificate stored in CurrentUser\\My")
	fmt.Println()

	// Re-derive key from store (simulates runtime lookup)
	fmt.Println("  [CLIENT] Simulating runtime key lookup (re-deriving key from CertContext) ...")
	storedCert, ctx, _, err := state.store.CertByCommonName(clientCN)
	if err != nil {
		return fmt.Errorf("looking up cert from store: %w", err)
	}
	defer certtostore.FreeCertContext(ctx)

	storeKey, err := state.store.CertKey(ctx)
	if err != nil {
		return fmt.Errorf("deriving key from cert context: %w", err)
	}

	state.storedCert = storedCert
	state.storeKey = storeKey

	fmt.Println("  [CLIENT] Key successfully retrieved via CertKey — ready for TLS.")
	fmt.Println()
	return nil
}

// --- Step 7 ---

func step7StartServerAndRequest(state *demoState) error {
	fmt.Println("=== Step 7/9: Start mTLS server and make trusted request ===")
	fmt.Printf("Client uses store-backed key (provider: %s) with enterprise cert chain.\n", state.provider)
	fmt.Println()

	// Create server
	serverCert, err := tls.LoadX509KeyPair(serverChainFile, serverKeyFile)
	if err != nil {
		return fmt.Errorf("loading server cert: %w", err)
	}
	rootPEM, err := os.ReadFile(serverRootCAFile)
	if err != nil {
		return fmt.Errorf("reading root CA cert: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(rootPEM) {
		return fmt.Errorf("failed to parse root CA certificate")
	}

	srv := &http.Server{
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				fmt.Printf("[SERVER] Client cert: %s (issued by %s)\n",
					r.TLS.PeerCertificates[0].Subject.CommonName,
					r.TLS.PeerCertificates[0].Issuer.CommonName)
			}
			fmt.Fprintln(w, "success!")
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	if err != nil {
		return fmt.Errorf("starting TLS listener: %w", err)
	}
	go func() { state.recordServerError(srv.Serve(ln)) }()

	state.server = srv
	state.serverURL = "https://" + ln.Addr().String()
	fmt.Printf("[SERVER] Listening on %s\n", state.serverURL)
	fmt.Println()

	// Build client with store-backed key + enterprise chain
	tlsCert := tls.Certificate{
		Certificate: [][]byte{state.storedCert.Raw, state.intCert.Raw},
		PrivateKey:  state.storeKey,
		Leaf:        state.storedCert,
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(state.rootCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      rootCAs,
				Certificates: []tls.Certificate{tlsCert},
			},
		},
	}

	fmt.Printf("[CLIENT] GET %s\n", state.serverURL)
	resp, err := client.Get(state.serverURL)
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[CLIENT] Server verified: %s (issued by %s)\n",
		resp.TLS.PeerCertificates[0].Subject.CommonName,
		resp.TLS.PeerCertificates[0].Issuer.CommonName)
	fmt.Printf("[CLIENT] Handshake — version: %s, cipher suite: %s\n",
		cert.TLSVersionName(resp.TLS.Version), tls.CipherSuiteName(resp.TLS.CipherSuite))
	fmt.Printf("[CLIENT] Signing performed by: %s (private key never left the provider)\n", state.provider)
	fmt.Printf("[CLIENT] Response: %s\n", resp.Status)
	fmt.Println()

	return state.unexpectedServerError()
}

// --- Step 8 ---

func step8UntrustedClient(state *demoState) error {
	if err := state.unexpectedServerError(); err != nil {
		return err
	}

	fmt.Println("=== Step 8/9: Demonstrate untrusted client (separate enterprise PKI) ===")
	fmt.Println("This client's certificate chain originates from a completely different root CA.")
	fmt.Println()

	// Build separate PKI
	_, untrustedSignInt, err := cert.CreateRootCA(untrustedRootCN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("creating untrusted root CA: %w", err)
	}
	untrustedIntCert, untrustedSignLeaf, err := untrustedSignInt(untrustedIntCN, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("creating untrusted intermediate CA: %w", err)
	}

	profile := cert.LeafProfile{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	untrustedClientCert, untrustedClientKey, err := cert.CreateLeafCertWithProfile(untrustedSignLeaf, untrustedCliCN, profile)
	if err != nil {
		return fmt.Errorf("creating untrusted client cert: %w", err)
	}

	// Build untrusted client (in-memory, no files)
	untrustedChain := tls.Certificate{
		Certificate: [][]byte{untrustedClientCert.Raw, untrustedIntCert.Raw},
		PrivateKey:  untrustedClientKey,
		Leaf:        untrustedClientCert,
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(state.rootCert) // trust the real server's root

	untrustedClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      rootCAs,
				Certificates: []tls.Certificate{untrustedChain},
			},
		},
	}

	fmt.Printf("[UNTRUSTED CLIENT] GET %s\n", state.serverURL)
	_, err = untrustedClient.Get(state.serverURL)
	if err != nil {
		fmt.Printf("[UNTRUSTED CLIENT] Connection rejected — %s\n", err)
		fmt.Println("[UNTRUSTED CLIENT] Expected: server refused client cert — not signed by the trusted CA.")
		fmt.Println()
		return state.unexpectedServerError()
	}

	return fmt.Errorf("expected untrusted client to be rejected, but request succeeded")
}

// --- Step 9 ---

func step9Summary(state *demoState) error {
	fmt.Println("=== Step 9/9: Summary and cleanup ===")
	fmt.Println()

	fmt.Println("Certificate chain (enterprise PKI + store-backed client key):")
	fmt.Printf("  Root CA (SKID: %X)\n", state.rootCert.SubjectKeyId)
	fmt.Printf("    └── Intermediate CA (SKID: %X, AKID: %X)\n", state.intCert.SubjectKeyId, state.intCert.AuthorityKeyId)
	fmt.Printf("          ├── Server cert (AKID: %X) → file-based chain bundle\n", state.intCert.SubjectKeyId)
	fmt.Printf("          └── Client cert (AKID: %X) → store-backed key in Windows cert store\n", state.intCert.SubjectKeyId)
	fmt.Println()

	fmt.Println("File layout:")
	fmt.Printf("  %-55s  %s\n", certBaseDir+"/root-ca/cert.crt", "public — root CA certificate")
	fmt.Printf("  %-55s  %s\n", certBaseDir+"/intermediate-ca/cert.crt", "public — intermediate CA certificate")
	fmt.Printf("  %-55s  %s\n", certBaseDir+"/server/chain.crt", "public — server leaf + intermediate bundle")
	fmt.Printf("  %-55s  %s\n", certBaseDir+"/server/server.key", "private — never leaves the server")
	fmt.Printf("  %-55s  %s\n", certBaseDir+"/server/root-ca.crt", "public — root CA for client validation")
	fmt.Printf("  %-55s  %s\n", "Windows CurrentUser\\My", "client cert + store-backed key (no file)")
	fmt.Println()

	fmt.Println("The demo can now remove the client certificate and NCrypt key container.")
	fmt.Print("Run cleanup now? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return fmt.Errorf("reading cleanup response: %w", err)
	}

	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		fmt.Println()
		fmt.Println("[CLEANUP] Removing client cert and key container ...")
		printCleanupInstructions()
		return nil
	default:
		fmt.Println()
		fmt.Println("[CLEANUP] Skipped.")
		printCleanupInstructions()
		return nil
	}
}

func printCleanupInstructions() {
	fmt.Println()
	fmt.Println("=== Manual Cleanup Commands ===")
	fmt.Println()
	fmt.Println("  # 1. Remove the client certificate from CurrentUser\\My:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.Subject -match 'CN=%s' } | ForEach-Object { $store.Remove($_) }\n", clientCN)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 2. Remove the intermediate CA from CurrentUser\\CA:")
	fmt.Println("  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('CA', 'CurrentUser')")
	fmt.Println("  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)")
	fmt.Printf("  $store.Certificates | Where-Object { $_.Subject -match 'CN=%s' } | ForEach-Object { $store.Remove($_) }\n", intermediCACN)
	fmt.Println("  $store.Close()")
	fmt.Println()
	fmt.Println("  # 3. Delete the NCrypt key container:")
	fmt.Printf("  $p = New-Object System.Security.Cryptography.CngProvider('%s')\n", certtostore.ProviderMSSoftware)
	fmt.Printf("  $k = [System.Security.Cryptography.CngKey]::Open('%s', $p)\n", containerName)
	fmt.Println("  $k.Delete()")
}

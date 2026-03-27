//go:build windows

package mtlstpm

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/google/certtostore"
)

func RunDemo() error {
	opCfg, err := LoadOperatorConfig(defaultOperatorConfigPath)
	if err != nil {
		return fmt.Errorf("loading operator config: %w", err)
	}
	serverCfg, err := LoadServerConfig(defaultServerConfigPath)
	if err != nil {
		return fmt.Errorf("loading server config: %w", err)
	}
	clientCfg, err := LoadClientConfig(defaultClientConfigPath)
	if err != nil {
		return fmt.Errorf("loading client config: %w", err)
	}
	untrustedCfg, err := LoadUntrustedClientConfig(defaultUntrustedClientConfigPath)
	if err != nil {
		return fmt.Errorf("loading untrusted client config: %w", err)
	}
	return runDemo(opCfg, serverCfg, clientCfg, untrustedCfg)
}

func runDemo(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig, untrustedCfg UntrustedClientConfig) error {
	state := &demoState{}

	if err := step1GenerateCAAndServer(state, opCfg, serverCfg); err != nil {
		return err
	}
	if err := step2CheckTPM(state, clientCfg); err != nil {
		return err
	}
	if err := step3GenerateClientKey(state, opCfg, clientCfg); err != nil {
		return err
	}
	defer state.store.Close()

	if err := step4ImportClientCertificate(state, clientCfg); err != nil {
		return err
	}
	if err := step5StartServerAndMakeTrustedRequest(state, serverCfg); err != nil {
		return err
	}
	defer state.server.Close()

	if err := step6DemonstrateUntrustedClient(state, opCfg, untrustedCfg); err != nil {
		return err
	}

	printCleanupInstructions(state.provider, clientCfg.Container, clientCfg.CN)
	return nil
}

type demoState struct {
	operator         *Operator
	provider         string
	store            *certtostore.WinCertStore
	clientCert       *x509.Certificate
	storedClientCert *x509.Certificate
	storeKey         crypto.Signer
	server           *http.Server
	serverURL        string
}

// certStoreAddReplaceExisting is the Windows CryptoAPI CERT_STORE_ADD_REPLACE_EXISTING
// disposition constant. It replaces any existing cert with the same subject/issuer
// rather than silently reusing the old one — ensures re-runs pick up the new cert.
const certStoreAddReplaceExisting = 3

func printCleanupInstructions(provider, container, cn string) {
	fmt.Println("=== Manual Cleanup ===")
	fmt.Println("The client certificate and key were NOT removed automatically.")
	fmt.Println("You can inspect them in certmgr.msc (CurrentUser → Personal → Certificates).")
	fmt.Println()
	fmt.Println("To remove them, run the following PowerShell commands:")
	fmt.Println()
	fmt.Println("  # 1. Remove the client certificate from CurrentUser\\My:")
	fmt.Printf("  Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Subject -like \"*%s*\" } | Remove-Item\n", cn)
	fmt.Println()
	fmt.Println("  # 2. Delete the NCrypt key container from the provider:")
	fmt.Printf("  $p = New-Object System.Security.Cryptography.CngProvider('%s')\n", provider)
	fmt.Printf("  $k = [System.Security.Cryptography.CngKey]::Open('%s', $p)\n", container)
	fmt.Println("  $k.Delete()")
}

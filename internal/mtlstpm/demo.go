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
	defer func() {
		if state.store != nil {
			state.store.Close()
		}
	}()

	if err := step4ImportClientCertificate(state, clientCfg); err != nil {
		return err
	}
	if err := step5StartServerAndMakeTrustedRequest(state, serverCfg); err != nil {
		return err
	}
	defer func() {
		if state.server != nil {
			state.server.Close()
		}
	}()

	if err := step6DemonstrateUntrustedClient(state, opCfg, untrustedCfg); err != nil {
		return err
	}

	if err := closeDemoResources(state); err != nil {
		return err
	}

	return step7Cleanup(state.provider, clientCfg.Container, clientCfg.CN, opCfg.CN)
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

func closeDemoResources(state *demoState) error {
	if state.server != nil {
		if err := state.server.Close(); err != nil {
			return fmt.Errorf("closing server: %w", err)
		}
		state.server = nil
	}
	if state.store != nil {
		if err := state.store.Close(); err != nil {
			return fmt.Errorf("closing Windows cert store: %w", err)
		}
		state.store = nil
	}
	return nil
}

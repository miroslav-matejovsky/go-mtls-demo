//go:build windows

package mtlstpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/operator"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/tpm"
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
	state := newDemoState()

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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := state.server.Shutdown(ctx); err != nil {
				state.server.Close()
			}
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
	store            *tpm.CurrentUserStore
	clientCert       *x509.Certificate
	storedClientCert *x509.Certificate
	storeKey         crypto.Signer
	server           *http.Server
	serverURL        string
	serverErr        chan error
}

func newDemoState() *demoState {
	return &demoState{
		serverErr: make(chan error, 1),
	}
}

func (state *demoState) recordServerError(err error) {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return
	}

	select {
	case state.serverErr <- err:
	default:
	}
}

func (state *demoState) unexpectedServerError() error {
	select {
	case err := <-state.serverErr:
		return fmt.Errorf("server stopped unexpectedly: %w", err)
	default:
		return nil
	}
}

func closeDemoResources(state *demoState) error {
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
			return fmt.Errorf("closing Windows cert store: %w", err)
		}
		state.store = nil
	}
	return nil
}

type Operator = operator.Operator

func NewOperator(cfg OperatorConfig) (*Operator, error) {
	validity, err := cfg.ParseValidity()
	if err != nil {
		return nil, err
	}
	return operator.NewSimple(operator.CAConfig{
		CN:       cfg.CN,
		CertFile: cfg.CertFile,
		Validity: validity,
	})
}

func CreateServer(certFile, keyFile, caCertFile string) (*http.Server, error) {
	return server.NewFileMTLS(server.FileMTLSConfig{
		CertificateFile: certFile,
		PrivateKeyFile:  keyFile,
		ClientCAFile:    caCertFile,
	})
}

func CreateClient(caCert *x509.Certificate, key crypto.Signer, clientCert *x509.Certificate) (*http.Client, error) {
	return client.NewMTLSWithSigner(client.SignerMTLSConfig{
		CACert:           caCert,
		PrivateKey:       key,
		CertificateChain: []*x509.Certificate{clientCert},
	})
}

package mtlsfiles

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/authority"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
	"github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
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

	if err := step1GenerateCertificates(state, opCfg, serverCfg, clientCfg); err != nil {
		return err
	}
	if err := step2StartServer(state, serverCfg); err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := state.server.Shutdown(ctx); err != nil {
			state.server.Close()
		}
	}()

	if err := step3MakeTrustedRequest(state, clientCfg); err != nil {
		return err
	}
	if err := step4GenerateUntrustedClient(state, untrustedCfg); err != nil {
		return err
	}
	if err := step5MakeUntrustedRequest(state, untrustedCfg); err != nil {
		return err
	}

	step6InspectFiles(opCfg, serverCfg, clientCfg, untrustedCfg)
	return nil
}

type demoState struct {
	operator  *Operator
	validity  time.Duration
	server    *http.Server
	serverURL string
	serverErr chan error
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

type Operator = authority.Simple

func NewOperator(cfg OperatorConfig) (*Operator, error) {
	validity, err := cfg.ParseValidity()
	if err != nil {
		return nil, err
	}
	return authority.NewSimple(authority.CAConfig{
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

func CreateClient(caCertFile, clientCertFile, clientKeyFile string) (*http.Client, error) {
	return client.NewMTLSFromFiles(client.FileMTLSConfig{
		CACertFile:      caCertFile,
		CertificateFile: clientCertFile,
		PrivateKeyFile:  clientKeyFile,
	})
}

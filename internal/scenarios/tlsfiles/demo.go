package tlsfiles

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/miroslav-matejovsky/go-mtls-demo/internal/authority"
	sharedclient "github.com/miroslav-matejovsky/go-mtls-demo/internal/client"
	sharedserver "github.com/miroslav-matejovsky/go-mtls-demo/internal/server"
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
	return runDemo(opCfg, serverCfg, clientCfg)
}

func runDemo(opCfg OperatorConfig, serverCfg ServerConfig, clientCfg ClientConfig) error {
	state := newDemoState()

	if err := step1GenerateCA(state, opCfg, clientCfg); err != nil {
		return err
	}
	if err := step2GenerateServerCertificate(state, serverCfg); err != nil {
		return err
	}
	if err := step3StartServer(state, serverCfg); err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := state.server.Shutdown(ctx); err != nil {
			state.server.Close()
		}
	}()

	return step4MakeRequest(state, clientCfg)
}

type demoState struct {
	operator  *Operator
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

func CreateServer(certFile, keyFile string) (*http.Server, error) {
	return sharedserver.NewFileTLS(sharedserver.FileTLSConfig{
		CertificateFile: certFile,
		PrivateKeyFile:  keyFile,
	})
}

func CreateClient(caCertFile string) (*http.Client, error) {
	return sharedclient.NewTLSFromFiles(sharedclient.FileTLSConfig{
		CACertFile: caCertFile,
	})
}

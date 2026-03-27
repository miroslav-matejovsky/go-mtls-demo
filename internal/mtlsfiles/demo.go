package mtlsfiles

import (
	"errors"
	"fmt"
	"net/http"
	"time"
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
	defer state.server.Close()

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

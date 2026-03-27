package mtlsfiles

import (
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
	state := &demoState{}

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
}

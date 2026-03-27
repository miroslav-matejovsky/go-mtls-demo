package tlsfiles

import (
	"fmt"
	"net/http"
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
	state := &demoState{}

	if err := step1GenerateCA(state, opCfg, clientCfg); err != nil {
		return err
	}
	if err := step2GenerateServerCertificate(state, serverCfg); err != nil {
		return err
	}
	if err := step3StartServer(state, serverCfg); err != nil {
		return err
	}
	defer state.server.Close()

	return step4MakeRequest(state, clientCfg)
}

type demoState struct {
	operator  *Operator
	server    *http.Server
	serverURL string
}

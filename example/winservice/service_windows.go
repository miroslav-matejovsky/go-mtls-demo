//go:build windows

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

// mtlsService implements the Windows Service handler interface.
// In production, the server configuration (cert paths, listen address) would
// come from environment variables, registry keys, or a config file.
type mtlsService struct {
	chainFile    string
	keyFile      string
	rootCertFile string
	listenAddr   string
}

// Execute implements svc.Handler. It starts the mTLS server and waits for
// stop/shutdown signals from the Windows Service Control Manager.
func (s *mtlsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	srv, err := createServiceServer(s.chainFile, s.keyFile, s.rootCertFile, s.listenAddr)
	if err != nil {
		log.Printf("failed to create server: %v", err)
		return false, 1
	}

	ln, err := tls.Listen("tcp", s.listenAddr, srv.TLSConfig)
	if err != nil {
		log.Printf("failed to start listener: %v", err)
		return false, 1
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Serve(ln)
	}()

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case err := <-serverErr:
			if err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := srv.Shutdown(ctx); err != nil {
					log.Printf("shutdown error: %v", err)
				}
				return false, 0
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		}
	}
}

func createServiceServer(chainFile, keyFile, rootCertFile, addr string) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}
	rootPEM, err := os.ReadFile(rootCertFile)
	if err != nil {
		return nil, fmt.Errorf("reading root CA certificate: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to parse root CA certificate")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			log.Printf("request from %s", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		fmt.Fprintln(w, "ok")
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}, nil
}

// runService starts the mTLS server as a Windows Service or in console debug mode.
//
// Install with: sc.exe create example-winservice binPath= "C:\path\to\winservice.exe --service"
// Start with:   sc.exe start example-winservice
// Debug with:   winservice.exe --service-debug
func runService(name string, isDebug bool) error {
	svcInstance := &mtlsService{
		chainFile:    envOrDefault("SERVER_CHAIN_FILE", serverChainFile),
		keyFile:      envOrDefault("SERVER_KEY_FILE", serverKeyFile),
		rootCertFile: envOrDefault("ROOT_CA_FILE", serverRootCAFile),
		listenAddr:   envOrDefault("LISTEN_ADDR", ":8443"),
	}
	if isDebug {
		return debug.Run(name, svcInstance)
	}
	return svc.Run(name, svcInstance)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	mtlsPort := envOrDefault("MTLS_PORT", "8443")
	healthPort := envOrDefault("HEALTH_PORT", "8080")
	chainFile := os.Getenv("SERVER_CHAIN_FILE")
	keyFile := os.Getenv("SERVER_KEY_FILE")
	rootCAFile := os.Getenv("ROOT_CA_FILE")

	if chainFile == "" || keyFile == "" || rootCAFile == "" {
		log.Fatal("SERVER_CHAIN_FILE, SERVER_KEY_FILE, and ROOT_CA_FILE must be set")
	}

	serverCert, err := tls.LoadX509KeyPair(chainFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load server certificate chain: %v", err)
	}

	rootCAPEM, err := os.ReadFile(rootCAFile)
	if err != nil {
		log.Fatalf("failed to read root CA file: %v", err)
	}

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(rootCAPEM) {
		log.Fatal("failed to parse root CA certificate")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		Certificates: []tls.Certificate{serverCert},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			log.Printf("request from client: %s", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
		fmt.Fprintln(w, "ok")
	})

	mtlsServer := &http.Server{
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "healthy")
	})
	healthMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})

	healthServer := &http.Server{
		Addr:         ":" + healthPort,
		Handler:      healthMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("health server error: %v", err)
		}
	}()

	ln, err := tls.Listen("tcp", ":"+mtlsPort, tlsCfg)
	if err != nil {
		log.Fatalf("failed to listen on :%s: %v", mtlsPort, err)
	}

	go func() {
		if err := mtlsServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("mTLS server error: %v", err)
		}
	}()

	log.Printf("mTLS server listening on :%s, health on :%s", mtlsPort, healthPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	log.Printf("shutdown signal received")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := mtlsServer.Shutdown(ctx); err != nil {
		log.Printf("mTLS server shutdown error: %v", err)
	}
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("health server shutdown error: %v", err)
	}

	// Close the listener explicitly in case Shutdown did not reach it.
	_ = ln.Close()

	log.Printf("shutdown complete")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

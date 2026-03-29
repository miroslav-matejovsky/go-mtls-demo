//go:build windows

// Package tpm provides Windows CurrentUser certificate store helpers built on
// top of certtostore. It centralizes provider selection, key generation,
// certificate import, and runtime signer recovery for TPM-backed or
// software-backed client identities.
package tpm

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// PlatformProvider returns the Microsoft Platform Crypto Provider name used for
// TPM-backed keys.
func PlatformProvider() string {
	return certtostore.ProviderMSPlatform
}

// SoftwareProvider returns the Microsoft Software Key Storage Provider name
// used when TPM-backed storage is unavailable or not desired.
func SoftwareProvider() string {
	return certtostore.ProviderMSSoftware
}

// SelectProvider returns override when it is non-empty. Otherwise it selects
// the TPM-backed provider when tpmAvailable is true and the software provider
// when it is false.
func SelectProvider(override string, tpmAvailable bool) string {
	if override != "" {
		return override
	}
	if tpmAvailable {
		return PlatformProvider()
	}
	return SoftwareProvider()
}

// OpenCurrentUserStoreOptions configures how OpenCurrentUserStore opens the
// Windows CurrentUser\My certificate store.
type OpenCurrentUserStoreOptions struct {
	Provider          string
	Container         string
	IssuerCommonNames []string
}

// CurrentUserStore wraps a certtostore WinCertStore handle for the
// CurrentUser\My store.
type CurrentUserStore struct {
	handle *certtostore.WinCertStore
}

// OpenCurrentUserStore opens the Windows CurrentUser\My certificate store with
// the requested provider, key container, and issuer CN filters.
func OpenCurrentUserStore(options OpenCurrentUserStoreOptions) (*CurrentUserStore, error) {
	if options.Provider == "" {
		return nil, fmt.Errorf("opening Windows cert store: provider is required")
	}
	if options.Container == "" {
		return nil, fmt.Errorf("opening Windows cert store: container is required")
	}

	handle, err := certtostore.OpenWinCertStoreCurrentUser(
		options.Provider,
		options.Container,
		issuerSubjects(options.IssuerCommonNames),
		nil,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("opening Windows cert store: %w", err)
	}

	return &CurrentUserStore{handle: handle}, nil
}

// GenerateECDSAP256 creates an ECDSA P-256 key pair inside the configured
// provider and returns a signer backed by that provider.
func (s *CurrentUserStore) GenerateECDSAP256() (crypto.Signer, error) {
	if s == nil || s.handle == nil {
		return nil, fmt.Errorf("generating key in Windows cert store: store is not open")
	}

	signer, err := s.handle.Generate(certtostore.GenerateOpts{
		Algorithm: certtostore.EC,
		Size:      256,
	})
	if err != nil {
		return nil, fmt.Errorf("generating key in Windows cert store: %w", err)
	}
	return signer, nil
}

// StoreCertificate links cert to the existing provider-backed key container and
// stores it in CurrentUser\My using replace-existing semantics.
func (s *CurrentUserStore) StoreCertificate(cert, issuer *x509.Certificate) error {
	if s == nil || s.handle == nil {
		return fmt.Errorf("storing certificate in Windows cert store: store is not open")
	}
	if cert == nil {
		return fmt.Errorf("storing certificate in Windows cert store: certificate is required")
	}
	if issuer == nil {
		return fmt.Errorf("storing certificate in Windows cert store: issuer certificate is required")
	}

	if err := s.handle.StoreWithDisposition(cert, issuer, windows.CERT_STORE_ADD_REPLACE_EXISTING); err != nil {
		return fmt.Errorf("storing certificate in Windows cert store: %w", err)
	}
	return nil
}

// LoadCertificateByCommonName looks up a certificate by subject common name in
// CurrentUser\My and re-derives the provider-backed signer from the certificate
// context.
func (s *CurrentUserStore) LoadCertificateByCommonName(commonName string) (*x509.Certificate, crypto.Signer, error) {
	if s == nil || s.handle == nil {
		return nil, nil, fmt.Errorf("looking up certificate from Windows cert store: store is not open")
	}
	if commonName == "" {
		return nil, nil, fmt.Errorf("looking up certificate from Windows cert store: common name is required")
	}

	storedCert, ctx, _, err := s.handle.CertByCommonName(commonName)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up certificate from Windows cert store: %w", err)
	}
	defer certtostore.FreeCertContext(ctx)

	storeKey, err := s.handle.CertKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving key from certificate context: %w", err)
	}

	return storedCert, storeKey, nil
}

// Close releases the underlying certtostore handle.
func (s *CurrentUserStore) Close() error {
	if s == nil || s.handle == nil {
		return nil
	}
	return s.handle.Close()
}

func issuerSubjects(commonNames []string) []string {
	subjects := make([]string, 0, len(commonNames))
	for _, commonName := range commonNames {
		commonName = strings.TrimSpace(commonName)
		if commonName == "" {
			continue
		}
		subjects = append(subjects, "CN="+commonName)
	}
	if len(subjects) == 0 {
		return nil
	}
	return subjects
}

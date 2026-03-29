//go:build windows

package tpm

import (
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tpmVersion12 = 1
	tpmVersion20 = 2
)

var (
	ncryptDLL                 = windows.NewLazySystemDLL("ncrypt.dll")
	ncryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	ncryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
	tbsDLL                    = windows.NewLazySystemDLL("tbs.dll")
	tbsiGetDeviceInfo         = tbsDLL.NewProc("Tbsi_GetDeviceInfo")
)

type tpmDeviceInfo struct {
	StructVersion    uint32
	TPMVersion       uint32
	TPMInterfaceType uint32
	TPMImpRevision   uint32
}

type tpmProbe struct {
	tbsStatus          uintptr
	info               tpmDeviceInfo
	providerProbed     bool
	providerStatus     uintptr
	providerStatusNote string
}

// CheckTPM reports whether a TPM-backed client key path is available and
// returns a human-readable summary of the native Windows probe results.
func CheckTPM() (available bool, details string, err error) {
	probe, err := probeTPM()
	if err != nil {
		return false, "", fmt.Errorf("checking TPM availability: %w", err)
	}
	return probe.available(), probe.details(), nil
}

// ShowCertsInStore returns formatted details for matching certificates in the
// Windows CurrentUser\My store. It returns an empty string when no matches are
// found.
func ShowCertsInStore(commonName string) (string, error) {
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return "", fmt.Errorf("showing certificates in Windows cert store: common name is required")
	}

	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return "", fmt.Errorf("showing certificates in Windows cert store: %w", err)
	}

	store, err := windows.CertOpenStore(
		uintptr(windows.CERT_STORE_PROV_SYSTEM_W),
		0,
		0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_OPEN_EXISTING_FLAG|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return "", fmt.Errorf("showing certificates in Windows cert store: opening CurrentUser\\My: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var blocks []string
	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		ctx = next
		if ctx == nil {
			if isWindowsErr(err, windows.Errno(uintptr(windows.CRYPT_E_NOT_FOUND))) {
				break
			}
			return "", fmt.Errorf("showing certificates in Windows cert store: enumerating CurrentUser\\My: %w", err)
		}

		cert, err := parseCertificateContext(ctx)
		if err != nil {
			_ = windows.CertFreeCertificateContext(ctx)
			return "", fmt.Errorf("showing certificates in Windows cert store: parsing certificate: %w", err)
		}
		if !subjectMatches(cert, commonName) {
			continue
		}

		thumbprint := sha1.Sum(cert.Raw)
		blocks = append(blocks, strings.Join([]string{
			fmt.Sprintf("Subject    : %s", cert.Subject.String()),
			fmt.Sprintf("Issuer     : %s", cert.Issuer.String()),
			fmt.Sprintf("Thumbprint : %X", thumbprint),
			fmt.Sprintf("NotAfter   : %s", cert.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC")),
		}, "\n"))
	}

	if len(blocks) == 0 {
		return "", nil
	}
	return strings.Join(blocks, "\n\n"), nil
}

func probeTPM() (tpmProbe, error) {
	info, tbsStatus, err := queryTPMDeviceInfo()
	if err != nil {
		return tpmProbe{}, err
	}

	probe := tpmProbe{
		tbsStatus: tbsStatus,
		info:      info,
	}
	if probe.tbsStatus != 0 {
		probe.providerStatusNote = "skipped (TPM unavailable)"
		return probe, nil
	}
	if probe.info.TPMVersion != tpmVersion20 {
		probe.providerStatusNote = fmt.Sprintf("skipped (%s)", tpmVersionName(probe.info.TPMVersion))
		return probe, nil
	}

	status, err := probeStorageProvider(PlatformProvider())
	if err != nil {
		return tpmProbe{}, err
	}
	probe.providerProbed = true
	probe.providerStatus = status
	return probe, nil
}

func queryTPMDeviceInfo() (tpmDeviceInfo, uintptr, error) {
	if err := tbsiGetDeviceInfo.Find(); err != nil {
		return tpmDeviceInfo{}, 0, fmt.Errorf("loading Tbsi_GetDeviceInfo: %w", err)
	}

	info := tpmDeviceInfo{
		StructVersion: tpmVersion20,
	}
	result, _, _ := tbsiGetDeviceInfo.Call(
		uintptr(uint32(unsafe.Sizeof(info))),
		uintptr(unsafe.Pointer(&info)),
	)
	return info, result, nil
}

func probeStorageProvider(name string) (uintptr, error) {
	if err := ncryptOpenStorageProvider.Find(); err != nil {
		return 0, fmt.Errorf("loading NCryptOpenStorageProvider: %w", err)
	}
	if err := ncryptFreeObject.Find(); err != nil {
		return 0, fmt.Errorf("loading NCryptFreeObject: %w", err)
	}

	providerName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("encoding provider name: %w", err)
	}

	var handle windows.Handle
	status, _, _ := ncryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(providerName)),
		0,
	)
	if status != 0 {
		return status, nil
	}

	_, _, _ = ncryptFreeObject.Call(uintptr(handle))
	return 0, nil
}

func parseCertificateContext(ctx *windows.CertContext) (*x509.Certificate, error) {
	raw := unsafe.Slice(ctx.EncodedCert, ctx.Length)
	return x509.ParseCertificate(raw)
}

func subjectMatches(cert *x509.Certificate, commonName string) bool {
	subject := cert.Subject.String()
	return containsFold(cert.Subject.CommonName, commonName) || containsFold(subject, commonName)
}

func containsFold(value, needle string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(needle))
}

func isWindowsErr(err error, code windows.Errno) bool {
	return err != nil && errors.Is(err, code)
}

func (p tpmProbe) available() bool {
	return p.tbsStatus == 0 && p.info.TPMVersion == tpmVersion20 && p.providerProbed && p.providerStatus == 0
}

func (p tpmProbe) details() string {
	lines := []string{
		fmt.Sprintf("TpmPresent       : %t", p.tbsStatus == 0),
		fmt.Sprintf("TpmReady         : %t", p.available()),
		fmt.Sprintf("TpmEnabled       : %t", p.available()),
	}

	if p.tbsStatus == 0 {
		lines = append(lines,
			fmt.Sprintf("TpmVersion       : %s", tpmVersionName(p.info.TPMVersion)),
			fmt.Sprintf("TpmInterfaceType : 0x%08X", p.info.TPMInterfaceType),
			fmt.Sprintf("TpmImpRevision   : 0x%08X", p.info.TPMImpRevision),
		)
	} else {
		lines = append(lines, "TpmVersion       : unavailable")
	}

	lines = append(lines,
		fmt.Sprintf("TpmProbeStatus   : %s", formatStatus(p.tbsStatus)),
		fmt.Sprintf("PlatformProvider : %s", PlatformProvider()),
	)
	if p.providerProbed {
		lines = append(lines,
			fmt.Sprintf("PlatformUsable   : %t", p.providerStatus == 0),
			fmt.Sprintf("ProviderStatus   : %s", formatStatus(p.providerStatus)),
		)
	} else {
		lines = append(lines,
			"PlatformUsable   : false",
			fmt.Sprintf("ProviderStatus   : %s", p.providerStatusNote),
		)
	}

	return strings.Join(lines, "\n")
}

func tpmVersionName(version uint32) string {
	switch version {
	case tpmVersion12:
		return "TPM 1.2"
	case tpmVersion20:
		return "TPM 2.0"
	default:
		return fmt.Sprintf("unknown (0x%08X)", version)
	}
}

func formatStatus(status uintptr) string {
	if status == 0 {
		return "success (0x00000000)"
	}
	return fmt.Sprintf("%s (0x%08X)", windows.Errno(status).Error(), uint32(status))
}

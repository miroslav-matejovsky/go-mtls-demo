// Package pwsh provides helpers for running PowerShell commands from Go.
// It is used by the mtlstpm scenario to query TPM status and inspect the
// Windows Certificate Store — tasks that the certtostore library does not expose.
package pwsh

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RunCommand executes a PowerShell one-liner and returns trimmed stdout.
// stderr is included in the error message when the command fails.
func RunCommand(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("powershell: %w\n%s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// RunScriptFile executes a PowerShell script file with inherited stdio so the
// caller can interact with it and see its console output directly.
func RunScriptFile(path string, args ...string) error {
	cmdArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path}, args...)
	cmd := exec.Command("powershell", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("powershell: %w", err)
	}
	return nil
}

// CheckTPM returns whether a TPM 2.0 chip is present and enabled, plus a
// human-readable summary of TPM properties from Get-Tpm.
func CheckTPM() (available bool, details string, err error) {
	raw, err := RunCommand("$t = Get-Tpm; ($t.TpmPresent -and $t.TpmEnabled).ToString()")
	if err != nil {
		return false, "", fmt.Errorf("CheckTPM: %w", err)
	}
	details, err = RunCommand(
		"Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, ManufacturerId, ManufacturerVersion | Format-List | Out-String",
	)
	if err != nil {
		return false, "", fmt.Errorf("CheckTPM details: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true"), strings.TrimSpace(details), nil
}

func singleQuotePowerShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// ShowCertsInStore returns a formatted list of certificates from CurrentUser\My
// whose Subject contains cn. It queries the .NET X509Store directly so it works
// even when the Cert: PSDrive is unavailable. Returns an empty string if no
// matching certs exist.
func ShowCertsInStore(cn string) (string, error) {
	script := fmt.Sprintf(
		`$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser'); `+
			`$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly); `+
			`try { `+
			`$store.Certificates | Where-Object { $_.Subject -like ('*' + %s + '*') } | `+
			`Select-Object Subject, Issuer, Thumbprint, NotAfter | Format-List | Out-String `+
			`} finally { `+
			`$store.Close() `+
			`}`,
		singleQuotePowerShell(cn),
	)
	out, err := RunCommand(script)
	if err != nil {
		return "", fmt.Errorf("ShowCertsInStore: %w", err)
	}
	return out, nil
}

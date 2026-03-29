// Package pwsh provides helpers for running PowerShell commands and scripts from
// Go.
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

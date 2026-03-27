# check.ps1 — run all standard Go checks and build the binary.
# Usage: pwsh scripts/check.ps1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Step([string]$label, [scriptblock]$cmd) {
    Write-Host ""
    Write-Host "── $label " -ForegroundColor Cyan -NoNewline
    Write-Host ("─" * (60 - $label.Length)) -ForegroundColor DarkGray
    & $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "OK" -ForegroundColor Green
}

Step "go vet"      { go vet ./... }
Step "go mod tidy" {
    go mod tidy
    # Fail if tidy changed anything — means go.mod/go.sum were out of sync.
    git diff --exit-code go.mod go.sum
}
Step "go build" {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $binDir = Join-Path $repoRoot "bin"
    $bin = Join-Path $binDir "go-mtls-demo.exe"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    go build -o $bin ./cmd/
}
Step "go test"  { go test ./... }

Write-Host ""
Write-Host "All checks passed." -ForegroundColor Green

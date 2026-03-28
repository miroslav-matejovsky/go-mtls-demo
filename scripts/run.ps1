param(
    [Parameter(Position = 0)]
    [ValidateSet('tlsmem', 'mtlsmem', 'tlsfiles', 'mtlsfiles', 'mtlsenterprise', 'mtlsenterprisetpm', 'mtlstpm')]
    [string]$Mode
)

if (-not $Mode) {
    Write-Host ""
    Write-Host "Usage: pwsh scripts/run.ps1 <mode>" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available modes:" -ForegroundColor Yellow
    Write-Host "  tlsmem    One-way TLS  — certificates generated and held in memory"
    Write-Host "  mtlsmem   Mutual TLS   — certificates generated and held in memory"
    Write-Host "  tlsfiles  One-way TLS  — certificates written to certs/tlsfiles/ and loaded from disk"
    Write-Host "  mtlsfiles Mutual TLS   — certificates written to certs/mtlsfiles/ and loaded from disk"
    Write-Host "  mtlsenterprise"
    Write-Host "            Mutual TLS   — intermediate CA, role-specific EKU, DNS SANs, chain bundles"
    Write-Host "  mtlsenterprisetpm"
    Write-Host "            Mutual TLS   — enterprise PKI + client key in Windows cert store + TPM (Windows only)"
    Write-Host "  mtlstpm   Mutual TLS   — server: files on disk; client: Windows cert store + TPM key (Windows only)"
    Write-Host ""
    exit 0
}

go run ./cmd/ $Mode

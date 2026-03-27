# mtlstpm-cleanup.ps1 — remove the TPM/NCrypt demo client certificate and key container.
# Usage:
#   pwsh scripts/mtlstpm-cleanup.ps1
#   pwsh scripts/mtlstpm-cleanup.ps1 -Provider "Microsoft Platform Crypto Provider"

param(
    [string]$CN = 'go mTLS TPM Demo Client',
    [string]$CACN = 'go mTLS TPM Demo CA',
    [string]$Container = 'go-mtls-demo-client',
    [string]$Provider
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Remove-CertificatesFromStore([string]$StoreName, [string]$CommonName) {
    Write-Step "Removing certificates from CurrentUser\$StoreName with exact CN '$CommonName'"

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($StoreName, 'CurrentUser')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    try {
        $certMatches = @(
            $store.Certificates | Where-Object {
                $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq $CommonName
            }
        )
        if ($certMatches.Count -eq 0) {
            Write-Host "No matching certificates found." -ForegroundColor Yellow
            return
        }

        foreach ($cert in $certMatches) {
            Write-Host ("Removing certificate: {0} | Thumbprint: {1}" -f $cert.Subject, $cert.Thumbprint)
            $store.Remove($cert)
        }

        Write-Host ("Removed {0} certificate(s)." -f $certMatches.Count) -ForegroundColor Green
    } finally {
        $store.Close()
    }
}

function Remove-KeyContainer([string]$ProviderName, [string]$KeyContainer) {
    Write-Step "Deleting key container '$KeyContainer' from provider '$ProviderName'"

    try {
        $providerObject = New-Object System.Security.Cryptography.CngProvider($ProviderName)
        $keyObject = [System.Security.Cryptography.CngKey]::Open($KeyContainer, $providerObject)
    } catch {
        Write-Host ("Key container not found in provider '{0}': {1}" -f $ProviderName, $_.Exception.Message) -ForegroundColor Yellow
        return $false
    }

    try {
        $keyObject.Delete()
    } finally {
        $keyObject.Dispose()
    }

    Write-Host "Key container deleted." -ForegroundColor Green
    return $true
}

Write-Host "mTLS TPM cleanup starting..." -ForegroundColor Green
Write-Host ("Certificate CN : {0}" -f $CN)
Write-Host ("CA CN          : {0}" -f $CACN)
Write-Host ("Key container  : {0}" -f $Container)
if ($Provider) {
    Write-Host ("Provider       : {0}" -f $Provider)
} else {
    Write-Host "Provider       : auto-detect (will try both TPM and software providers)"
}

Remove-CertificatesFromStore -StoreName 'My' -CommonName $CN
Remove-CertificatesFromStore -StoreName 'CA' -CommonName $CACN

$providersToTry = if ($Provider) {
    @($Provider)
} else {
    @(
        'Microsoft Platform Crypto Provider',
        'Microsoft Software Key Storage Provider'
    )
}

$removedKey = $false
foreach ($providerName in $providersToTry) {
    if (Remove-KeyContainer -ProviderName $providerName -KeyContainer $Container) {
        $removedKey = $true
        break
    }
}

if (-not $removedKey) {
    Write-Host ""
    Write-Host "No matching key container was deleted." -ForegroundColor Yellow
    Write-Host "If the demo used a different provider, rerun this script with -Provider <name>." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "mTLS TPM cleanup finished." -ForegroundColor Green

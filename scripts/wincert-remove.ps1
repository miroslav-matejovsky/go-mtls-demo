#
# .SYNOPSIS
# Removes Windows certificates that match a store and subject filter.
#
# .DESCRIPTION
# Searches the requested Windows certificate store and removes certificates whose
# Subject matches the provided wildcard pattern.
#
# The script defaults to the current user certificate scope. Use -Machine to target
# the local machine scope instead.
#
# .PARAMETER CertStore
# The certificate store name, such as My, Root, or a full Cert:\ path.
#
# .PARAMETER Subject
# The subject filter. Wildcards are supported, for example CN=test* or *.
#
# .PARAMETER Machine
# Switches the scope from CurrentUser to LocalMachine.
#
# .EXAMPLE
# .\scripts\wincert-remove.ps1 My "CN=test*"
# Removes certificates from the current user's My store whose subject starts with CN=test.
#
# .EXAMPLE
# .\scripts\wincert-remove.ps1 My "*" -Machine -WhatIf
# Shows what would be removed from the local machine's My store.
#
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$CertStore,

  [Parameter(Mandatory = $true, Position = 1)]
  [string]$Subject,

  [switch]$Machine
)

$Scope = if ($Machine) { 'LocalMachine' } else { 'CurrentUser' }

function Resolve-CertStorePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Store,

    [Parameter(Mandatory = $true)]
    [string]$StoreScope
  )

  if ($Store -match '^[Cc]ert:\\') {
    return $Store
  }

  return "Cert:\$StoreScope\$Store"
}

function Format-CertificateSummary {
  param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  [pscustomobject]@{
    Subject       = $Certificate.Subject
    Thumbprint    = $Certificate.Thumbprint
    NotBefore     = $Certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
    NotAfter      = $Certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
    Store         = $Certificate.PSParentPath
    HasPrivateKey = if ($Certificate.HasPrivateKey) { 'Yes' } else { 'No' }
  }
}

$Path = Resolve-CertStorePath -Store $CertStore -StoreScope $Scope

if (-not (Test-Path $Path)) {
  throw "Certificate store path not found: $Path"
}

Write-Host "Searching certificates in $Path" -ForegroundColor Cyan
Write-Host "Subject filter: $Subject" -ForegroundColor Cyan
Write-Host ""

try {
  $Certificates = Get-ChildItem -Path $Path -ErrorAction Stop |
  Where-Object { $_.Subject -like $Subject } |
  Sort-Object NotBefore, Subject
}
catch {
  throw "Failed to read certificates from ${Path}: $($_.Exception.Message)"
}

if (-not $Certificates -or $Certificates.Count -eq 0) {
  Write-Host "No certificates matched the provided criteria." -ForegroundColor Yellow
  exit 0
}

Write-Host "Matching certificates:" -ForegroundColor Green
$Certificates |
ForEach-Object { Format-CertificateSummary -Certificate $_ } |
Format-Table -AutoSize

Write-Host ""

$RemovedCount = 0

foreach ($Certificate in $Certificates) {
  $Target = "[$($Certificate.Subject)] $($Certificate.Thumbprint)"

  if ($PSCmdlet.ShouldProcess($Target, "Remove certificate from $Path")) {
    try {
      Remove-Item -Path $Certificate.PSPath -ErrorAction Stop
      $RemovedCount++
      Write-Host "Removed: $Target" -ForegroundColor Green
    }
    catch {
      Write-Warning "Failed to remove ${Target}: $($_.Exception.Message)"
    }
  }
}

Write-Host ""
Write-Host "Removed $RemovedCount certificate(s) from $Path" -ForegroundColor Cyan
#
# .SYNOPSIS
# Lists certificates from Windows certificate stores in a readable table.
#
# .DESCRIPTION
# Prints certificates from common Windows certificate stores for the current user
# by default, or for the local machine when -Machine is specified.
#
# The script shows NotBefore as the closest available creation/valid-from date.
#
# .PARAMETER Machine
# Switches the scope from CurrentUser to LocalMachine.
#
# .EXAMPLE
# .\scripts\wincert-list.ps1
# Lists certificates from the current user's stores.
#
# .EXAMPLE
# .\scripts\wincert-list.ps1 -Machine
# Lists certificates from the local machine's stores.
#
[CmdletBinding()]
param(
  [switch]$Machine
)

$Scope = if ($Machine) { 'LocalMachine' } else { 'CurrentUser' }
$Stores = @(
  'My',
  'Root',
  'CA',
  'AuthRoot',
  'TrustedPublisher',
  'TrustedPeople',
  'Disallowed',
  'AddressBook'
)

function Convert-ToCertRow {
  param(
    [Parameter(Mandatory)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  [pscustomobject]@{
    'Created/Valid From' = $Certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss')
    'Valid To'           = $Certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
    'Subject'            = $Certificate.Subject
    'Issuer'             = $Certificate.Issuer
    'Thumbprint'         = $Certificate.Thumbprint
    'Friendly Name'      = $Certificate.FriendlyName
    'Has Private Key'    = if ($Certificate.HasPrivateKey) { 'Yes' } else { 'No' }
    'Is CA'              = if ($Certificate.Extensions | Where-Object {
        $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and $_.CertificateAuthority
      }) { 'Yes' } else { 'No' }
  }
}

Write-Host "Windows certificate stores for $Scope" -ForegroundColor Cyan
Write-Host ""

foreach ($Store in $Stores) {
  $Path = "Cert:\$Scope\$Store"

  if (-not (Test-Path $Path)) {
    continue
  }

  Write-Host "Store: $Path" -ForegroundColor Yellow

  try {
    $Certs = Get-ChildItem -Path $Path -ErrorAction Stop | Sort-Object NotBefore, Subject
  }
  catch {
    Write-Host "  Unable to read store: $($_.Exception.Message)" -ForegroundColor DarkYellow
    Write-Host ""
    continue
  }

  if (-not $Certs -or $Certs.Count -eq 0) {
    Write-Host "  (empty)"
    Write-Host ""
    continue
  }

  Write-Host ("  Certificates: {0}" -f $Certs.Count)
  $Certs |
  ForEach-Object { Convert-ToCertRow -Certificate $_ } |
  Format-Table -AutoSize

  Write-Host ""
}
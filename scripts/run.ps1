param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('tls', 'mtls')]
    [string]$Mode
)

go run cmd/main.go $Mode

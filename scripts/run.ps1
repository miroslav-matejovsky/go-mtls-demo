param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('tlsmem', 'mtlsmem', 'tlsfiles', 'mtlsfiles')]
    [string]$Mode
)

go run cmd/main.go $Mode

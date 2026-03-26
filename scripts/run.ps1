param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('tlsmem', 'mtlsmem', 'tlsfiles', 'mtlsfiles', 'mtlstpm')]
    [string]$Mode
)

go run cmd/main.go $Mode

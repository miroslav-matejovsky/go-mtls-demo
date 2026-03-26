param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('tlsmem', 'mtlsmem')]
    [string]$Mode
)

go run cmd/main.go $Mode

param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePath,

    [Parameter(Mandatory = $true)]
    [string]$TargetPath
)

$ErrorActionPreference = "Stop"
$serviceName = "EndpointSecurityAgent"

$service = Get-Service `
    -Name $serviceName `
    -ErrorAction Stop

if ($service.Status -ne "Stopped") {
    Stop-Service `
        -Name $serviceName `
        -Force

    $service.WaitForStatus(
        "Stopped",
        [TimeSpan]::FromSeconds(30))
}

New-Item `
    -ItemType Directory `
    -Path $TargetPath `
    -Force | Out-Null

Get-ChildItem `
    -Path $TargetPath `
    -Force `
    -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force

Copy-Item `
    -Path (Join-Path $SourcePath "*") `
    -Destination $TargetPath `
    -Recurse `
    -Force

Start-Service -Name $serviceName

(Get-Service -Name $serviceName).WaitForStatus(
    "Running",
    [TimeSpan]::FromSeconds(30))

Write-Host ""
Write-Host "Agent service updated successfully." `
    -ForegroundColor Green

Get-Service -Name $serviceName |
    Format-Table Status, Name, DisplayName

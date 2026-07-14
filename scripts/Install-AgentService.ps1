$ErrorActionPreference = "Stop"

$serviceName = "EndpointSecurityAgent"
$displayName = "Endpoint Security Agent"
$projectRoot = Split-Path -Parent $PSScriptRoot
$exePath = Join-Path `
    $projectRoot `
    "artifacts\agent\EndpointSecurity.Agent.exe"

if (-not (Test-Path $exePath)) {
    throw "Agent executable was not found: $exePath"
}

$existingService = Get-Service `
    -Name $serviceName `
    -ErrorAction SilentlyContinue

if ($null -ne $existingService) {
    if ($existingService.Status -ne "Stopped") {
        Stop-Service `
            -Name $serviceName `
            -Force

        $existingService.WaitForStatus(
            "Stopped",
            [TimeSpan]::FromSeconds(20))
    }

    sc.exe delete $serviceName | Out-Host
    Start-Sleep -Seconds 2
}

$binaryPath = "`"$exePath`""

New-Service `
    -Name $serviceName `
    -BinaryPathName $binaryPath `
    -DisplayName $displayName `
    -Description "Collects endpoint security posture, Defender results, processes, and network telemetry." `
    -StartupType Automatic

sc.exe failure `
    $serviceName `
    reset= 86400 `
    actions= restart/5000/restart/15000/restart/30000 |
    Out-Host

sc.exe failureflag $serviceName 1 |
    Out-Host

Start-Service -Name $serviceName

Start-Sleep -Seconds 3

Get-Service -Name $serviceName |
    Format-Table Status, Name, DisplayName

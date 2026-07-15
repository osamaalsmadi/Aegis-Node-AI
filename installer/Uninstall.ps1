$ErrorActionPreference = 'Stop'

$taskName = 'Endpoint Security Platform'
$serviceName = 'EndpointSecurityAgent'
$installRoot = Join-Path $env:ProgramFiles 'EndpointSecurityPlatform'
$desktop = [Environment]::GetFolderPath('Desktop')

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    $process = Start-Process powershell.exe `
        -Verb RunAs `
        -Wait `
        -PassThru `
        -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            "`"$PSCommandPath`""
        )

    exit $process.ExitCode
}

Write-Host 'Uninstalling Endpoint Security Platform...' -ForegroundColor Cyan

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
& sc.exe delete $serviceName | Out-Null

$processIds = @(
    Get-NetTCPConnection -LocalPort 5235 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
)

foreach ($ownerId in $processIds) {
    Stop-Process -Id $ownerId -Force -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath (Join-Path $desktop 'Endpoint Security Platform.url') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $desktop 'Uninstall Endpoint Security Platform.lnk') -Force -ErrorAction SilentlyContinue

$deleteCommand = "timeout /t 3 /nobreak >nul & rmdir /s /q `"$installRoot`""
Start-Process cmd.exe -ArgumentList '/c', $deleteCommand -WindowStyle Hidden

Write-Host ''
Write-Host 'Endpoint Security Platform was uninstalled.' -ForegroundColor Green
Write-Host 'SQL data and Ollama models were preserved.'
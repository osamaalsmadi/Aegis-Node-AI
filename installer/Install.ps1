$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$taskName = 'Endpoint Security Platform'
$serviceName = 'EndpointSecurityAgent'
$displayName = 'Endpoint Security Agent'
$installRoot = Join-Path $env:ProgramFiles 'EndpointSecurityPlatform'
$apiTarget = Join-Path $installRoot 'Api'
$agentTarget = Join-Path $installRoot 'Agent'
$apiSource = Join-Path $PSScriptRoot 'Api'
$agentSource = Join-Path $PSScriptRoot 'Agent'
$apiExe = Join-Path $apiTarget 'EndpointSecurity.Api.exe'
$agentExe = Join-Path $agentTarget 'EndpointSecurity.Agent.exe'
$iconTarget = Join-Path $installRoot 'EndpointSecurityPlatform.ico'
$uninstallTarget = Join-Path $installRoot 'Uninstall.ps1'
$backupRoot = Join-Path $env:ProgramData 'EndpointSecurityPlatform\InstallBackups'
$backupPath = Join-Path $backupRoot (Get-Date -Format 'yyyyMMdd-HHmmss')

$oldTaskXml = $null
$oldTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$oldService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
$oldServicePath = $oldService.PathName
$oldServiceWasRunning = $oldService.State -eq 'Running'
$oldInstallExisted = Test-Path -LiteralPath $installRoot
$installationStarted = $false

function Wait-Api {
    $deadline = [DateTime]::UtcNow.AddSeconds(75)

    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri 'http://localhost:5235/api/health' -TimeoutSec 5

            if ($health.status -eq 'Healthy') {
                return
            }
        }
        catch {
        }

        Start-Sleep -Milliseconds 750
    }

    throw 'Installed API did not become healthy.'
}

function Stop-PortProcess {
    $processIds = @(
        Get-NetTCPConnection -LocalPort 5235 -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique
    )

    foreach ($ownerId in $processIds) {
        Stop-Process -Id $ownerId -Force -ErrorAction SilentlyContinue
    }
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'Installer must run as Administrator.'
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Endpoint Security Platform requires 64-bit Windows.'
}

$sqlService = Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue

if ($null -eq $sqlService) {
    throw 'SQL Server Express instance SQLEXPRESS is required.'
}

if ($sqlService.Status -ne 'Running') {
    Start-Service -Name 'MSSQL$SQLEXPRESS'
    (Get-Service -Name 'MSSQL$SQLEXPRESS').WaitForStatus(
        'Running',
        [TimeSpan]::FromSeconds(30)
    )
}

if (-not (Test-Path -LiteralPath (Join-Path $apiSource 'EndpointSecurity.Api.exe'))) {
    throw 'API payload is missing.'
}

if (-not (Test-Path -LiteralPath (Join-Path $agentSource 'EndpointSecurity.Agent.exe'))) {
    throw 'Agent payload is missing.'
}

try {
    Write-Host ''
    Write-Host 'Installing Endpoint Security Platform...' -ForegroundColor Cyan

    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

    if ($null -ne $oldTask) {
        $oldTaskXml = Export-ScheduledTask -TaskName $taskName
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    if ($null -ne $oldService) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        (Get-Service -Name $serviceName).WaitForStatus(
            'Stopped',
            [TimeSpan]::FromSeconds(30)
        )
    }

    Stop-PortProcess
    Start-Sleep -Seconds 2

    if ($oldInstallExisted) {
        Copy-Item -LiteralPath $installRoot -Destination $backupPath -Recurse -Force
    }

    $installationStarted = $true

    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $apiTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $agentTarget -Force | Out-Null

    Copy-Item -Path (Join-Path $apiSource '*') -Destination $apiTarget -Recurse -Force
    Copy-Item -Path (Join-Path $agentSource '*') -Destination $agentTarget -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'EndpointSecurityPlatform.ico') -Destination $iconTarget -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall.ps1') -Destination $uninstallTarget -Force

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction `
        -Execute $apiExe `
        -Argument '--urls http://localhost:5235' `
        -WorkingDirectory $apiTarget
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId $currentUser `
        -LogonType Interactive `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 5 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $taskPrincipal `
        -Settings $settings `
        -Description 'Runs the Endpoint Security API and dashboard locally.' `
        -Force | Out-Null

    Start-ScheduledTask -TaskName $taskName
    Wait-Api

    if ($null -eq $oldService) {
        New-Service `
            -Name $serviceName `
            -BinaryPathName "`"$agentExe`"" `
            -DisplayName $displayName `
            -Description 'Collects endpoint security posture, Defender, processes, connections, findings, and Windows security events.' `
            -StartupType Automatic
    }
    else {
        & sc.exe config $serviceName binPath= "`"$agentExe`"" start= auto | Out-Host

        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to update the Agent service configuration.'
        }
    }

    & sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Host
    & sc.exe failureflag $serviceName 1 | Out-Host

    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus(
        'Running',
        [TimeSpan]::FromSeconds(30)
    )

    $desktop = [Environment]::GetFolderPath('Desktop')
    $dashboardShortcut = Join-Path $desktop 'Endpoint Security Platform.url'

    $shortcutText = @"
[InternetShortcut]
URL=http://localhost:5235
IconFile=$iconTarget
IconIndex=0
"@

    [IO.File]::WriteAllText(
        $dashboardShortcut,
        $shortcutText,
        [Text.Encoding]::ASCII
    )

    $shell = New-Object -ComObject WScript.Shell
    $uninstallShortcut = $shell.CreateShortcut(
        (Join-Path $desktop 'Uninstall Endpoint Security Platform.lnk')
    )
    $uninstallShortcut.TargetPath = 'powershell.exe'
    $uninstallShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$uninstallTarget`""
    $uninstallShortcut.WorkingDirectory = $installRoot
    $uninstallShortcut.IconLocation = "$iconTarget,0"
    $uninstallShortcut.Save()

    $metadata = @"
InstalledUtc=$([DateTime]::UtcNow.ToString('o'))
Version=1.0.0
Dashboard=http://localhost:5235
"@

    [IO.File]::WriteAllText(
        (Join-Path $installRoot 'install.info'),
        $metadata,
        [Text.Encoding]::ASCII
    )

    $aiStatus = Invoke-RestMethod -Uri 'http://localhost:5235/api/ai-security/status' -TimeoutSec 15

    Write-Host ''
    Write-Host 'Endpoint Security Platform installed successfully.' -ForegroundColor Green
    Write-Host "Install path: $installRoot"
    Write-Host "Dashboard: http://localhost:5235"
    Write-Host "Agent service: $((Get-Service $serviceName).Status)"
    Write-Host "AI model: $($aiStatus.model)"

    Start-Process 'http://localhost:5235'
}
catch {
    $failure = $_.Exception.Message
    Write-Host "Installation failed: $failure" -ForegroundColor Red
    Write-Host 'Rolling back...' -ForegroundColor Yellow

    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    Stop-PortProcess

    if ($installationStarted) {
        Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue

        if ($oldInstallExisted -and (Test-Path -LiteralPath $backupPath)) {
            Copy-Item -LiteralPath $backupPath -Destination $installRoot -Recurse -Force
        }
    }

    if ($null -ne $oldTaskXml) {
        Register-ScheduledTask -TaskName $taskName -Xml $oldTaskXml -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    else {
        $legacyDll = Join-Path $env:LOCALAPPDATA 'EndpointSecurityPlatform\Api\current\EndpointSecurity.Api.dll'

        if (Test-Path -LiteralPath $legacyDll) {
            Start-Process dotnet.exe `
                -ArgumentList "`"$legacyDll`" --urls http://localhost:5235" `
                -WorkingDirectory (Split-Path -Parent $legacyDll) `
                -WindowStyle Hidden
        }
    }

    if ($null -ne $oldService) {
        & sc.exe config $serviceName binPath= $oldServicePath | Out-Null

        if ($oldServiceWasRunning) {
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
        }
    }
    else {
        & sc.exe delete $serviceName | Out-Null
    }

    throw "Installation was rolled back: $failure"
}
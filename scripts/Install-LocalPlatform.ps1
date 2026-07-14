$ErrorActionPreference = "Stop"

function Assert-NativeCommand {
    param([string]$Step)

    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE."
    }
}

$taskName = "Endpoint Security Platform"
$projectRoot = Split-Path -Parent $PSScriptRoot

$dashboardPath = Join-Path `
    $projectRoot `
    "src\EndpointSecurity.Dashboard"

$dashboardDistPath = Join-Path `
    $dashboardPath `
    "dist"

$apiProjectPath = Join-Path `
    $projectRoot `
    "src\EndpointSecurity.Api"

$apiWwwrootPath = Join-Path `
    $apiProjectPath `
    "wwwroot"

$stagingPath = Join-Path `
    $projectRoot `
    "artifacts\api-update"

$installedPath = Join-Path `
    $projectRoot `
    "artifacts\api"

Write-Host ""
Write-Host "===== BUILD DASHBOARD =====" `
    -ForegroundColor Cyan

Push-Location $dashboardPath

npm.cmd run build

Assert-NativeCommand "Dashboard build"

Pop-Location

if (-not (Test-Path $dashboardDistPath)) {
    throw "Dashboard dist folder was not created."
}

Remove-Item `
    $apiWwwrootPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

New-Item `
    -ItemType Directory `
    -Path $apiWwwrootPath `
    -Force | Out-Null

Copy-Item `
    -Path (Join-Path $dashboardDistPath "*") `
    -Destination $apiWwwrootPath `
    -Recurse `
    -Force

Write-Host ""
Write-Host "===== PUBLISH API =====" `
    -ForegroundColor Cyan

Remove-Item `
    $stagingPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

dotnet publish `
    (Join-Path $apiProjectPath "EndpointSecurity.Api.csproj") `
    --configuration Release `
    --runtime win-x64 `
    --self-contained false `
    -p:PublishSingleFile=true `
    --output $stagingPath

Assert-NativeCommand "API publish"

Write-Host ""
Write-Host "===== STOP OLD PROCESSES =====" `
    -ForegroundColor Cyan

$existingTask = Get-ScheduledTask `
    -TaskName $taskName `
    -ErrorAction SilentlyContinue

if ($null -ne $existingTask) {
    Stop-ScheduledTask `
        -TaskName $taskName `
        -ErrorAction SilentlyContinue

    Unregister-ScheduledTask `
        -TaskName $taskName `
        -Confirm:$false
}

foreach ($port in @(5235, 5173)) {
    $processIds = @(
        Get-NetTCPConnection `
            -LocalPort $port `
            -State Listen `
            -ErrorAction SilentlyContinue |
        Select-Object `
            -ExpandProperty OwningProcess `
            -Unique
    )

    foreach ($processId in $processIds) {
        Stop-Process `
            -Id $processId `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 2

Remove-Item `
    $installedPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

New-Item `
    -ItemType Directory `
    -Path $installedPath `
    -Force | Out-Null

Copy-Item `
    -Path (Join-Path $stagingPath "*") `
    -Destination $installedPath `
    -Recurse `
    -Force

Remove-Item `
    $stagingPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

$apiExecutable = Join-Path `
    $installedPath `
    "EndpointSecurity.Api.exe"

if (-not (Test-Path $apiExecutable)) {
    throw "Published API executable was not found."
}

Write-Host ""
Write-Host "===== REGISTER AUTO START =====" `
    -ForegroundColor Cyan

$currentUser =
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$action = New-ScheduledTaskAction `
    -Execute $apiExecutable `
    -Argument "--urls http://localhost:5235" `
    -WorkingDirectory $installedPath

$trigger = New-ScheduledTaskTrigger `
    -AtLogOn `
    -User $currentUser

$principal = New-ScheduledTaskPrincipal `
    -UserId $currentUser `
    -LogonType Interactive `
    -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

$task = New-ScheduledTask `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Runs the Endpoint Security API and dashboard locally."

Register-ScheduledTask `
    -TaskName $taskName `
    -InputObject $task `
    -Force | Out-Null

Start-ScheduledTask -TaskName $taskName

Write-Host ""
Write-Host "===== VERIFY PLATFORM =====" `
    -ForegroundColor Cyan

$apiHealth = $null

for ($attempt = 1; $attempt -le 30; $attempt++) {
    Start-Sleep -Seconds 1

    try {
        $apiHealth = Invoke-RestMethod `
            "http://localhost:5235/api/health" `
            -ErrorAction Stop

        break
    }
    catch {
    }
}

if ($null -eq $apiHealth) {
    $taskInfo = Get-ScheduledTaskInfo `
        -TaskName $taskName

    $taskInfo | Format-List

    throw "The automatically started API did not become healthy."
}

$dashboardResponse = Invoke-WebRequest `
    "http://localhost:5235" `
    -UseBasicParsing

Write-Host ""
Write-Host "Endpoint Security Platform installed successfully." `
    -ForegroundColor Green

$apiHealth | Format-List

Write-Host "Dashboard HTTP status: $($dashboardResponse.StatusCode)"

Get-ScheduledTask `
    -TaskName $taskName |
    Select-Object TaskName, State |
    Format-Table

$desktopPath =
    [Environment]::GetFolderPath("Desktop")

$shortcutPath = Join-Path `
    $desktopPath `
    "Endpoint Security Platform.url"

@"
[InternetShortcut]
URL=http://localhost:5235
"@ | Set-Content `
    $shortcutPath `
    -Encoding ASCII

Start-Process "http://localhost:5235"

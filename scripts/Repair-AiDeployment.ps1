$ErrorActionPreference = "Stop"

$projectRoot =
    "C:\Users\bsmad\Documents\Projects\EndpointSecurityPlatform"

$taskName =
    "Endpoint Security Platform"

$dashboardPath = Join-Path `
    $projectRoot `
    "src\EndpointSecurity.Dashboard"

$apiProject = Join-Path `
    $projectRoot `
    "src\EndpointSecurity.Api\EndpointSecurity.Api.csproj"

$apiWwwRoot = Join-Path `
    $projectRoot `
    "src\EndpointSecurity.Api\wwwroot"

$dashboardDist = Join-Path `
    $dashboardPath `
    "dist"

$artifactsRoot = Join-Path `
    $projectRoot `
    "artifacts"

$publishPath = Join-Path `
    $artifactsRoot `
    "api"

$stagingPath = Join-Path `
    $artifactsRoot `
    "api-stage"

$backupPath = Join-Path `
    $artifactsRoot `
    "api-backup"

Set-Location $projectRoot

Write-Host "`n===== BUILD DASHBOARD =====" `
    -ForegroundColor Cyan

Set-Location $dashboardPath

npm.cmd run build

if ($LASTEXITCODE -ne 0) {
    throw "Dashboard build failed."
}

if (-not (Test-Path $dashboardDist)) {
    throw "Dashboard dist folder was not created."
}

Write-Host "`n===== PREPARE DASHBOARD =====" `
    -ForegroundColor Cyan

Remove-Item `
    $apiWwwRoot `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

New-Item `
    -ItemType Directory `
    -Path $apiWwwRoot `
    -Force |
    Out-Null

Copy-Item `
    -Path "$dashboardDist\*" `
    -Destination $apiWwwRoot `
    -Recurse `
    -Force

Write-Host "`n===== PUBLISH API =====" `
    -ForegroundColor Cyan

Set-Location $projectRoot

Remove-Item `
    $stagingPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

dotnet publish `
    $apiProject `
    --configuration Release `
    --runtime win-x64 `
    --self-contained false `
    -p:PublishSingleFile=true `
    --output $stagingPath

if ($LASTEXITCODE -ne 0) {
    throw "API publish failed."
}

$stagedExe = Join-Path `
    $stagingPath `
    "EndpointSecurity.Api.exe"

if (-not (Test-Path $stagedExe)) {
    throw "Published API executable was not created."
}

Write-Host "`n===== STOP OLD API =====" `
    -ForegroundColor Cyan

Stop-ScheduledTask `
    -TaskName $taskName `
    -ErrorAction SilentlyContinue

$apiConnections = Get-NetTCPConnection `
    -LocalPort 5235 `
    -State Listen `
    -ErrorAction SilentlyContinue

foreach ($connection in $apiConnections) {
    Stop-Process `
        -Id $connection.OwningProcess `
        -Force `
        -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 3

Write-Host "`n===== INSTALL NEW API =====" `
    -ForegroundColor Cyan

Remove-Item `
    $backupPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

if (Test-Path $publishPath) {
    Move-Item `
        -Path $publishPath `
        -Destination $backupPath `
        -Force
}

Move-Item `
    -Path $stagingPath `
    -Destination $publishPath `
    -Force

$exePath = Join-Path `
    $publishPath `
    "EndpointSecurity.Api.exe"

$currentUser =
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$action = New-ScheduledTaskAction `
    -Execute $exePath `
    -Argument "--urls http://localhost:5235" `
    -WorkingDirectory $publishPath

$trigger = New-ScheduledTaskTrigger `
    -AtLogOn `
    -User $currentUser

$principal = New-ScheduledTaskPrincipal `
    -UserId $currentUser `
    -LogonType Interactive `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 5 `
    -RestartInterval (
        New-TimeSpan -Minutes 1
    ) `
    -ExecutionTimeLimit (
        New-TimeSpan -Days 3650
    )

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Runs the Endpoint Security API and dashboard." `
    -Force |
    Out-Null

Start-ScheduledTask `
    -TaskName $taskName

Write-Host "`n===== VERIFY NEW API =====" `
    -ForegroundColor Cyan

$health = $null

for ($attempt = 1; $attempt -le 40; $attempt++) {
    Start-Sleep -Seconds 2

    try {
        $health = Invoke-RestMethod `
            "http://localhost:5235/api/health" `
            -ErrorAction Stop

        break
    }
    catch {
    }
}

if ($null -eq $health) {
    if (Test-Path $backupPath) {
        Stop-ScheduledTask `
            -TaskName $taskName `
            -ErrorAction SilentlyContinue

        Remove-Item `
            $publishPath `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue

        Move-Item `
            $backupPath `
            $publishPath `
            -Force
    }

    throw "The newly deployed API did not start."
}

$aiStatus = Invoke-RestMethod `
    "http://localhost:5235/api/ai-security/status"

if (-not $aiStatus.available) {
    throw "API is running but local AI is unavailable."
}

Remove-Item `
    $backupPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "`nDeployment completed successfully." `
    -ForegroundColor Green

$health | Format-List
$aiStatus | Format-List

Get-ScheduledTask `
    -TaskName $taskName |
    Select-Object TaskName, State |
    Format-Table

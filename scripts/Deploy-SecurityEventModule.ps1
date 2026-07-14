$ErrorActionPreference = "Stop"

function Assert-NativeCommand {
    param([string]$Step)

    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE."
    }
}

$projectRoot =
    "C:\Users\bsmad\Documents\Projects\EndpointSecurityPlatform"

Set-Location $projectRoot

Write-Host ""
Write-Host "===== UPDATE DATABASE =====" `
    -ForegroundColor Cyan

dotnet ef database update `
    --project ".\src\EndpointSecurity.Infrastructure\EndpointSecurity.Infrastructure.csproj" `
    --startup-project ".\src\EndpointSecurity.Api\EndpointSecurity.Api.csproj" `
    --context EndpointSecurityDbContext

Assert-NativeCommand "Database update"

Write-Host ""
Write-Host "===== INSTALL API AND DASHBOARD =====" `
    -ForegroundColor Cyan

& ".\scripts\Install-LocalPlatform.ps1"

Write-Host ""
Write-Host "===== PUBLISH WINDOWS AGENT =====" `
    -ForegroundColor Cyan

$agentStaging =
    Join-Path `
        $projectRoot `
        "artifacts\agent-security-event-update"

$agentTarget =
    Join-Path `
        $projectRoot `
        "artifacts\agent"

Remove-Item `
    $agentStaging `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

dotnet publish `
    ".\src\EndpointSecurity.Agent\EndpointSecurity.Agent.csproj" `
    --configuration Release `
    --runtime win-x64 `
    --self-contained false `
    -p:PublishSingleFile=true `
    --output $agentStaging

Assert-NativeCommand "Agent publish"

& ".\scripts\Update-AgentService.ps1" `
    -SourcePath $agentStaging `
    -TargetPath $agentTarget

Remove-Item `
    $agentStaging `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "===== WAIT FOR EVENT COLLECTION =====" `
    -ForegroundColor Cyan

Start-Sleep -Seconds 25

$deviceId = (
    Get-Content `
        "$env:ProgramData\EndpointSecurity\device-id.txt"
).Trim()

Write-Host ""
Write-Host "===== API HEALTH =====" `
    -ForegroundColor Cyan

Invoke-RestMethod `
    "http://localhost:5235/api/health" |
    Format-List

Write-Host ""
Write-Host "===== EVENT SUMMARY =====" `
    -ForegroundColor Cyan

Invoke-RestMethod `
    "http://localhost:5235/api/security-events/devices/$deviceId/summary" |
    Format-List

Write-Host ""
Write-Host "===== AGENT SERVICE =====" `
    -ForegroundColor Cyan

Get-Service "EndpointSecurityAgent" |
    Format-Table Status, Name, DisplayName

Write-Host ""
Write-Host "Security Event Monitor deployed successfully." `
    -ForegroundColor Green

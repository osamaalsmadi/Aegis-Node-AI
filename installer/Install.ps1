param (
    [string]$InstallDir = "C:\Program Files\EndpointSecurityPlatform"
)
$ErrorActionPreference = 'Stop'
Write-Host "Starting Installation to $InstallDir..."

if (-not (Get-Service -Name "MSSQL$SQLEXPRESS" -ErrorAction SilentlyContinue)) {
    Write-Host "Installing SQL Server Express..."
    $sqlExe = Join-Path $InstallDir "Dependencies\SQLEXPR_x64_ENU.exe"
    if (Test-Path $sqlExe) {
        $sqlArgs = "/QS /ACTION=Install /FEATURES=SQLENGINE /INSTANCENAME=SQLEXPRESS /SQLSVCACCOUNT="NT Service\MSSQL$SQLEXPRESS" /SQLSYSADMINACCOUNTS="BUILTIN\Administrators" "$env:COMPUTERNAME\$env:USERNAME" /TCPENABLED=0 /NPENABLED=0 /IACCEPTSQLSERVERLICENSETERMS /UpdateEnabled=False"
        Start-Process -FilePath $sqlExe -ArgumentList $sqlArgs -Wait -NoNewWindow
    }
}

$ollamaPath = "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe"
if (-not (Test-Path $ollamaPath)) {
    Write-Host "Downloading and Installing Ollama..."
    $ollamaSetup = Join-Path $InstallDir "Dependencies\OllamaSetup.exe"
    try {
        Invoke-WebRequest -Uri "https://ollama.com/download/OllamaSetup.exe" -OutFile $ollamaSetup -UseBasicParsing
        if (Test-Path $ollamaSetup) {
            Start-Process -FilePath $ollamaSetup -ArgumentList "/silent" -Wait -NoNewWindow
        }
    } catch {
        Write-Host "AI installation skipped/failed." -ForegroundColor Yellow
    }
}

if (Test-Path $ollamaPath) {
    Write-Host "Pulling AI model..."
    try { & $ollamaPath pull qwen2.5:1.5b } catch { }
}

Write-Host "Configuring EndpointSecurityAgent Service..."
$agentExe = Join-Path $InstallDir "Agent\EndpointSecurity.Agent.exe"
if (Get-Service -Name "EndpointSecurityAgent" -ErrorAction SilentlyContinue) { 
    Stop-Service "EndpointSecurityAgent" -Force
    Remove-Service "EndpointSecurityAgent" 
}
New-Service -Name "EndpointSecurityAgent" -BinaryPathName $agentExe -StartupType Automatic | Out-Null
Start-Service "EndpointSecurityAgent"

Write-Host "Configuring API Scheduled Task..."
$taskName = "Endpoint Security Platform"
$apiExe = Join-Path $InstallDir "Api\EndpointSecurity.Api.exe"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { 
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false 
}
$action = New-ScheduledTaskAction -Execute $apiExe -Argument "--urls http://localhost:5235" -WorkingDirectory (Join-Path $InstallDir "Api")
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Highest -User $env:USERNAME -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "Triggering Database Creation..."
try { Start-Sleep -Seconds 5; Invoke-RestMethod -Uri "http://localhost:5235/api/health" -UseBasicParsing | Out-Null } catch { }

Write-Host "Creating Desktop App Shortcut..."
$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut("$env:PUBLIC\Desktop\Endpoint Security Platform.lnk")
$shortcut.TargetPath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$shortcut.Arguments = "--app="http://localhost:5235""
$shortcut.IconLocation = "$apiExe,0"
$shortcut.Save()

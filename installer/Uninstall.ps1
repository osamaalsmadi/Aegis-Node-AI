$ErrorActionPreference = 'Continue'
Write-Host "Removing Endpoint Security Platform..."

if (Get-Service -Name "EndpointSecurityAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "EndpointSecurityAgent" -Force
    Remove-Service "EndpointSecurityAgent"
}

$taskName = "Endpoint Security Platform"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $taskName
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

Get-Process -Name "EndpointSecurity.Api" -ErrorAction SilentlyContinue | Stop-Process -Force

$shortcut = "$env:PUBLIC\Desktop\Endpoint Security Platform.lnk"
if (Test-Path $shortcut) { Remove-Item $shortcut -Force }

Write-Host "Uninstallation completed. SQL Server, Ollama, and User Data are preserved."

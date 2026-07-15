$ErrorActionPreference = 'Stop'
$projectPath = "C:\Users\bsmad\Documents\Projects\EndpointSecurityPlatform"
$publishDir = Join-Path $projectPath "publish"
$setupDir = Join-Path $projectPath "installer\EndpointSecurity.Setup"
$releaseDir = Join-Path $projectPath "release"
$installerCache = "C:\ProgramData\EndpointSecurityPlatform\InstallerDependencies"

Write-Host "Cleaning directories..."
if (Test-Path $publishDir) { Remove-Item -Path $publishDir -Recurse -Force }
New-Item -ItemType Directory -Path $publishDir -Force | Out-Null
if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null }

Write-Host "Building API and Agent (Self-contained)..."
dotnet publish "$projectPath\src\EndpointSecurity.Api\EndpointSecurity.Api.csproj" -c Release -r win-x64 --self-contained true -o "$publishDir\Api"
dotnet publish "$projectPath\src\EndpointSecurity.Agent\EndpointSecurity.Agent.csproj" -c Release -r win-x64 --self-contained true -o "$publishDir\Agent"

Write-Host "Staging Installer Dependencies (SQL only)..."
$depsDir = Join-Path $publishDir "Dependencies"
New-Item -ItemType Directory -Path $depsDir -Force | Out-Null
Copy-Item "$installerCache\SQL\SQLEXPR_x64_ENU.exe" -Destination $depsDir

Copy-Item "$projectPath\installer\Install.ps1" -Destination $publishDir
Copy-Item "$projectPath\installer\Uninstall.ps1" -Destination $publishDir

Write-Host "Creating Payload Archive (This may take a minute)..."
$payloadZip = Join-Path $setupDir "payload.zip"
if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }
Compress-Archive -Path "$publishDir\*" -DestinationPath $payloadZip -Force

Write-Host "Building Final Graphical Setup.exe..."
dotnet publish "$setupDir\EndpointSecurity.Setup.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $releaseDir

Write-Host "Build stage complete. Final Setup is in $releaseDir"

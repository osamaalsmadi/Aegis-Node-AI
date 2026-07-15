$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$projectRoot = Split-Path -Parent $PSScriptRoot
$dashboardPath = Join-Path $projectRoot 'src\EndpointSecurity.Dashboard'
$dashboardDist = Join-Path $dashboardPath 'dist'
$apiProject = Join-Path $projectRoot 'src\EndpointSecurity.Api\EndpointSecurity.Api.csproj'
$apiWwwroot = Join-Path $projectRoot 'src\EndpointSecurity.Api\wwwroot'
$agentProject = Join-Path $projectRoot 'src\EndpointSecurity.Agent\EndpointSecurity.Agent.csproj'
$installerSource = Join-Path $projectRoot 'installer'
$setupProjectSource = Join-Path $installerSource 'EndpointSecurity.Setup'
$releaseRoot = Join-Path $projectRoot 'release'
$stageRoot = Join-Path $releaseRoot '.stage'
$packageRoot = Join-Path $stageRoot 'package'
$apiOutput = Join-Path $packageRoot 'Api'
$agentOutput = Join-Path $packageRoot 'Agent'
$setupBuildRoot = Join-Path $stageRoot 'setup-project'
$setupOutput = Join-Path $stageRoot 'setup-publish'
$verifyRoot = Join-Path $stageRoot 'verify'
$payloadZip = Join-Path $stageRoot 'Payload.zip'
$setupExe = Join-Path $releaseRoot 'EndpointSecurityPlatform-Setup.exe'
$portableZip = Join-Path $releaseRoot 'EndpointSecurityPlatform-Windows-x64.zip'
$hashFile = Join-Path $releaseRoot 'SHA256.txt'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-ToolPath {
    param([string[]]$Names)

    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue

        if ($null -ne $command) {
            return $command.Source
        }
    }

    throw "Required tool was not found: $($Names -join ', ')"
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory
    )

    Write-Host ''
    Write-Host "Running: $FilePath $($Arguments -join ' ')" -ForegroundColor Cyan
    Push-Location -LiteralPath $WorkingDirectory

    try {
        & $FilePath @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($exitCode -ne 0) {
        throw "Command failed with exit code $exitCode."
    }
}

function Wait-Api {
    param(
        [string]$BaseUrl,
        [int]$Seconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)

    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$BaseUrl/api/health" -TimeoutSec 5

            if ($health.status -eq 'Healthy') {
                return
            }
        }
        catch {
        }

        Start-Sleep -Milliseconds 500
    }

    throw "Packaged API did not become healthy at $BaseUrl"
}

function New-PlatformIcon {
    param([string]$Path)

    Add-Type -AssemblyName System.Drawing

    $bitmap = [System.Drawing.Bitmap]::new(64, 64)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::FromArgb(8, 27, 43))

    $background = [System.Drawing.SolidBrush]::new(
        [System.Drawing.Color]::FromArgb(14, 49, 72)
    )
    $graphics.FillEllipse($background, 3, 3, 58, 58)

    $pen = [System.Drawing.Pen]::new(
        [System.Drawing.Color]::FromArgb(38, 214, 255),
        4
    )

    $shield = @(
        [System.Drawing.Point]::new(32, 10),
        [System.Drawing.Point]::new(51, 18),
        [System.Drawing.Point]::new(48, 41),
        [System.Drawing.Point]::new(32, 54),
        [System.Drawing.Point]::new(16, 41),
        [System.Drawing.Point]::new(13, 18),
        [System.Drawing.Point]::new(32, 10)
    )

    $graphics.DrawLines($pen, $shield)
    $graphics.DrawLine($pen, 22, 31, 29, 38)
    $graphics.DrawLine($pen, 29, 38, 43, 24)

    $iconHandle = $bitmap.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($iconHandle)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Create)

    try {
        $icon.Save($stream)
    }
    finally {
        $stream.Dispose()
        $icon.Dispose()
        $pen.Dispose()
        $background.Dispose()
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

$dotnet = Get-ToolPath @('dotnet.exe', 'dotnet')
$npm = Get-ToolPath @('npm.cmd', 'npm')

Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $apiOutput -Force | Out-Null
New-Item -ItemType Directory -Path $agentOutput -Force | Out-Null
New-Item -ItemType Directory -Path $setupBuildRoot -Force | Out-Null
New-Item -ItemType Directory -Path $setupOutput -Force | Out-Null

Write-Host ''
Write-Host '===== BUILD DASHBOARD =====' -ForegroundColor Cyan
Invoke-Native $npm @('run', 'build') $dashboardPath

if (-not (Test-Path -LiteralPath $dashboardDist -PathType Container)) {
    throw 'Dashboard build did not create dist.'
}

Remove-Item -LiteralPath $apiWwwroot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $apiWwwroot -Force | Out-Null
Copy-Item -Path (Join-Path $dashboardDist '*') -Destination $apiWwwroot -Recurse -Force

Write-Host ''
Write-Host '===== PUBLISH SELF-CONTAINED API =====' -ForegroundColor Cyan
Invoke-Native $dotnet @(
    'publish',
    $apiProject,
    '--configuration', 'Release',
    '--runtime', 'win-x64',
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    '--output', $apiOutput,
    '--nologo'
) $projectRoot

Write-Host ''
Write-Host '===== PUBLISH SELF-CONTAINED AGENT =====' -ForegroundColor Cyan
Invoke-Native $dotnet @(
    'publish',
    $agentProject,
    '--configuration', 'Release',
    '--runtime', 'win-x64',
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    '--output', $agentOutput,
    '--nologo'
) $projectRoot

$apiExe = Join-Path $apiOutput 'EndpointSecurity.Api.exe'
$agentExe = Join-Path $agentOutput 'EndpointSecurity.Agent.exe'

if (-not (Test-Path -LiteralPath $apiExe -PathType Leaf)) {
    throw 'Packaged API executable is missing.'
}

if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
    throw 'Packaged Agent executable is missing.'
}

Copy-Item -LiteralPath (Join-Path $installerSource 'Install.ps1') -Destination $packageRoot -Force
Copy-Item -LiteralPath (Join-Path $installerSource 'Uninstall.ps1') -Destination $packageRoot -Force

$iconPath = Join-Path $packageRoot 'EndpointSecurityPlatform.ico'
New-PlatformIcon $iconPath

$readme = @"
Endpoint Security Platform 1.0.0
================================

Run EndpointSecurityPlatform-Setup.exe to install.

Requirements:
- Windows 10/11 x64
- SQL Server Express instance SQLEXPRESS
- Ollama is optional; verified fallback analysis remains available

The installer creates:
- Endpoint Security Platform automatic scheduled task
- EndpointSecurityAgent Windows service
- Desktop dashboard shortcut
- Uninstall shortcut

The uninstaller preserves SQL data and Ollama models.
"@

[IO.File]::WriteAllText(
    (Join-Path $packageRoot 'README.txt'),
    $readme,
    $utf8NoBom
)

Write-Host ''
Write-Host '===== TEST PACKAGED API ON PORT 5236 =====' -ForegroundColor Cyan

$existingTestPort = Get-NetTCPConnection -LocalPort 5236 -State Listen -ErrorAction SilentlyContinue

if ($null -ne $existingTestPort) {
    throw 'Port 5236 is already in use.'
}

$testOut = Join-Path $stageRoot 'api-test.out.log'
$testErr = Join-Path $stageRoot 'api-test.err.log'
$oldEnvironment = $env:ASPNETCORE_ENVIRONMENT
$env:ASPNETCORE_ENVIRONMENT = 'Production'

try {
    $testProcess = Start-Process `
        -FilePath $apiExe `
        -ArgumentList '--urls http://127.0.0.1:5236' `
        -WorkingDirectory $apiOutput `
        -WindowStyle Hidden `
        -RedirectStandardOutput $testOut `
        -RedirectStandardError $testErr `
        -PassThru

    Wait-Api 'http://127.0.0.1:5236' 60

    $dashboardResponse = Invoke-WebRequest `
        -Uri 'http://127.0.0.1:5236' `
        -UseBasicParsing `
        -TimeoutSec 15

    $aiStatus = Invoke-RestMethod `
        -Uri 'http://127.0.0.1:5236/api/ai-security/status' `
        -TimeoutSec 15

    if ([int]$dashboardResponse.StatusCode -ne 200) {
        throw 'Packaged dashboard did not return HTTP 200.'
    }

    if ([string]::IsNullOrWhiteSpace([string]$aiStatus.model)) {
        throw 'Packaged AI status response is invalid.'
    }
}
finally {
    if ($null -ne $testProcess) {
        Stop-Process -Id $testProcess.Id -Force -ErrorAction SilentlyContinue
    }

    if ($null -eq $oldEnvironment) {
        Remove-Item Env:ASPNETCORE_ENVIRONMENT -ErrorAction SilentlyContinue
    }
    else {
        $env:ASPNETCORE_ENVIRONMENT = $oldEnvironment
    }
}

Write-Host ''
Write-Host '===== CREATE PAYLOAD ZIP =====' -ForegroundColor Cyan

Remove-Item -LiteralPath $payloadZip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $packageRoot '*') -DestinationPath $payloadZip -CompressionLevel Optimal

Remove-Item -LiteralPath $verifyRoot -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $payloadZip -DestinationPath $verifyRoot -Force

foreach ($required in @(
    'Api\EndpointSecurity.Api.exe',
    'Agent\EndpointSecurity.Agent.exe',
    'Install.ps1',
    'Uninstall.ps1',
    'EndpointSecurityPlatform.ico'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $verifyRoot $required) -PathType Leaf)) {
        throw "Payload verification failed. Missing: $required"
    }
}

Write-Host ''
Write-Host '===== BUILD SELF-CONTAINED SETUP.EXE =====' -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $setupProjectSource -PathType Container)) {
    throw 'The .NET Setup project source is missing.'
}

Copy-Item -Path (Join-Path $setupProjectSource '*') -Destination $setupBuildRoot -Recurse -Force
Copy-Item -LiteralPath $payloadZip -Destination (Join-Path $setupBuildRoot 'Payload.zip') -Force
Copy-Item -LiteralPath $iconPath -Destination (Join-Path $setupBuildRoot 'EndpointSecurityPlatform.ico') -Force

$setupProject = Join-Path $setupBuildRoot 'EndpointSecurity.Setup.csproj'

Invoke-Native $dotnet @(
    'publish',
    $setupProject,
    '--configuration', 'Release',
    '--runtime', 'win-x64',
    '--self-contained', 'true',
    '-p:PublishSingleFile=true',
    '-p:IncludeNativeLibrariesForSelfExtract=true',
    '-p:EnableCompressionInSingleFile=false',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',
    '--output', $setupOutput,
    '--nologo'
) $projectRoot

$publishedSetup = Join-Path $setupOutput 'EndpointSecurityPlatform-Setup.exe'

if (-not (Test-Path -LiteralPath $publishedSetup -PathType Leaf)) {
    throw 'The .NET publish did not create EndpointSecurityPlatform-Setup.exe.'
}

if (
    (Get-Item -LiteralPath $publishedSetup).Length -le
    (Get-Item -LiteralPath $payloadZip).Length
) {
    throw 'Setup.exe does not contain the complete embedded payload.'
}

Remove-Item -LiteralPath $setupExe -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $publishedSetup -Destination $setupExe -Force

Remove-Item -LiteralPath $portableZip -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $payloadZip -Destination $portableZip -Force

$setupHash = (Get-FileHash -LiteralPath $setupExe -Algorithm SHA256).Hash
$zipHash = (Get-FileHash -LiteralPath $portableZip -Algorithm SHA256).Hash

$hashText = @"
$setupHash  EndpointSecurityPlatform-Setup.exe
$zipHash  EndpointSecurityPlatform-Windows-x64.zip
"@

[IO.File]::WriteAllText($hashFile, $hashText, [Text.Encoding]::ASCII)

Write-Host ''
Write-Host 'WINDOWS INSTALLER BUILD SUCCEEDED.' -ForegroundColor Green
Write-Host "Setup: $setupExe"
Write-Host "Portable ZIP: $portableZip"
Write-Host "Hashes: $hashFile"
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using EndpointSecurity.Application.Telemetry;
using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Agent.Services;

public sealed class EndpointTelemetryCollector(
    ILogger<EndpointTelemetryCollector> logger)
{
    public async Task<SubmitEndpointTelemetryRequest> CollectAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SubmitEndpointTelemetryRequest(
                deviceId,
                0,
                0,
                Array.Empty<SubmitFindingRequest>());
        }

        var result = await RunPowerShellAsync(
            cancellationToken);

        var findings = (result.Findings ?? [])
            .Select(ToFindingRequest)
            .ToList();

        logger.LogInformation(
            "Telemetry collected: {ProcessCount} processes, " +
            "{ConnectionCount} connections, {FindingCount} findings.",
            result.ProcessCount,
            result.ActiveTcpConnectionCount,
            findings.Count);

        return new SubmitEndpointTelemetryRequest(
            deviceId,
            result.ProcessCount,
            result.ActiveTcpConnectionCount,
            findings);
    }

    private static SubmitFindingRequest ToFindingRequest(
        PowerShellFinding finding)
    {
        var category = Enum.TryParse<FindingCategory>(
            finding.Category,
            true,
            out var parsedCategory)
            ? parsedCategory
            : FindingCategory.SuspiciousProcess;

        var severity = Enum.TryParse<FindingSeverity>(
            finding.Severity,
            true,
            out var parsedSeverity)
            ? parsedSeverity
            : FindingSeverity.Low;

        return new SubmitFindingRequest(
            category,
            severity,
            Limit(finding.Title, 200) ?? "Suspicious activity",
            Limit(finding.Description, 2000) ??
                "A suspicious activity indicator was detected.",
            Limit(finding.ProcessName, 255),
            finding.ProcessId,
            Limit(finding.FilePath, 1024),
            Limit(finding.CommandLine, 4000));
    }

    private static string? Limit(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var cleanValue = value.Trim();

        return cleanValue.Length <= maxLength
            ? cleanValue
            : cleanValue[..maxLength];
    }

    private static async Task<PowerShellTelemetryResult>
        RunPowerShellAsync(
            CancellationToken cancellationToken)
    {
        var encodedCommand = Convert.ToBase64String(
            Encoding.Unicode.GetBytes(PowerShellScript));

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments =
                $"-NoLogo -NoProfile -NonInteractive " +
                $"-EncodedCommand {encodedCommand}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process
        {
            StartInfo = startInfo
        };

        if (!process.Start())
        {
            throw new InvalidOperationException(
                "PowerShell could not be started.");
        }

        var outputTask =
            process.StandardOutput.ReadToEndAsync(
                cancellationToken);

        var errorTask =
            process.StandardError.ReadToEndAsync(
                cancellationToken);

        await process.WaitForExitAsync(cancellationToken);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Telemetry collection failed: {error}");
        }

        return JsonSerializer.Deserialize<
                   PowerShellTelemetryResult>(
                   output,
                   new JsonSerializerOptions
                   {
                       PropertyNameCaseInsensitive = true
                   })
               ?? throw new InvalidOperationException(
                   "PowerShell returned no telemetry.");
    }

    private sealed record PowerShellTelemetryResult(
        int ProcessCount,
        int ActiveTcpConnectionCount,
        List<PowerShellFinding>? Findings);

    private sealed record PowerShellFinding(
        string Category,
        string Severity,
        string Title,
        string Description,
        string? ProcessName,
        int? ProcessId,
        string? FilePath,
        string? CommandLine);

    private const string PowerShellScript = """
        $processes = @(
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        )

        $connections = @(
            Get-NetTCPConnection `
                -State Established `
                -ErrorAction SilentlyContinue
        )

        $findings = @()

        foreach ($process in $processes) {
            if ($process.ProcessId -eq $PID) {
                continue
            }

            $name = [string]$process.Name
            $path = [string]$process.ExecutablePath
            $commandLine = [string]$process.CommandLine
            $nameLower = $name.ToLowerInvariant()

            $suspiciousCommand = $false
            $commandDescription = $null

            if (
                ($nameLower -eq 'powershell.exe' -or
                 $nameLower -eq 'pwsh.exe') -and
                $commandLine -match
                '(?i)(-enc(odedcommand)?\b|frombase64string|invoke-expression|\biex\b|downloadstring)'
            ) {
                $suspiciousCommand = $true
                $commandDescription =
                    'PowerShell is using an encoded or execution-related command.'
            }
            elseif (
                $nameLower -eq 'mshta.exe' -and
                $commandLine -match '(?i)https?://'
            ) {
                $suspiciousCommand = $true
                $commandDescription =
                    'MSHTA is referencing a remote URL.'
            }
            elseif (
                $nameLower -eq 'certutil.exe' -and
                $commandLine -match '(?i)(-urlcache|-decode)'
            ) {
                $suspiciousCommand = $true
                $commandDescription =
                    'CertUtil is being used to download or decode content.'
            }
            elseif (
                $nameLower -eq 'rundll32.exe' -and
                $commandLine -match '(?i)javascript:'
            ) {
                $suspiciousCommand = $true
                $commandDescription =
                    'Rundll32 is executing JavaScript content.'
            }
            elseif (
                $nameLower -eq 'regsvr32.exe' -and
                $commandLine -match '(?i)/i:https?://'
            ) {
                $suspiciousCommand = $true
                $commandDescription =
                    'Regsvr32 is referencing a remote URL.'
            }

            if ($suspiciousCommand) {
                $findings += [pscustomobject]@{
                    Category = 'SuspiciousCommandLine'
                    Severity = 'High'
                    Title = 'Suspicious command line detected'
                    Description = $commandDescription
                    ProcessName = $name
                    ProcessId = [int]$process.ProcessId
                    FilePath = $path
                    CommandLine = $commandLine
                }
            }

            if (
                -not [string]::IsNullOrWhiteSpace($path) -and
                $path -match
                '(?i)(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\)'
            ) {
                $findings += [pscustomobject]@{
                    Category = 'SuspiciousFileLocation'
                    Severity = 'Medium'
                    Title = 'Process running from a risky location'
                    Description =
                        'A running process was found inside a temporary or public directory.'
                    ProcessName = $name
                    ProcessId = [int]$process.ProcessId
                    FilePath = $path
                    CommandLine = $commandLine
                }
            }
        }

        [pscustomobject]@{
            ProcessCount = @($processes).Count
            ActiveTcpConnectionCount = @($connections).Count
            Findings = @($findings)
        } |
        ConvertTo-Json -Depth 6 -Compress
        """;
}

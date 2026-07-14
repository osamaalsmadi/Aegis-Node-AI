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
        var result = await RunPowerShellAsync(
            cancellationToken);

        var connections = (result.Connections ?? [])
            .Select(x => new SubmitNetworkConnectionRequest(
                "TCP",
                Limit(x.LocalAddress, 64) ?? "Unknown",
                x.LocalPort,
                Limit(x.RemoteAddress, 64) ?? "Unknown",
                x.RemotePort,
                Limit(x.State, 30) ?? "Unknown",
                x.ProcessId,
                Limit(x.ProcessName, 255)))
            .ToList();

        var findings = (result.Findings ?? [])
            .Select(ToFindingRequest)
            .ToList();

        logger.LogInformation(
            "Telemetry collected: {Processes} processes, " +
            "{Connections} connections, {Findings} findings.",
            result.ProcessCount,
            connections.Count,
            findings.Count);

        return new SubmitEndpointTelemetryRequest(
            deviceId,
            result.ProcessCount,
            result.ActiveTcpConnectionCount,
            connections,
            findings);
    }

    private static SubmitFindingRequest ToFindingRequest(
        PowerShellFinding finding)
    {
        Enum.TryParse<FindingCategory>(
            finding.Category,
            true,
            out var category);

        Enum.TryParse<FindingSeverity>(
            finding.Severity,
            true,
            out var severity);

        return new SubmitFindingRequest(
            category,
            severity,
            Limit(finding.Title, 200) ??
                "Suspicious activity",
            Limit(finding.Description, 2000) ??
                "Suspicious activity detected.",
            Limit(finding.ProcessName, 255),
            finding.ProcessId,
            Limit(finding.FilePath, 1024),
            Limit(finding.CommandLine, 4000));
    }

    private static string? Limit(string? value, int length)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var clean = value.Trim();

        return clean.Length <= length
            ? clean
            : clean[..length];
    }

    private static async Task<PowerShellTelemetryResult>
        RunPowerShellAsync(
            CancellationToken cancellationToken)
    {
        var encoded = Convert.ToBase64String(
            Encoding.Unicode.GetBytes(PowerShellScript));

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments =
                "-NoLogo -NoProfile -NonInteractive " +
                $"-EncodedCommand {encoded}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process
        {
            StartInfo = startInfo
        };

        process.Start();

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
            throw new InvalidOperationException(error);

        return JsonSerializer.Deserialize<
                   PowerShellTelemetryResult>(
                   output,
                   new JsonSerializerOptions
                   {
                       PropertyNameCaseInsensitive = true
                   })
               ?? throw new InvalidOperationException(
                   "No telemetry was returned.");
    }

    private sealed record PowerShellTelemetryResult(
        int ProcessCount,
        int ActiveTcpConnectionCount,
        List<PowerShellConnection>? Connections,
        List<PowerShellFinding>? Findings);

    private sealed record PowerShellConnection(
        string? LocalAddress,
        int LocalPort,
        string? RemoteAddress,
        int RemotePort,
        string? State,
        int ProcessId,
        string? ProcessName);

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
            Get-CimInstance Win32_Process `
                -ErrorAction SilentlyContinue
        )

        $connections = @(
            Get-NetTCPConnection `
                -State Established `
                -ErrorAction SilentlyContinue |
            Select-Object -First 200
        )

        $processMap = @{}

        foreach ($process in $processes) {
            $processMap[[int]$process.ProcessId] =
                [string]$process.Name
        }

        $connectionItems = @()

        foreach ($connection in $connections) {
            $ownerId = [int]$connection.OwningProcess
            $ownerName = $processMap[$ownerId]

            $connectionItems += [pscustomobject]@{
                LocalAddress =
                    [string]$connection.LocalAddress

                LocalPort =
                    [int]$connection.LocalPort

                RemoteAddress =
                    [string]$connection.RemoteAddress

                RemotePort =
                    [int]$connection.RemotePort

                State =
                    [string]$connection.State

                ProcessId =
                    $ownerId

                ProcessName =
                    $ownerName
            }
        }

        $findings = @()

        foreach ($process in $processes) {
            if ($process.ProcessId -eq $PID) {
                continue
            }

            $name = [string]$process.Name
            $path = [string]$process.ExecutablePath
            $commandLine = [string]$process.CommandLine
            $nameLower = $name.ToLowerInvariant()

            $description = $null

            if (
                ($nameLower -eq 'powershell.exe' -or
                 $nameLower -eq 'pwsh.exe') -and
                $commandLine -match
                '(?i)(-enc(odedcommand)?\b|frombase64string|invoke-expression|\biex\b|downloadstring)'
            ) {
                $description =
                    'PowerShell is using an encoded or execution-related command.'
            }
            elseif (
                $nameLower -eq 'mshta.exe' -and
                $commandLine -match '(?i)https?://'
            ) {
                $description =
                    'MSHTA is referencing a remote URL.'
            }
            elseif (
                $nameLower -eq 'certutil.exe' -and
                $commandLine -match
                '(?i)(-urlcache|-decode)'
            ) {
                $description =
                    'CertUtil is downloading or decoding content.'
            }
            elseif (
                $nameLower -eq 'rundll32.exe' -and
                $commandLine -match '(?i)javascript:'
            ) {
                $description =
                    'Rundll32 is executing JavaScript.'
            }
            elseif (
                $nameLower -eq 'regsvr32.exe' -and
                $commandLine -match '(?i)/i:https?://'
            ) {
                $description =
                    'Regsvr32 is referencing a remote URL.'
            }

            if ($null -ne $description) {
                $findings += [pscustomobject]@{
                    Category =
                        'SuspiciousCommandLine'

                    Severity =
                        'High'

                    Title =
                        'Suspicious command line detected'

                    Description =
                        $description

                    ProcessName =
                        $name

                    ProcessId =
                        [int]$process.ProcessId

                    FilePath =
                        $path

                    CommandLine =
                        $commandLine
                }
            }

            if (
                -not [string]::IsNullOrWhiteSpace($path) -and
                $path -match
                '(?i)(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\)'
            ) {
                $signatureStatus = 'Unavailable'
                $signerSubject = 'No publisher'

                try {
                    $signature =
                        Get-AuthenticodeSignature `
                            -FilePath $path `
                            -ErrorAction Stop

                    $signatureStatus =
                        [string]$signature.Status

                    if (
                        $null -ne
                        $signature.SignerCertificate
                    ) {
                        $signerSubject =
                            [string]$signature
                                .SignerCertificate
                                .Subject
                    }
                }
                catch {
                    $signatureStatus = 'Unavailable'
                }

                $findingDescription =
                    'A process is running from a temporary or public directory. ' +
                    "Digital signature: $signatureStatus. " +
                    "Publisher: $signerSubject."

                $findings += [pscustomobject]@{
                    Category =
                        'SuspiciousFileLocation'

                    Severity =
                        'Medium'

                    Title =
                        'Process running from a risky location'

                    Description =
                        $findingDescription

                    ProcessName =
                        $name

                    ProcessId =
                        [int]$process.ProcessId

                    FilePath =
                        $path

                    CommandLine =
                        $commandLine
                }
            }
        }

        [pscustomobject]@{
            ProcessCount =
                @($processes).Count

            ActiveTcpConnectionCount =
                @($connections).Count

            Connections =
                @($connectionItems)

            Findings =
                @($findings)
        } |
        ConvertTo-Json -Depth 7 -Compress
        """;
}


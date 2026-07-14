using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace EndpointSecurity.Agent.Services;

public sealed class DefenderMaintenanceService(
    ILogger<DefenderMaintenanceService> logger)
{
    public async Task<string> UpdateSignaturesAsync(
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Microsoft Defender signature update started.");

        var output = await RunPowerShellAsync(
            UpdateSignaturesScript,
            cancellationToken);

        var result =
            JsonSerializer.Deserialize<MaintenanceResult>(
                output,
                JsonOptions)
            ?? throw new InvalidOperationException(
                "Defender returned no signature update result.");

        logger.LogInformation(
            "Microsoft Defender signature update completed.");

        return result.Message;
    }

    public async Task<string> RemediateThreatsAsync(
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Microsoft Defender threat remediation started.");

        var output = await RunPowerShellAsync(
            RemediationScript,
            cancellationToken);

        var result =
            JsonSerializer.Deserialize<MaintenanceResult>(
                output,
                JsonOptions)
            ?? throw new InvalidOperationException(
                "Defender returned no remediation result.");

        logger.LogInformation(
            "Microsoft Defender remediation completed.");

        return result.Message;
    }

    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            PropertyNameCaseInsensitive = true
        };

    private static async Task<string> RunPowerShellAsync(
        string script,
        CancellationToken cancellationToken)
    {
        var encodedCommand = Convert.ToBase64String(
            Encoding.Unicode.GetBytes(script));

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments =
                "-NoLogo -NoProfile -NonInteractive " +
                "-OutputFormat Text " +
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
                $"Defender maintenance failed: {error.Trim()}");
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            throw new InvalidOperationException(
                "Defender returned an empty maintenance result.");
        }

        return output;
    }

    private sealed record MaintenanceResult(
        string Message);

    private const string UpdateSignaturesScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'

        Update-MpSignature -ErrorAction Stop

        $status = Get-MpComputerStatus

        $updatedAt = if (
            $null -ne $status.AntivirusSignatureLastUpdated
        ) {
            ([DateTime]$status.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd HH:mm:ss')
        }
        else {
            'Unknown'
        }

        [pscustomobject]@{
            Message =
                "Microsoft Defender signatures updated successfully. Last updated: $updatedAt"
        } |
        ConvertTo-Json -Compress
        """;

    private const string RemediationScript = """
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'SilentlyContinue'

        $threatsBefore = @(
            Get-MpThreat -ErrorAction SilentlyContinue
        )

        if ($threatsBefore.Count -gt 0) {
            Remove-MpThreat -ErrorAction Stop
            Start-Sleep -Seconds 2
        }

        $threatsAfter = @(
            Get-MpThreat -ErrorAction SilentlyContinue
        )

        [pscustomobject]@{
            Message =
                "Defender remediation completed. Threat records before: $($threatsBefore.Count). Remaining active records: $($threatsAfter.Count)."
        } |
        ConvertTo-Json -Compress
        """;
}



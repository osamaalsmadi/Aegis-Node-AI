using System.Diagnostics;
using System.Text;
using System.Text.Json;
using EndpointSecurity.Application.SecurityPosture;

namespace EndpointSecurity.Agent.Services;

public sealed class WindowsSecurityCollector(
    ILogger<WindowsSecurityCollector> logger)
{
    public async Task<SubmitSecurityPostureRequest> CollectAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SubmitSecurityPostureRequest(
                deviceId,
                null,
                null,
                null,
                null,
                null,
                null,
                null);
        }

        var result = await RunPowerShellAsync(
            cancellationToken);

        logger.LogInformation(
            "Windows security information collected.");

        return new SubmitSecurityPostureRequest(
            deviceId,
            result.DefenderEnabled,
            result.RealTimeProtectionEnabled,
            result.AntivirusSignatureAgeDays,
            result.FirewallDomainEnabled,
            result.FirewallPrivateEnabled,
            result.FirewallPublicEnabled,
            result.RebootRequired);
    }

    private static async Task<PowerShellSecurityResult>
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
                $"Security collection failed: {error}");
        }

        var result =
            JsonSerializer.Deserialize<PowerShellSecurityResult>(
                output,
                new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

        return result
            ?? throw new InvalidOperationException(
                "PowerShell returned no security information.");
    }

    private sealed record PowerShellSecurityResult(
        bool? DefenderEnabled,
        bool? RealTimeProtectionEnabled,
        int? AntivirusSignatureAgeDays,
        bool? FirewallDomainEnabled,
        bool? FirewallPrivateEnabled,
        bool? FirewallPublicEnabled,
        bool? RebootRequired);

    private const string PowerShellScript = """
        $defenderEnabled = $null
        $realTimeProtectionEnabled = $null
        $antivirusSignatureAgeDays = $null
        $firewallDomainEnabled = $null
        $firewallPrivateEnabled = $null
        $firewallPublicEnabled = $null

        try {
            $defender = Get-MpComputerStatus -ErrorAction Stop

            $defenderEnabled =
                [bool]$defender.AntivirusEnabled

            $realTimeProtectionEnabled =
                [bool]$defender.RealTimeProtectionEnabled

            $antivirusSignatureAgeDays =
                [int]$defender.AntivirusSignatureAge
        }
        catch {
        }

        try {
            $profiles =
                Get-NetFirewallProfile -ErrorAction Stop

            $domainProfile = $profiles |
                Where-Object { $_.Name -eq 'Domain' } |
                Select-Object -First 1

            $privateProfile = $profiles |
                Where-Object { $_.Name -eq 'Private' } |
                Select-Object -First 1

            $publicProfile = $profiles |
                Where-Object { $_.Name -eq 'Public' } |
                Select-Object -First 1

            if ($null -ne $domainProfile) {
                $firewallDomainEnabled =
                    [bool]$domainProfile.Enabled
            }

            if ($null -ne $privateProfile) {
                $firewallPrivateEnabled =
                    [bool]$privateProfile.Enabled
            }

            if ($null -ne $publicProfile) {
                $firewallPublicEnabled =
                    [bool]$publicProfile.Enabled
            }
        }
        catch {
        }

        $rebootRequired =
            (Test-Path `
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') `
            -or `
            (Test-Path `
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

        [pscustomobject]@{
            DefenderEnabled =
                $defenderEnabled

            RealTimeProtectionEnabled =
                $realTimeProtectionEnabled

            AntivirusSignatureAgeDays =
                $antivirusSignatureAgeDays

            FirewallDomainEnabled =
                $firewallDomainEnabled

            FirewallPrivateEnabled =
                $firewallPrivateEnabled

            FirewallPublicEnabled =
                $firewallPublicEnabled

            RebootRequired =
                [bool]$rebootRequired
        } |
        ConvertTo-Json -Compress
        """;
}

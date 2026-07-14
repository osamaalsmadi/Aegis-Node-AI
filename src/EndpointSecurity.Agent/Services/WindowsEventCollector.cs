using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using EndpointSecurity.Application.SecurityEvents;

namespace EndpointSecurity.Agent.Services;

public sealed class WindowsEventCollector(
    ILogger<WindowsEventCollector> logger)
{
    public async Task<
        SubmitWindowsSecurityEventBatchRequest>
        CollectAsync(
            Guid deviceId,
            int lookbackMinutes,
            CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new SubmitWindowsSecurityEventBatchRequest(
                deviceId,
                Array.Empty<
                    SubmitWindowsSecurityEventRequest>());
        }

        var safeLookback = Math.Clamp(
            lookbackMinutes,
            5,
            10_080);

        var script = PowerShellScript.Replace(
            "__LOOKBACK_MINUTES__",
            safeLookback.ToString(
                CultureInfo.InvariantCulture),
            StringComparison.Ordinal);

        var result = await RunPowerShellAsync(
            script,
            cancellationToken);

        var events = (result.Events ?? [])
            .Where(x =>
                !string.IsNullOrWhiteSpace(
                    x.EventKey))
            .Select(x =>
                new SubmitWindowsSecurityEventRequest(
                    Limit(
                        x.EventKey,
                        300,
                        "Unknown event"),
                    Limit(
                        x.ProviderName,
                        255,
                        "Unknown provider"),
                    Limit(
                        x.LogName,
                        255,
                        "Unknown log"),
                    x.EventId,
                    Limit(
                        x.Level,
                        30,
                        "Information"),
                    Limit(
                        x.Severity,
                        30,
                        "Informational"),
                    Limit(
                        x.Category,
                        100,
                        "System"),
                    Limit(
                        x.Title,
                        255,
                        "Windows security event"),
                    Limit(
                        x.Message,
                        4000,
                        "Event message was unavailable."),
                    x.RecordId,
                    x.OccurredAtUtc))
            .ToList();

        logger.LogInformation(
            "Windows Event Log collection completed. " +
            "Security events found: {EventCount}.",
            events.Count);

        return new SubmitWindowsSecurityEventBatchRequest(
            deviceId,
            events);
    }

    private static async Task<
        PowerShellEventResult>
        RunPowerShellAsync(
            string script,
            CancellationToken cancellationToken)
    {
        var encodedCommand =
            Convert.ToBase64String(
                Encoding.Unicode.GetBytes(script));

        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments =
                "-NoLogo -NoProfile -NonInteractive " +
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

        await process.WaitForExitAsync(
            cancellationToken);

        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Windows event collection failed: {error}");
        }

        return JsonSerializer.Deserialize<
                   PowerShellEventResult>(
                   output,
                   new JsonSerializerOptions
                   {
                       PropertyNameCaseInsensitive = true
                   })
               ?? new PowerShellEventResult([]);
    }

    private static string Limit(
        string? value,
        int maximumLength,
        string fallback)
    {
        var result =
            string.IsNullOrWhiteSpace(value)
                ? fallback
                : value.Trim();

        return result.Length <= maximumLength
            ? result
            : result[..maximumLength];
    }

    private sealed record PowerShellEventResult(
        List<PowerShellSecurityEvent>? Events);

    private sealed record PowerShellSecurityEvent(
        string EventKey,
        string ProviderName,
        string LogName,
        int EventId,
        string Level,
        string Severity,
        string Category,
        string Title,
        string Message,
        long RecordId,
        DateTime OccurredAtUtc);

    private const string PowerShellScript = """
        $ErrorActionPreference = 'Stop'

        $startTime =
            (Get-Date).AddMinutes(
                -__LOOKBACK_MINUTES__
            )

        $queries = @(
            [pscustomobject]@{
                LogName = 'Security'
                EventIds = @(
                    4625,
                    4720,
                    4732,
                    1102
                )
            }

            [pscustomobject]@{
                LogName = 'System'
                EventIds = @(
                    7045
                )
            }

            [pscustomobject]@{
                LogName =
                    'Microsoft-Windows-Windows Defender/Operational'

                EventIds = @(
                    1116,
                    1117,
                    5007
                )
            }
        )

        $results = @()

        foreach ($query in $queries) {
            try {
                $events = @(
                    Get-WinEvent `
                        -FilterHashtable @{
                            LogName =
                                [string]$query.LogName

                            Id =
                                [int[]]$query.EventIds

                            StartTime =
                                $startTime
                        } `
                        -MaxEvents 200 `
                        -ErrorAction Stop
                )
            }
            catch {
                continue
            }

            foreach ($event in $events) {
                $severity = 'Low'
                $category = 'System'
                $title =
                    "Windows event $($event.Id)"

                switch ([int]$event.Id) {
                    4625 {
                        $severity = 'Medium'
                        $category = 'Authentication'
                        $title =
                            'Failed Windows sign-in'
                    }

                    4720 {
                        $severity = 'High'
                        $category = 'Account Management'
                        $title =
                            'Windows account created'
                    }

                    4732 {
                        $severity = 'High'
                        $category = 'Privilege Change'
                        $title =
                            'Member added to a local security group'
                    }

                    1102 {
                        $severity = 'Critical'
                        $category = 'Audit'
                        $title =
                            'Windows audit log was cleared'
                    }

                    7045 {
                        $severity = 'High'
                        $category = 'Persistence'
                        $title =
                            'New Windows service installed'
                    }

                    1116 {
                        $severity = 'Critical'
                        $category = 'Malware'
                        $title =
                            'Microsoft Defender detected malware'
                    }

                    1117 {
                        $severity = 'Medium'
                        $category = 'Malware'
                        $title =
                            'Microsoft Defender remediation action'
                    }

                    5007 {
                        $severity = 'Medium'
                        $category = 'Protection Change'
                        $title =
                            'Microsoft Defender configuration changed'
                    }
                }

                try {
                    $message =
                        [string]$event.Message
                }
                catch {
                    $message =
                        'Windows could not format the event message.'
                }

                if (
                    [string]::IsNullOrWhiteSpace(
                        $message
                    )
                ) {
                    $message =
                        'Event message was unavailable.'
                }

                $message = [regex]::Replace(
                    $message,
                    '\s+',
                    ' '
                ).Trim()

                if ($message.Length -gt 4000) {
                    $message =
                        $message.Substring(0, 4000)
                }

                $provider =
                    [string]$event.ProviderName

                if (
                    [string]::IsNullOrWhiteSpace(
                        $provider
                    )
                ) {
                    $provider = 'Unknown provider'
                }

                $logName =
                    [string]$event.LogName

                $recordId =
                    [long]$event.RecordId

                $eventKey =
                    "$logName|$recordId"

                $occurredAtUtc =
                    ([DateTime]$event.TimeCreated).ToUniversalTime().ToString('O')

                $results += [pscustomobject]@{
                    EventKey =
                        $eventKey

                    ProviderName =
                        $provider

                    LogName =
                        $logName

                    EventId =
                        [int]$event.Id

                    Level =
                        [string]$event.LevelDisplayName

                    Severity =
                        $severity

                    Category =
                        $category

                    Title =
                        $title

                    Message =
                        $message

                    RecordId =
                        $recordId

                    OccurredAtUtc =
                        $occurredAtUtc
                }
            }
        }

        [pscustomobject]@{
            Events =
                @($results)
        } |
        ConvertTo-Json -Depth 7 -Compress
        """;
}

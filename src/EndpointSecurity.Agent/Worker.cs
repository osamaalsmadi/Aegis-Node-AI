using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.InteropServices;
using EndpointSecurity.Agent.Services;
using EndpointSecurity.Application.Devices;
using EndpointSecurity.Application.SecurityPosture;
using EndpointSecurity.Application.Telemetry;
using Microsoft.Win32;

namespace EndpointSecurity.Agent;

public sealed class Worker(
    ILogger<Worker> logger,
    HttpClient httpClient,
    DeviceIdentityProvider identityProvider,
    WindowsSecurityCollector securityCollector,
    EndpointTelemetryCollector telemetryCollector,
    DefenderMalwareScanner malwareScanner,
    IConfiguration configuration) : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var heartbeatInterval = TimeSpan.FromSeconds(
            Math.Max(
                10,
                configuration.GetValue(
                    "Agent:HeartbeatIntervalSeconds",
                    60)));

        var securityScanInterval = TimeSpan.FromSeconds(
            Math.Max(
                60,
                configuration.GetValue(
                    "Agent:SecurityScanIntervalSeconds",
                    300)));

        var telemetryScanInterval = TimeSpan.FromSeconds(
            Math.Max(
                60,
                configuration.GetValue(
                    "Agent:TelemetryScanIntervalSeconds",
                    300)));

        var malwareScanInterval = TimeSpan.FromHours(
            Math.Max(
                1,
                configuration.GetValue(
                    "Agent:MalwareScanIntervalHours",
                    24)));

        var deviceId =
            identityProvider.GetOrCreateDeviceId();

        var nextSecurityScanUtc = DateTime.MinValue;
        var nextTelemetryScanUtc = DateTime.MinValue;
        var nextMalwareScanUtc = DateTime.MinValue;

        IReadOnlyList<SubmitFindingRequest>
            pendingMalwareFindings =
                Array.Empty<SubmitFindingRequest>();

        logger.LogInformation(
            "Endpoint Security Agent started with ID {DeviceId}.",
            deviceId);

        while (!stoppingToken.IsCancellationRequested)
        {
            var registered = await RegisterDeviceAsync(
                deviceId,
                stoppingToken);

            if (registered &&
                DateTime.UtcNow >= nextSecurityScanUtc)
            {
                if (await SubmitSecurityPostureAsync(
                        deviceId,
                        stoppingToken))
                {
                    nextSecurityScanUtc =
                        DateTime.UtcNow.Add(
                            securityScanInterval);
                }
            }

            if (registered &&
                DateTime.UtcNow >= nextMalwareScanUtc)
            {
                pendingMalwareFindings =
                    await RunMalwareScanAsync(
                        stoppingToken);

                nextMalwareScanUtc =
                    DateTime.UtcNow.Add(
                        malwareScanInterval);
            }

            if (registered &&
                DateTime.UtcNow >= nextTelemetryScanUtc)
            {
                var submitted = await SubmitTelemetryAsync(
                    deviceId,
                    pendingMalwareFindings,
                    stoppingToken);

                if (submitted)
                {
                    pendingMalwareFindings =
                        Array.Empty<SubmitFindingRequest>();

                    nextTelemetryScanUtc =
                        DateTime.UtcNow.Add(
                            telemetryScanInterval);
                }
            }

            try
            {
                await Task.Delay(
                    heartbeatInterval,
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task<bool> RegisterDeviceAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        try
        {
            var request = new RegisterDeviceRequest(
                deviceId,
                Environment.MachineName,
                GetOperatingSystemName(),
                Environment.OSVersion.Version.ToString(),
                RuntimeInformation.OSArchitecture.ToString(),
                GetAgentVersion());

            using var response = await httpClient.PostAsJsonAsync(
                "api/devices/register",
                request,
                cancellationToken);

            response.EnsureSuccessStatusCode();

            logger.LogInformation(
                "Device registration heartbeat sent.");

            return true;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Agent could not register with the API.");

            return false;
        }
    }

    private async Task<bool> SubmitSecurityPostureAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        try
        {
            var request = await securityCollector.CollectAsync(
                deviceId,
                cancellationToken);

            using var response = await httpClient.PostAsJsonAsync(
                "api/security-posture",
                request,
                cancellationToken);

            response.EnsureSuccessStatusCode();

            var result = await response.Content
                .ReadFromJsonAsync<SecurityPostureResponse>(
                    cancellationToken);

            logger.LogInformation(
                "Security posture submitted. Risk score: {RiskScore}.",
                result?.RiskScore);

            return true;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Security posture submission failed.");

            return false;
        }
    }

    private async Task<
        IReadOnlyList<SubmitFindingRequest>>
        RunMalwareScanAsync(
            CancellationToken cancellationToken)
    {
        try
        {
            return await malwareScanner.RunQuickScanAsync(
                cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Microsoft Defender Quick Scan failed.");

            return Array.Empty<SubmitFindingRequest>();
        }
    }

    private async Task<bool> SubmitTelemetryAsync(
        Guid deviceId,
        IReadOnlyList<SubmitFindingRequest>
            additionalFindings,
        CancellationToken cancellationToken)
    {
        try
        {
            var request = await telemetryCollector.CollectAsync(
                deviceId,
                cancellationToken);

            var combinedFindings = request.Findings
                .Concat(additionalFindings)
                .ToList();

            var combinedRequest = request with
            {
                Findings = combinedFindings
            };

            using var response = await httpClient.PostAsJsonAsync(
                "api/telemetry",
                combinedRequest,
                cancellationToken);

            response.EnsureSuccessStatusCode();

            var result = await response.Content
                .ReadFromJsonAsync<EndpointTelemetryResponse>(
                    cancellationToken);

            logger.LogInformation(
                "Telemetry submitted. Processes: {Processes}, " +
                "connections: {Connections}, findings: {Findings}, " +
                "risk score: {RiskScore}.",
                result?.ProcessCount,
                result?.ActiveTcpConnectionCount,
                result?.Findings.Count,
                result?.RiskScore);

            return true;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Telemetry submission failed.");

            return false;
        }
    }

    private static string GetOperatingSystemName()
    {
        if (!OperatingSystem.IsWindows())
            return RuntimeInformation.OSDescription;

        const string registryKey =
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

        var productName = Registry.GetValue(
                registryKey,
                "ProductName",
                "Microsoft Windows")
            ?.ToString()
            ?? "Microsoft Windows";

        if (Environment.OSVersion.Version.Build >= 22000)
        {
            productName = productName.Replace(
                "Windows 10",
                "Windows 11",
                StringComparison.OrdinalIgnoreCase);
        }

        return productName;
    }

    private static string GetAgentVersion()
    {
        return Assembly.GetExecutingAssembly()
                   .GetName()
                   .Version?
                   .ToString(3)
               ?? "1.0.0";
    }
}

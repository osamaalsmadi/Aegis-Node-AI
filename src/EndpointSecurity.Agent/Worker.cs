using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.InteropServices;
using EndpointSecurity.Agent.Services;
using EndpointSecurity.Application.Devices;
using EndpointSecurity.Application.SecurityPosture;
using Microsoft.Win32;

namespace EndpointSecurity.Agent;

public sealed class Worker(
    ILogger<Worker> logger,
    HttpClient httpClient,
    DeviceIdentityProvider identityProvider,
    WindowsSecurityCollector securityCollector,
    IConfiguration configuration) : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var heartbeatSeconds = Math.Max(
            10,
            configuration.GetValue(
                "Agent:HeartbeatIntervalSeconds",
                60));

        var securityScanSeconds = Math.Max(
            60,
            configuration.GetValue(
                "Agent:SecurityScanIntervalSeconds",
                300));

        var heartbeatInterval =
            TimeSpan.FromSeconds(heartbeatSeconds);

        var securityScanInterval =
            TimeSpan.FromSeconds(securityScanSeconds);

        var deviceId =
            identityProvider.GetOrCreateDeviceId();

        var nextSecurityScanUtc = DateTime.MinValue;

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
                var submitted = await SubmitSecurityPostureAsync(
                    deviceId,
                    stoppingToken);

                if (submitted)
                {
                    nextSecurityScanUtc =
                        DateTime.UtcNow.Add(
                            securityScanInterval);
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

            var result =
                await response.Content.ReadFromJsonAsync<
                    SecurityPostureResponse>(
                    cancellationToken);

            logger.LogInformation(
                "Security posture submitted. Risk score: {RiskScore}.",
                result?.RiskScore);

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
                "Security posture submission failed.");

            return false;
        }
    }

    private static string GetOperatingSystemName()
    {
        if (!OperatingSystem.IsWindows())
        {
            return RuntimeInformation.OSDescription;
        }

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

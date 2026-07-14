using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.InteropServices;
using EndpointSecurity.Agent.Services;
using EndpointSecurity.Application.Devices;
using Microsoft.Win32;

namespace EndpointSecurity.Agent;

public sealed class Worker(
    ILogger<Worker> logger,
    HttpClient httpClient,
    DeviceIdentityProvider identityProvider,
    IConfiguration configuration) : BackgroundService
{
    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var intervalSeconds = Math.Max(
            10,
            configuration.GetValue(
                "Agent:HeartbeatIntervalSeconds",
                60));

        var interval = TimeSpan.FromSeconds(intervalSeconds);

        logger.LogInformation(
            "Endpoint Security Agent started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            await RegisterDeviceAsync(stoppingToken);

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task RegisterDeviceAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var deviceId = identityProvider.GetOrCreateDeviceId();

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
                "Device {DeviceId} registered successfully at {Time}.",
                deviceId,
                DateTimeOffset.Now);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Agent could not contact the API. It will retry.");
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

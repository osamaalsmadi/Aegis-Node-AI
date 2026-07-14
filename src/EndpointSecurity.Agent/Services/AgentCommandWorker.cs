using System.Net;
using System.Net.Http.Json;

namespace EndpointSecurity.Agent.Services;

public sealed class AgentCommandWorker(
    HttpClient httpClient,
    DeviceIdentityProvider deviceIdentityProvider,
    DefenderMalwareScanner defenderMalwareScanner,
    ILogger<AgentCommandWorker> logger)
    : BackgroundService
{
    private static readonly TimeSpan PollInterval =
        TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var deviceId =
            deviceIdentityProvider.GetOrCreateDeviceId();

        logger.LogInformation(
            "Agent command worker started for device {DeviceId}.",
            deviceId);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessNextCommandAsync(
                    deviceId,
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(
                    exception,
                    "Agent command polling failed.");
            }

            try
            {
                await Task.Delay(
                    PollInterval,
                    stoppingToken);
            }
            catch (OperationCanceledException)
                when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private async Task ProcessNextCommandAsync(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        using var pendingResponse =
            await httpClient.GetAsync(
                $"api/agent-commands/devices/" +
                $"{deviceId}/pending",
                cancellationToken);

        if (pendingResponse.StatusCode ==
            HttpStatusCode.NoContent)
        {
            return;
        }

        pendingResponse.EnsureSuccessStatusCode();

        var command =
            await pendingResponse.Content
                .ReadFromJsonAsync<AgentCommandMessage>(
                    cancellationToken);

        if (command is null)
        {
            return;
        }

        logger.LogInformation(
            "Agent command {CommandId} received. Type: {Type}.",
            command.Id,
            command.Type);

        using var startResponse =
            await httpClient.PostAsync(
                $"api/agent-commands/{command.Id}/start",
                null,
                cancellationToken);

        startResponse.EnsureSuccessStatusCode();

        try
        {
            if (!string.Equals(
                command.Type,
                "DefenderQuickScan",
                StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Unsupported command type: {command.Type}");
            }

            var findings =
                await defenderMalwareScanner.RunQuickScanAsync(
                    cancellationToken);

            var resultMessage =
                findings.Count == 0
                    ? "Microsoft Defender Quick Scan completed. " +
                      "No threats were detected."
                    : "Microsoft Defender Quick Scan completed. " +
                      $"{findings.Count} threat(s) were detected.";

            using var completeResponse =
                await httpClient.PostAsJsonAsync(
                    $"api/agent-commands/" +
                    $"{command.Id}/complete",
                    new CompleteCommandRequest(
                        findings.Count,
                        resultMessage),
                    cancellationToken);

            completeResponse.EnsureSuccessStatusCode();

            logger.LogInformation(
                "Agent command {CommandId} completed. " +
                "Threats detected: {ThreatCount}.",
                command.Id,
                findings.Count);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            await TryReportFailureAsync(
                command.Id,
                exception,
                cancellationToken);

            throw;
        }
    }

    private async Task TryReportFailureAsync(
        Guid commandId,
        Exception exception,
        CancellationToken cancellationToken)
    {
        try
        {
            using var failureResponse =
                await httpClient.PostAsJsonAsync(
                    $"api/agent-commands/{commandId}/fail",
                    new FailCommandRequest(
                        exception.Message),
                    cancellationToken);

            failureResponse.EnsureSuccessStatusCode();
        }
        catch (Exception reportException)
        {
            logger.LogError(
                reportException,
                "Could not report failure for command {CommandId}.",
                commandId);
        }
    }

    private sealed record AgentCommandMessage(
        Guid Id,
        Guid DeviceId,
        string Type,
        string Status);

    private sealed record CompleteCommandRequest(
        int ThreatCount,
        string ResultMessage);

    private sealed record FailCommandRequest(
        string ErrorMessage);
}

using System.Net;
using System.Net.Http.Json;

namespace EndpointSecurity.Agent.Services;

public sealed class AgentCommandWorker(
    HttpClient httpClient,
    DeviceIdentityProvider deviceIdentityProvider,
    DefenderMalwareScanner defenderMalwareScanner,
    DefenderMaintenanceService defenderMaintenanceService,
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
            "Agent command {CommandId} received. " +
            "Type: {Type}.",
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
            var executionResult =
                await ExecuteCommandAsync(
                    command,
                    cancellationToken);

            using var completeResponse =
                await httpClient.PostAsJsonAsync(
                    $"api/agent-commands/" +
                    $"{command.Id}/complete",
                    new CompleteCommandRequest(
                        executionResult.ThreatCount,
                        executionResult.Message),
                    cancellationToken);

            completeResponse.EnsureSuccessStatusCode();

            logger.LogInformation(
                "Agent command {CommandId} completed.",
                command.Id);
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

    private async Task<CommandExecutionResult>
        ExecuteCommandAsync(
            AgentCommandMessage command,
            CancellationToken cancellationToken)
    {
        switch (command.Type)
        {
            case "DefenderQuickScan":
                return await ExecuteScanAsync(
                    DefenderScanKind.Quick,
                    null,
                    cancellationToken);

            case "DefenderFullScan":
                return await ExecuteScanAsync(
                    DefenderScanKind.Full,
                    null,
                    cancellationToken);

            case "DefenderCustomScan":
                return await ExecuteScanAsync(
                    DefenderScanKind.Custom,
                    command.TargetPath,
                    cancellationToken);

            case "DefenderUpdateSignatures":
            {
                var message =
                    await defenderMaintenanceService
                        .UpdateSignaturesAsync(
                            cancellationToken);

                return new CommandExecutionResult(
                    0,
                    message);
            }

            case "DefenderRemediateThreats":
            {
                var remediationMessage =
                    await defenderMaintenanceService
                        .RemediateThreatsAsync(
                            cancellationToken);

                var verification =
                    await defenderMalwareScanner.RunScanAsync(
                        DefenderScanKind.Quick,
                        null,
                        cancellationToken);

                var message =
                    $"{remediationMessage} " +
                    "Verification Quick Scan completed. " +
                    $"{verification.Count} threat(s) detected.";

                return new CommandExecutionResult(
                    verification.Count,
                    message);
            }

            default:
                throw new InvalidOperationException(
                    $"Unsupported command type: {command.Type}");
        }
    }

    private async Task<CommandExecutionResult>
        ExecuteScanAsync(
            DefenderScanKind scanKind,
            string? targetPath,
            CancellationToken cancellationToken)
    {
        var findings =
            await defenderMalwareScanner.RunScanAsync(
                scanKind,
                targetPath,
                cancellationToken);

        var scanLabel = scanKind switch
        {
            DefenderScanKind.Quick => "Quick Scan",
            DefenderScanKind.Full => "Full Scan",
            DefenderScanKind.Custom => "Custom Scan",
            _ => "Defender Scan"
        };

        var message =
            findings.Count == 0
                ? $"Microsoft Defender {scanLabel} " +
                  "completed. No threats were detected."
                : $"Microsoft Defender {scanLabel} " +
                  $"completed. {findings.Count} " +
                  "threat(s) were detected.";

        return new CommandExecutionResult(
            findings.Count,
            message);
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
        string? TargetPath,
        string Status);

    private sealed record CommandExecutionResult(
        int ThreatCount,
        string Message);

    private sealed record CompleteCommandRequest(
        int ThreatCount,
        string ResultMessage);

    private sealed record FailCommandRequest(
        string ErrorMessage);
}

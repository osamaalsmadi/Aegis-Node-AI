using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/agent-commands")]
public sealed class AgentCommandsController(
    EndpointSecurityDbContext dbContext) : ControllerBase
{
    [HttpPost("devices/{deviceId:guid}/scan")]
    public async Task<ActionResult<AgentCommandResponse>>
        RequestScan(
            Guid deviceId,
            RequestAgentScan request,
            CancellationToken cancellationToken)
    {
        if (!TryParseScanType(
            request.ScanType,
            out var commandType))
        {
            return BadRequest(
                "ScanType must be Quick, Full, or Custom.");
        }

        if (
            commandType ==
                AgentCommandType.DefenderCustomScan &&
            string.IsNullOrWhiteSpace(request.TargetPath))
        {
            return BadRequest(
                "A file or folder path is required " +
                "for a custom scan.");
        }

        return await QueueCommandAsync(
            deviceId,
            commandType,
            request.TargetPath,
            cancellationToken);
    }

    [HttpPost(
        "devices/{deviceId:guid}/defender-quick-scan")]
    public Task<ActionResult<AgentCommandResponse>>
        RequestDefenderQuickScan(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        return QueueCommandAsync(
            deviceId,
            AgentCommandType.DefenderQuickScan,
            null,
            cancellationToken);
    }

    [HttpPost(
        "devices/{deviceId:guid}/actions/update-signatures")]
    public Task<ActionResult<AgentCommandResponse>>
        UpdateDefenderSignatures(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        return QueueCommandAsync(
            deviceId,
            AgentCommandType.DefenderUpdateSignatures,
            null,
            cancellationToken);
    }

    [HttpPost(
        "devices/{deviceId:guid}/actions/remediate-threats")]
    public Task<ActionResult<AgentCommandResponse>>
        RemediateDefenderThreats(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        return QueueCommandAsync(
            deviceId,
            AgentCommandType.DefenderRemediateThreats,
            null,
            cancellationToken);
    }

    [HttpGet("devices/{deviceId:guid}/latest")]
    public async Task<ActionResult<AgentCommandResponse>>
        GetLatest(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var command =
            await dbContext.Set<AgentCommand>()
                .Where(x => x.DeviceId == deviceId)
                .OrderByDescending(x => x.RequestedAtUtc)
                .FirstOrDefaultAsync(cancellationToken);

        if (command is null)
        {
            return NotFound();
        }

        return Ok(ToResponse(command));
    }

    [HttpGet("devices/{deviceId:guid}/history")]
    public async Task<
        ActionResult<IReadOnlyList<AgentCommandResponse>>>
        GetHistory(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var commands =
            await dbContext.Set<AgentCommand>()
                .Where(x => x.DeviceId == deviceId)
                .OrderByDescending(x => x.RequestedAtUtc)
                .Take(100)
                .ToListAsync(cancellationToken);

        return Ok(commands.Select(ToResponse).ToList());
    }

    [HttpGet("devices/{deviceId:guid}/pending")]
    public async Task<ActionResult<AgentCommandResponse>>
        GetPending(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var command =
            await dbContext.Set<AgentCommand>()
                .Where(x =>
                    x.DeviceId == deviceId &&
                    x.Status == AgentCommandStatus.Pending)
                .OrderBy(x => x.RequestedAtUtc)
                .FirstOrDefaultAsync(cancellationToken);

        if (command is null)
        {
            return NoContent();
        }

        return Ok(ToResponse(command));
    }

    [HttpPost("{commandId:guid}/start")]
    public async Task<ActionResult<AgentCommandResponse>>
        Start(
            Guid commandId,
            CancellationToken cancellationToken)
    {
        var command =
            await FindCommandAsync(
                commandId,
                cancellationToken);

        if (command is null)
        {
            return NotFound();
        }

        if (command.Status == AgentCommandStatus.Pending)
        {
            command.MarkRunning();

            await dbContext.SaveChangesAsync(
                cancellationToken);
        }
        else if (
            command.Status != AgentCommandStatus.Running)
        {
            return Conflict(ToResponse(command));
        }

        return Ok(ToResponse(command));
    }

    [HttpPost("{commandId:guid}/complete")]
    public async Task<ActionResult<AgentCommandResponse>>
        Complete(
            Guid commandId,
            CompleteAgentCommandRequest request,
            CancellationToken cancellationToken)
    {
        var command =
            await FindCommandAsync(
                commandId,
                cancellationToken);

        if (command is null)
        {
            return NotFound();
        }

        if (command.Status == AgentCommandStatus.Completed)
        {
            return Ok(ToResponse(command));
        }

        if (command.Status == AgentCommandStatus.Failed)
        {
            return Conflict(ToResponse(command));
        }

        command.MarkCompleted(
            request.ThreatCount,
            request.ResultMessage);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return Ok(ToResponse(command));
    }

    [HttpPost("{commandId:guid}/fail")]
    public async Task<ActionResult<AgentCommandResponse>>
        Fail(
            Guid commandId,
            FailAgentCommandRequest request,
            CancellationToken cancellationToken)
    {
        var command =
            await FindCommandAsync(
                commandId,
                cancellationToken);

        if (command is null)
        {
            return NotFound();
        }

        if (command.Status == AgentCommandStatus.Failed)
        {
            return Ok(ToResponse(command));
        }

        if (command.Status == AgentCommandStatus.Completed)
        {
            return Conflict(ToResponse(command));
        }

        command.MarkFailed(request.ErrorMessage);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return Ok(ToResponse(command));
    }

    private async Task<ActionResult<AgentCommandResponse>>
        QueueCommandAsync(
            Guid deviceId,
            AgentCommandType type,
            string? targetPath,
            CancellationToken cancellationToken)
    {
        var deviceExists =
            await dbContext.Set<ManagedDevice>()
                .AnyAsync(
                    x => x.Id == deviceId,
                    cancellationToken);

        if (!deviceExists)
        {
            return NotFound(
                "The requested endpoint was not found.");
        }

        var existingCommand =
            await dbContext.Set<AgentCommand>()
                .Where(x =>
                    x.DeviceId == deviceId &&
                    (
                        x.Status ==
                            AgentCommandStatus.Pending ||
                        x.Status ==
                            AgentCommandStatus.Running
                    ))
                .OrderByDescending(x => x.RequestedAtUtc)
                .FirstOrDefaultAsync(cancellationToken);

        if (existingCommand is not null)
        {
            return Ok(ToResponse(existingCommand));
        }

        var command = new AgentCommand(
            deviceId,
            type,
            targetPath);

        dbContext.Add(command);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return Ok(ToResponse(command));
    }

    private Task<AgentCommand?> FindCommandAsync(
        Guid commandId,
        CancellationToken cancellationToken)
    {
        return dbContext.Set<AgentCommand>()
            .FirstOrDefaultAsync(
                x => x.Id == commandId,
                cancellationToken);
    }

    private static bool TryParseScanType(
        string? value,
        out AgentCommandType commandType)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case "quick":
            case "quickscan":
            case "defenderquickscan":
                commandType =
                    AgentCommandType.DefenderQuickScan;
                return true;

            case "full":
            case "fullscan":
            case "defenderfullscan":
                commandType =
                    AgentCommandType.DefenderFullScan;
                return true;

            case "custom":
            case "customscan":
            case "defendercustomscan":
                commandType =
                    AgentCommandType.DefenderCustomScan;
                return true;

            default:
                commandType = default;
                return false;
        }
    }

    private static AgentCommandResponse ToResponse(
        AgentCommand command)
    {
        return new AgentCommandResponse(
            command.Id,
            command.DeviceId,
            command.Type.ToString(),
            command.TargetPath,
            command.Status.ToString(),
            command.RequestedAtUtc,
            command.StartedAtUtc,
            command.CompletedAtUtc,
            command.ThreatCount,
            command.ResultMessage,
            command.ErrorMessage);
    }
}

public sealed record RequestAgentScan(
    string ScanType,
    string? TargetPath);

public sealed record CompleteAgentCommandRequest(
    int ThreatCount,
    string? ResultMessage);

public sealed record FailAgentCommandRequest(
    string? ErrorMessage);

public sealed record AgentCommandResponse(
    Guid Id,
    Guid DeviceId,
    string Type,
    string? TargetPath,
    string Status,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int? ThreatCount,
    string? ResultMessage,
    string? ErrorMessage);

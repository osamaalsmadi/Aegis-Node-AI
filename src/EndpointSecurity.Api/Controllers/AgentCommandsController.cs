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
    [HttpPost(
        "devices/{deviceId:guid}/defender-quick-scan")]
    public async Task<ActionResult<AgentCommandResponse>>
        RequestDefenderQuickScan(
            Guid deviceId,
            CancellationToken cancellationToken)
    {
        var existingCommand =
            await dbContext.Set<AgentCommand>()
                .Where(x =>
                    x.DeviceId == deviceId &&
                    x.Type ==
                        AgentCommandType.DefenderQuickScan &&
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
            AgentCommandType.DefenderQuickScan);

        dbContext.Add(command);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Ok(ToResponse(command));
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
            await dbContext.Set<AgentCommand>()
                .FirstOrDefaultAsync(
                    x => x.Id == commandId,
                    cancellationToken);

        if (command is null)
        {
            return NotFound();
        }

        if (command.Status == AgentCommandStatus.Pending)
        {
            command.MarkRunning();
            await dbContext.SaveChangesAsync(cancellationToken);
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
            await dbContext.Set<AgentCommand>()
                .FirstOrDefaultAsync(
                    x => x.Id == commandId,
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

        await dbContext.SaveChangesAsync(cancellationToken);

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
            await dbContext.Set<AgentCommand>()
                .FirstOrDefaultAsync(
                    x => x.Id == commandId,
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

        await dbContext.SaveChangesAsync(cancellationToken);

        return Ok(ToResponse(command));
    }

    private static AgentCommandResponse ToResponse(
        AgentCommand command)
    {
        return new AgentCommandResponse(
            command.Id,
            command.DeviceId,
            command.Type.ToString(),
            command.Status.ToString(),
            command.RequestedAtUtc,
            command.StartedAtUtc,
            command.CompletedAtUtc,
            command.ThreatCount,
            command.ResultMessage,
            command.ErrorMessage);
    }
}

public sealed record CompleteAgentCommandRequest(
    int ThreatCount,
    string? ResultMessage);

public sealed record FailAgentCommandRequest(
    string? ErrorMessage);

public sealed record AgentCommandResponse(
    Guid Id,
    Guid DeviceId,
    string Type,
    string Status,
    DateTime RequestedAtUtc,
    DateTime? StartedAtUtc,
    DateTime? CompletedAtUtc,
    int? ThreatCount,
    string? ResultMessage,
    string? ErrorMessage);

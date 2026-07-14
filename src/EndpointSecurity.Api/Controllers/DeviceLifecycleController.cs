using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/devices")]
public sealed class DeviceLifecycleController(
    EndpointSecurityDbContext dbContext)
    : ControllerBase
{
    [HttpDelete("{deviceId:guid}")]
    public async Task<IActionResult> RemoveOfflineDevice(
        Guid deviceId,
        CancellationToken cancellationToken)
    {
        var device = await dbContext.ManagedDevices
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.Id == deviceId,
                cancellationToken);

        if (device is null)
        {
            return NotFound(new
            {
                message = "Device was not found."
            });
        }

        var onlineThreshold =
            DateTime.UtcNow.AddMinutes(-3);

        if (device.LastSeenUtc >= onlineThreshold)
        {
            return Conflict(new
            {
                message =
                    "An online endpoint cannot be removed. " +
                    "Stop its agent or decommission it first."
            });
        }

        await using var transaction =
            await dbContext.Database.BeginTransactionAsync(
                cancellationToken);

        await dbContext.Database.ExecuteSqlInterpolatedAsync(
            $"""
            DELETE FROM [FindingReviews]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [AgentCommands]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [NetworkConnectionSnapshots]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [SecurityFindings]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [EndpointTelemetryScans]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [SecurityPostureSnapshots]
            WHERE [DeviceId] = {deviceId};

            DELETE FROM [ManagedDevices]
            WHERE [Id] = {deviceId};
            """,
            cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        return Ok(new
        {
            deviceId,
            status = "Removed",
            message =
                "The offline endpoint and its stored telemetry were removed."
        });
    }
}

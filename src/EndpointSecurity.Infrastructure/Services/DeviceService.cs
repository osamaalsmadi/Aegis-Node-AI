using EndpointSecurity.Application.Devices;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Services;

public sealed class DeviceService(
    EndpointSecurityDbContext dbContext) : IDeviceService
{
    public async Task<DeviceResponse> RegisterAsync(
        RegisterDeviceRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.DeviceId == Guid.Empty)
        {
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(request));
        }

        var device = await dbContext.ManagedDevices
            .SingleOrDefaultAsync(
                x => x.Id == request.DeviceId,
                cancellationToken);

        if (device is null)
        {
            device = new ManagedDevice(
                request.DeviceId,
                request.HostName,
                request.OperatingSystem,
                request.OperatingSystemVersion,
                request.Architecture,
                request.AgentVersion);

            await dbContext.ManagedDevices.AddAsync(
                device,
                cancellationToken);
        }
        else
        {
            device.UpdateInventory(
                request.HostName,
                request.OperatingSystem,
                request.OperatingSystemVersion,
                request.Architecture,
                request.AgentVersion);
        }

        device.UpdateHeartbeat(
            request.AgentVersion,
            DeviceStatus.Healthy,
            0);

        await dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(device);
    }

    public async Task<IReadOnlyList<DeviceResponse>> GetAllAsync(
        CancellationToken cancellationToken = default)
    {
        var devices = await dbContext.ManagedDevices
            .AsNoTracking()
            .OrderByDescending(x => x.LastSeenUtc)
            .ToListAsync(cancellationToken);

        return devices.Select(ToResponse).ToList();
    }

    private static DeviceResponse ToResponse(
        ManagedDevice device)
    {
        return new DeviceResponse(
            device.Id,
            device.HostName,
            device.OperatingSystem,
            device.OperatingSystemVersion,
            device.Architecture,
            device.AgentVersion,
            device.Status,
            device.RiskScore,
            device.FirstSeenUtc,
            device.LastSeenUtc);
    }
}

using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Application.Devices;

public sealed record RegisterDeviceRequest(
    Guid DeviceId,
    string HostName,
    string OperatingSystem,
    string OperatingSystemVersion,
    string Architecture,
    string AgentVersion);

public sealed record DeviceResponse(
    Guid Id,
    string HostName,
    string OperatingSystem,
    string OperatingSystemVersion,
    string Architecture,
    string AgentVersion,
    DeviceStatus Status,
    int RiskScore,
    DateTime FirstSeenUtc,
    DateTime LastSeenUtc);

public interface IDeviceService
{
    Task<DeviceResponse> RegisterAsync(
        RegisterDeviceRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<DeviceResponse>> GetAllAsync(
        CancellationToken cancellationToken = default);
}

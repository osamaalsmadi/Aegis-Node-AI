using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Application.Telemetry;

public sealed record SubmitNetworkConnectionRequest(
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int ProcessId,
    string? ProcessName);

public sealed record SubmitFindingRequest(
    FindingCategory Category,
    FindingSeverity Severity,
    string Title,
    string Description,
    string? ProcessName,
    int? ProcessId,
    string? FilePath,
    string? CommandLine);

public sealed record SubmitEndpointTelemetryRequest(
    Guid DeviceId,
    int ProcessCount,
    int ActiveTcpConnectionCount,
    IReadOnlyList<SubmitNetworkConnectionRequest> Connections,
    IReadOnlyList<SubmitFindingRequest> Findings);

public sealed record NetworkConnectionResponse(
    Guid Id,
    string Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    string State,
    int ProcessId,
    string? ProcessName,
    DateTime CollectedAtUtc);

public sealed record FindingResponse(
    Guid Id,
    string Category,
    string Severity,
    string Title,
    string Description,
    string? ProcessName,
    int? ProcessId,
    string? FilePath,
    string? CommandLine,
    string Fingerprint,
    string Status,
    string? AnalystNote,
    string? AnalystName,
    DateTime? ReviewedAtUtc,
    DateTime DetectedAtUtc);

public sealed record EndpointTelemetryResponse(
    Guid ScanId,
    Guid DeviceId,
    int ProcessCount,
    int ActiveTcpConnectionCount,
    int RiskScore,
    DateTime CollectedAtUtc,
    IReadOnlyList<NetworkConnectionResponse> Connections,
    IReadOnlyList<FindingResponse> Findings);

public interface IEndpointTelemetryService
{
    Task<EndpointTelemetryResponse> SubmitAsync(
        SubmitEndpointTelemetryRequest request,
        CancellationToken cancellationToken = default);

    Task<EndpointTelemetryResponse?> GetLatestAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default);
}

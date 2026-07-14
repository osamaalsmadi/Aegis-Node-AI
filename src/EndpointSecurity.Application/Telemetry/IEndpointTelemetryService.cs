using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Application.Telemetry;

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
    IReadOnlyList<SubmitFindingRequest> Findings);

public sealed record FindingResponse(
    Guid Id,
    FindingCategory Category,
    FindingSeverity Severity,
    string Title,
    string Description,
    string? ProcessName,
    int? ProcessId,
    string? FilePath,
    string? CommandLine,
    DateTime DetectedAtUtc);

public sealed record EndpointTelemetryResponse(
    Guid ScanId,
    Guid DeviceId,
    int ProcessCount,
    int ActiveTcpConnectionCount,
    int RiskScore,
    DateTime CollectedAtUtc,
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

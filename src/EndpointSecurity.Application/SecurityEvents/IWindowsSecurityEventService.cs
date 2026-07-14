namespace EndpointSecurity.Application.SecurityEvents;

public sealed record SubmitWindowsSecurityEventRequest(
    string EventKey,
    string ProviderName,
    string LogName,
    int EventId,
    string Level,
    string Severity,
    string Category,
    string Title,
    string Message,
    long RecordId,
    DateTime OccurredAtUtc);

public sealed record SubmitWindowsSecurityEventBatchRequest(
    Guid DeviceId,
    IReadOnlyList<SubmitWindowsSecurityEventRequest> Events);

public sealed record WindowsSecurityEventResponse(
    Guid Id,
    Guid DeviceId,
    string EventKey,
    string ProviderName,
    string LogName,
    int EventId,
    string Level,
    string Severity,
    string Category,
    string Title,
    string Message,
    long RecordId,
    DateTime OccurredAtUtc,
    DateTime CollectedAtUtc);

public sealed record WindowsSecurityEventSummaryResponse(
    Guid DeviceId,
    int TotalEvents,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount,
    int FailedLogonCount,
    int DefenderEventCount,
    int RiskScore,
    DateTime? LastEventAtUtc);

public interface IWindowsSecurityEventService
{
    Task<IReadOnlyList<WindowsSecurityEventResponse>>
        SubmitBatchAsync(
            SubmitWindowsSecurityEventBatchRequest request,
            CancellationToken cancellationToken = default);

    Task<IReadOnlyList<WindowsSecurityEventResponse>>
        GetRecentAsync(
            Guid deviceId,
            int limit = 200,
            CancellationToken cancellationToken = default);

    Task<WindowsSecurityEventSummaryResponse>
        GetSummaryAsync(
            Guid deviceId,
            CancellationToken cancellationToken = default);
}

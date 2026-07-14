using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Application.Findings;

public sealed record ReviewFindingRequest(
    FindingReviewStatus Status,
    string? AnalystNote,
    string? AnalystName);

public sealed record FindingReviewResponse(
    Guid Id,
    Guid FindingId,
    Guid DeviceId,
    string Fingerprint,
    string Status,
    string? AnalystNote,
    string AnalystName,
    DateTime ReviewedAtUtc);

public interface IFindingManagementService
{
    Task<FindingReviewResponse> ReviewAsync(
        Guid findingId,
        ReviewFindingRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<FindingReviewResponse>> GetHistoryAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default);
}

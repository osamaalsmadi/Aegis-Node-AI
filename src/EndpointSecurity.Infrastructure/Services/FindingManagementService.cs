using EndpointSecurity.Application.Findings;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Services;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Services;

public sealed class FindingManagementService(
    EndpointSecurityDbContext dbContext)
    : IFindingManagementService
{
    public async Task<FindingReviewResponse> ReviewAsync(
        Guid findingId,
        ReviewFindingRequest request,
        CancellationToken cancellationToken = default)
    {
        var finding = await dbContext.SecurityFindings
            .SingleOrDefaultAsync(
                x => x.Id == findingId,
                cancellationToken)
            ?? throw new KeyNotFoundException(
                "The security finding was not found.");

        var analystName =
            string.IsNullOrWhiteSpace(request.AnalystName)
                ? "Osama Alsmadi"
                : request.AnalystName.Trim();

        if (analystName.Length > 100)
            analystName = analystName[..100];

        var analystNote =
            string.IsNullOrWhiteSpace(request.AnalystNote)
                ? null
                : request.AnalystNote.Trim();

        if (analystNote?.Length > 1000)
            analystNote = analystNote[..1000];

        var review = new FindingReview(
            finding.Id,
            finding.DeviceId,
            FindingFingerprint.Create(finding),
            request.Status,
            analystNote,
            analystName);

        await dbContext.FindingReviews.AddAsync(
            review,
            cancellationToken);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return ToResponse(review);
    }

    public async Task<IReadOnlyList<FindingReviewResponse>>
        GetHistoryAsync(
            Guid deviceId,
            CancellationToken cancellationToken = default)
    {
        return await dbContext.FindingReviews
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.ReviewedAtUtc)
            .Take(200)
            .Select(x => new FindingReviewResponse(
                x.Id,
                x.FindingId,
                x.DeviceId,
                x.Fingerprint,
                x.Status.ToString(),
                x.AnalystNote,
                x.AnalystName,
                x.ReviewedAtUtc))
            .ToListAsync(cancellationToken);
    }

    private static FindingReviewResponse ToResponse(
        FindingReview review)
    {
        return new FindingReviewResponse(
            review.Id,
            review.FindingId,
            review.DeviceId,
            review.Fingerprint,
            review.Status.ToString(),
            review.AnalystNote,
            review.AnalystName,
            review.ReviewedAtUtc);
    }
}

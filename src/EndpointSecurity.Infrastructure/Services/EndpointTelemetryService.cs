using EndpointSecurity.Application.Telemetry;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Domain.Services;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Services;

public sealed class EndpointTelemetryService(
    EndpointSecurityDbContext dbContext)
    : IEndpointTelemetryService
{
    public async Task<EndpointTelemetryResponse> SubmitAsync(
        SubmitEndpointTelemetryRequest request,
        CancellationToken cancellationToken = default)
    {
        var device = await dbContext.ManagedDevices
            .SingleOrDefaultAsync(
                x => x.Id == request.DeviceId,
                cancellationToken)
            ?? throw new KeyNotFoundException(
                "The device is not registered.");

        var incomingFindings =
            request.Findings ??
            Array.Empty<SubmitFindingRequest>();

        var incomingConnections =
            request.Connections ??
            Array.Empty<SubmitNetworkConnectionRequest>();

        var requestFingerprints = incomingFindings
            .Select(x => FindingFingerprint.Create(
                x.Category,
                x.Title,
                x.ProcessName,
                x.FilePath))
            .Distinct()
            .ToList();

        var existingReviews =
            await LoadLatestReviewsAsync(
                request.DeviceId,
                requestFingerprints,
                cancellationToken);

        var activeIncoming = incomingFindings
            .Where(x =>
            {
                var fingerprint =
                    FindingFingerprint.Create(
                        x.Category,
                        x.Title,
                        x.ProcessName,
                        x.FilePath);

                return !existingReviews.TryGetValue(
                           fingerprint,
                           out var review) ||
                       review.Status ==
                           FindingReviewStatus.Open;
            })
            .ToList();

        var telemetryRisk = CalculateRiskScore(
            activeIncoming.Select(x => x.Severity));

        var scan = new EndpointTelemetryScan(
            request.DeviceId,
            request.ProcessCount,
            request.ActiveTcpConnectionCount,
            telemetryRisk);

        await dbContext.EndpointTelemetryScans.AddAsync(
            scan,
            cancellationToken);

        var findings = incomingFindings
            .Select(x => new SecurityFinding(
                scan.Id,
                request.DeviceId,
                x.Category,
                x.Severity,
                x.Title,
                x.Description,
                x.ProcessName,
                x.ProcessId,
                x.FilePath,
                x.CommandLine))
            .ToList();

        var connections = incomingConnections
            .Take(500)
            .Select(x => new NetworkConnectionSnapshot(
                scan.Id,
                request.DeviceId,
                x.Protocol,
                x.LocalAddress,
                x.LocalPort,
                x.RemoteAddress,
                x.RemotePort,
                x.State,
                x.ProcessId,
                x.ProcessName))
            .ToList();

        if (findings.Count > 0)
        {
            await dbContext.SecurityFindings.AddRangeAsync(
                findings,
                cancellationToken);
        }

        if (connections.Count > 0)
        {
            await dbContext.NetworkConnectionSnapshots
                .AddRangeAsync(
                    connections,
                    cancellationToken);
        }

        device.UpdateHeartbeat(
            device.AgentVersion,
            GetDeviceStatus(telemetryRisk),
            telemetryRisk);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return ToResponse(
            scan,
            connections,
            findings,
            existingReviews);
    }

    public async Task<EndpointTelemetryResponse?> GetLatestAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var scan = await dbContext.EndpointTelemetryScans
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.CollectedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (scan is null)
            return null;

        var connections =
            await dbContext.NetworkConnectionSnapshots
                .AsNoTracking()
                .Where(x => x.ScanId == scan.Id)
                .OrderBy(x => x.ProcessName)
                .ToListAsync(cancellationToken);

        var findings = await dbContext.SecurityFindings
            .AsNoTracking()
            .Where(x => x.ScanId == scan.Id)
            .OrderByDescending(x => x.Severity)
            .ToListAsync(cancellationToken);

        var reviews = await LoadLatestReviewsAsync(
            deviceId,
            findings.Select(FindingFingerprint.Create),
            cancellationToken);

        return ToResponse(
            scan,
            connections,
            findings,
            reviews);
    }

    private async Task<
        IReadOnlyDictionary<string, FindingReview>>
        LoadLatestReviewsAsync(
            Guid deviceId,
            IEnumerable<string> fingerprints,
            CancellationToken cancellationToken)
    {
        var values = fingerprints
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (values.Count == 0)
        {
            return new Dictionary<string, FindingReview>(
                StringComparer.OrdinalIgnoreCase);
        }

        var reviews = await dbContext.FindingReviews
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                values.Contains(x.Fingerprint))
            .OrderByDescending(x => x.ReviewedAtUtc)
            .ToListAsync(cancellationToken);

        return reviews
            .GroupBy(
                x => x.Fingerprint,
                StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.First(),
                StringComparer.OrdinalIgnoreCase);
    }

    private static int CalculateRiskScore(
        IEnumerable<FindingSeverity> severities)
    {
        var score = severities.Sum(severity =>
            severity switch
            {
                FindingSeverity.Critical => 50,
                FindingSeverity.High => 30,
                FindingSeverity.Medium => 15,
                _ => 5
            });

        return Math.Min(score, 100);
    }

    private static DeviceStatus GetDeviceStatus(int score)
    {
        return score switch
        {
            >= 70 => DeviceStatus.Critical,
            >= 30 => DeviceStatus.Warning,
            _ => DeviceStatus.Healthy
        };
    }

    private static EndpointTelemetryResponse ToResponse(
        EndpointTelemetryScan scan,
        IReadOnlyList<NetworkConnectionSnapshot> connections,
        IReadOnlyList<SecurityFinding> findings,
        IReadOnlyDictionary<string, FindingReview> reviews)
    {
        var connectionResponses = connections
            .Select(x => new NetworkConnectionResponse(
                x.Id,
                x.Protocol,
                x.LocalAddress,
                x.LocalPort,
                x.RemoteAddress,
                x.RemotePort,
                x.State,
                x.ProcessId,
                x.ProcessName,
                x.CollectedAtUtc))
            .ToList();

        var findingResponses = findings
            .Select(x =>
            {
                var fingerprint =
                    FindingFingerprint.Create(x);

                reviews.TryGetValue(
                    fingerprint,
                    out var review);

                return new FindingResponse(
                    x.Id,
                    x.Category.ToString(),
                    x.Severity.ToString(),
                    x.Title,
                    x.Description,
                    x.ProcessName,
                    x.ProcessId,
                    x.FilePath,
                    x.CommandLine,
                    fingerprint,
                    review?.Status.ToString() ??
                        FindingReviewStatus.Open.ToString(),
                    review?.AnalystNote,
                    review?.AnalystName,
                    review?.ReviewedAtUtc,
                    x.DetectedAtUtc);
            })
            .ToList();

        var activeRisk = CalculateRiskScore(
            findings
                .Where(x =>
                {
                    var fingerprint =
                        FindingFingerprint.Create(x);

                    return !reviews.TryGetValue(
                               fingerprint,
                               out var review) ||
                           review.Status ==
                               FindingReviewStatus.Open;
                })
                .Select(x => x.Severity));

        return new EndpointTelemetryResponse(
            scan.Id,
            scan.DeviceId,
            scan.ProcessCount,
            scan.ActiveTcpConnectionCount,
            activeRisk,
            scan.CollectedAtUtc,
            connectionResponses,
            findingResponses);
    }
}

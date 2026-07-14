using EndpointSecurity.Application.Telemetry;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
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

        var telemetryRisk =
            CalculateRiskScore(incomingFindings);

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

        if (findings.Count > 0)
        {
            await dbContext.SecurityFindings.AddRangeAsync(
                findings,
                cancellationToken);
        }

        var overallRisk = Math.Max(
            device.RiskScore,
            telemetryRisk);

        device.UpdateHeartbeat(
            device.AgentVersion,
            GetDeviceStatus(overallRisk),
            overallRisk);

        await dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(scan, findings);
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

        var findings = await dbContext.SecurityFindings
            .AsNoTracking()
            .Where(x => x.ScanId == scan.Id)
            .OrderByDescending(x => x.Severity)
            .ToListAsync(cancellationToken);

        return ToResponse(scan, findings);
    }

    private static int CalculateRiskScore(
        IReadOnlyList<SubmitFindingRequest> findings)
    {
        var score = findings.Sum(x => x.Severity switch
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
        IReadOnlyList<SecurityFinding> findings)
    {
        var responses = findings
            .Select(x => new FindingResponse(
                x.Id,
                x.Category,
                x.Severity,
                x.Title,
                x.Description,
                x.ProcessName,
                x.ProcessId,
                x.FilePath,
                x.CommandLine,
                x.DetectedAtUtc))
            .ToList();

        return new EndpointTelemetryResponse(
            scan.Id,
            scan.DeviceId,
            scan.ProcessCount,
            scan.ActiveTcpConnectionCount,
            scan.RiskScore,
            scan.CollectedAtUtc,
            responses);
    }
}

using EndpointSecurity.Application.SecurityPosture;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Services;

public sealed class SecurityPostureService(
    EndpointSecurityDbContext dbContext)
    : ISecurityPostureService
{
    public async Task<SecurityPostureResponse> SubmitAsync(
        SubmitSecurityPostureRequest request,
        CancellationToken cancellationToken = default)
    {
        var device = await dbContext.ManagedDevices
            .SingleOrDefaultAsync(
                x => x.Id == request.DeviceId,
                cancellationToken)
            ?? throw new KeyNotFoundException(
                "The device is not registered.");

        var riskScore = CalculateRiskScore(request);

        var snapshot = new SecurityPostureSnapshot(
            request.DeviceId,
            request.DefenderEnabled,
            request.RealTimeProtectionEnabled,
            request.AntivirusSignatureAgeDays,
            request.FirewallDomainEnabled,
            request.FirewallPrivateEnabled,
            request.FirewallPublicEnabled,
            request.RebootRequired,
            riskScore);

        await dbContext.SecurityPostureSnapshots.AddAsync(
            snapshot,
            cancellationToken);

        device.UpdateHeartbeat(
            device.AgentVersion,
            GetDeviceStatus(riskScore),
            riskScore);

        await dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(snapshot);
    }

    public async Task<SecurityPostureResponse?> GetLatestAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default)
    {
        var snapshot = await dbContext.SecurityPostureSnapshots
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.CollectedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        return snapshot is null
            ? null
            : ToResponse(snapshot);
    }

    private static int CalculateRiskScore(
        SubmitSecurityPostureRequest request)
    {
        var score = 0;

        score += request.DefenderEnabled switch
        {
            false => 30,
            null => 10,
            _ => 0
        };

        score += request.RealTimeProtectionEnabled switch
        {
            false => 30,
            null => 10,
            _ => 0
        };

        score += FirewallRisk(
            request.FirewallDomainEnabled);

        score += FirewallRisk(
            request.FirewallPrivateEnabled);

        score += FirewallRisk(
            request.FirewallPublicEnabled);

        score += request.AntivirusSignatureAgeDays switch
        {
            > 7 => 15,
            > 3 => 8,
            null => 3,
            _ => 0
        };

        if (request.RebootRequired == true)
        {
            score += 10;
        }

        return Math.Min(score, 100);
    }

    private static int FirewallRisk(bool? enabled)
    {
        return enabled switch
        {
            false => 10,
            null => 3,
            _ => 0
        };
    }

    private static DeviceStatus GetDeviceStatus(int riskScore)
    {
        return riskScore switch
        {
            >= 70 => DeviceStatus.Critical,
            >= 30 => DeviceStatus.Warning,
            _ => DeviceStatus.Healthy
        };
    }

    private static SecurityPostureResponse ToResponse(
        SecurityPostureSnapshot snapshot)
    {
        return new SecurityPostureResponse(
            snapshot.Id,
            snapshot.DeviceId,
            snapshot.DefenderEnabled,
            snapshot.RealTimeProtectionEnabled,
            snapshot.AntivirusSignatureAgeDays,
            snapshot.FirewallDomainEnabled,
            snapshot.FirewallPrivateEnabled,
            snapshot.FirewallPublicEnabled,
            snapshot.RebootRequired,
            snapshot.RiskScore,
            snapshot.CollectedAtUtc);
    }
}

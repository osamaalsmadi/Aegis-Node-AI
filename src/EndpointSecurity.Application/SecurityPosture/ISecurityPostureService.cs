namespace EndpointSecurity.Application.SecurityPosture;

public sealed record SubmitSecurityPostureRequest(
    Guid DeviceId,
    bool? DefenderEnabled,
    bool? RealTimeProtectionEnabled,
    int? AntivirusSignatureAgeDays,
    bool? FirewallDomainEnabled,
    bool? FirewallPrivateEnabled,
    bool? FirewallPublicEnabled,
    bool? RebootRequired);

public sealed record SecurityPostureResponse(
    Guid Id,
    Guid DeviceId,
    bool? DefenderEnabled,
    bool? RealTimeProtectionEnabled,
    int? AntivirusSignatureAgeDays,
    bool? FirewallDomainEnabled,
    bool? FirewallPrivateEnabled,
    bool? FirewallPublicEnabled,
    bool? RebootRequired,
    int RiskScore,
    DateTime CollectedAtUtc);

public interface ISecurityPostureService
{
    Task<SecurityPostureResponse> SubmitAsync(
        SubmitSecurityPostureRequest request,
        CancellationToken cancellationToken = default);

    Task<SecurityPostureResponse?> GetLatestAsync(
        Guid deviceId,
        CancellationToken cancellationToken = default);
}

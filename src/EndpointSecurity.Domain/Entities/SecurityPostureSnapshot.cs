namespace EndpointSecurity.Domain.Entities;

public sealed class SecurityPostureSnapshot
{
    private SecurityPostureSnapshot()
    {
    }

    public SecurityPostureSnapshot(
        Guid deviceId,
        bool? defenderEnabled,
        bool? realTimeProtectionEnabled,
        int? antivirusSignatureAgeDays,
        bool? firewallDomainEnabled,
        bool? firewallPrivateEnabled,
        bool? firewallPublicEnabled,
        bool? rebootRequired,
        int riskScore)
    {
        if (deviceId == Guid.Empty)
        {
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));
        }

        if (riskScore is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(riskScore));
        }

        Id = Guid.NewGuid();
        DeviceId = deviceId;
        DefenderEnabled = defenderEnabled;
        RealTimeProtectionEnabled = realTimeProtectionEnabled;
        AntivirusSignatureAgeDays = antivirusSignatureAgeDays;
        FirewallDomainEnabled = firewallDomainEnabled;
        FirewallPrivateEnabled = firewallPrivateEnabled;
        FirewallPublicEnabled = firewallPublicEnabled;
        RebootRequired = rebootRequired;
        RiskScore = riskScore;
        CollectedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid DeviceId { get; private set; }

    public bool? DefenderEnabled { get; private set; }

    public bool? RealTimeProtectionEnabled { get; private set; }

    public int? AntivirusSignatureAgeDays { get; private set; }

    public bool? FirewallDomainEnabled { get; private set; }

    public bool? FirewallPrivateEnabled { get; private set; }

    public bool? FirewallPublicEnabled { get; private set; }

    public bool? RebootRequired { get; private set; }

    public int RiskScore { get; private set; }

    public DateTime CollectedAtUtc { get; private set; }
}

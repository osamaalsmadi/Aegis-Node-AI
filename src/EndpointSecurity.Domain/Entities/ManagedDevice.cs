using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Domain.Entities;

public sealed class ManagedDevice
{
    private ManagedDevice()
    {
    }

    public ManagedDevice(
        Guid id,
        string hostName,
        string operatingSystem,
        string operatingSystemVersion,
        string architecture,
        string agentVersion)
    {
        if (id == Guid.Empty)
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(id));

        Id = id;
        HostName = Required(hostName, nameof(hostName));
        OperatingSystem = Required(
            operatingSystem,
            nameof(operatingSystem));
        OperatingSystemVersion = Required(
            operatingSystemVersion,
            nameof(operatingSystemVersion));
        Architecture = Required(
            architecture,
            nameof(architecture));
        AgentVersion = Required(
            agentVersion,
            nameof(agentVersion));

        Status = DeviceStatus.Unknown;
        RiskScore = 0;
        FirstSeenUtc = DateTime.UtcNow;
        LastSeenUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public string HostName { get; private set; } = string.Empty;

    public string OperatingSystem { get; private set; } = string.Empty;

    public string OperatingSystemVersion { get; private set; } =
        string.Empty;

    public string Architecture { get; private set; } = string.Empty;

    public string AgentVersion { get; private set; } = string.Empty;

    public DeviceStatus Status { get; private set; }

    public int RiskScore { get; private set; }

    public DateTime FirstSeenUtc { get; private set; }

    public DateTime LastSeenUtc { get; private set; }

    public void UpdateInventory(
        string hostName,
        string operatingSystem,
        string operatingSystemVersion,
        string architecture,
        string agentVersion)
    {
        HostName = Required(hostName, nameof(hostName));
        OperatingSystem = Required(
            operatingSystem,
            nameof(operatingSystem));
        OperatingSystemVersion = Required(
            operatingSystemVersion,
            nameof(operatingSystemVersion));
        Architecture = Required(
            architecture,
            nameof(architecture));
        AgentVersion = Required(
            agentVersion,
            nameof(agentVersion));
        LastSeenUtc = DateTime.UtcNow;
    }

    public void UpdateHeartbeat(
        string agentVersion,
        DeviceStatus status,
        int riskScore)
    {
        if (riskScore is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(riskScore),
                "Risk score must be between 0 and 100.");
        }

        AgentVersion = Required(
            agentVersion,
            nameof(agentVersion));
        Status = status;
        RiskScore = riskScore;
        LastSeenUtc = DateTime.UtcNow;
    }

    private static string Required(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "Value cannot be empty.",
                parameterName);
        }

        return value.Trim();
    }
}

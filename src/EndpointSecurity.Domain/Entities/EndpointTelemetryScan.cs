namespace EndpointSecurity.Domain.Entities;

public sealed class EndpointTelemetryScan
{
    private EndpointTelemetryScan()
    {
    }

    public EndpointTelemetryScan(
        Guid deviceId,
        int processCount,
        int activeTcpConnectionCount,
        int riskScore)
    {
        if (deviceId == Guid.Empty)
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));

        if (processCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(processCount));

        if (activeTcpConnectionCount < 0)
            throw new ArgumentOutOfRangeException(
                nameof(activeTcpConnectionCount));

        if (riskScore is < 0 or > 100)
            throw new ArgumentOutOfRangeException(
                nameof(riskScore));

        Id = Guid.NewGuid();
        DeviceId = deviceId;
        ProcessCount = processCount;
        ActiveTcpConnectionCount = activeTcpConnectionCount;
        RiskScore = riskScore;
        CollectedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid DeviceId { get; private set; }

    public int ProcessCount { get; private set; }

    public int ActiveTcpConnectionCount { get; private set; }

    public int RiskScore { get; private set; }

    public DateTime CollectedAtUtc { get; private set; }
}

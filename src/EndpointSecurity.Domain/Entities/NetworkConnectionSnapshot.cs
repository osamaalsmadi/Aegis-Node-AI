namespace EndpointSecurity.Domain.Entities;

public sealed class NetworkConnectionSnapshot
{
    private NetworkConnectionSnapshot()
    {
    }

    public NetworkConnectionSnapshot(
        Guid scanId,
        Guid deviceId,
        string protocol,
        string localAddress,
        int localPort,
        string remoteAddress,
        int remotePort,
        string state,
        int processId,
        string? processName)
    {
        if (scanId == Guid.Empty)
            throw new ArgumentException(
                "Scan ID cannot be empty.",
                nameof(scanId));

        if (deviceId == Guid.Empty)
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));

        ValidatePort(localPort, nameof(localPort));
        ValidatePort(remotePort, nameof(remotePort));

        Id = Guid.NewGuid();
        ScanId = scanId;
        DeviceId = deviceId;
        Protocol = Required(protocol, nameof(protocol));
        LocalAddress = Required(
            localAddress,
            nameof(localAddress));
        LocalPort = localPort;
        RemoteAddress = Required(
            remoteAddress,
            nameof(remoteAddress));
        RemotePort = remotePort;
        State = Required(state, nameof(state));
        ProcessId = processId;
        ProcessName = Clean(processName);
        CollectedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid ScanId { get; private set; }

    public Guid DeviceId { get; private set; }

    public string Protocol { get; private set; } = string.Empty;

    public string LocalAddress { get; private set; } = string.Empty;

    public int LocalPort { get; private set; }

    public string RemoteAddress { get; private set; } = string.Empty;

    public int RemotePort { get; private set; }

    public string State { get; private set; } = string.Empty;

    public int ProcessId { get; private set; }

    public string? ProcessName { get; private set; }

    public DateTime CollectedAtUtc { get; private set; }

    private static void ValidatePort(
        int port,
        string parameterName)
    {
        if (port is < 0 or > 65535)
            throw new ArgumentOutOfRangeException(
                parameterName);
    }

    private static string Required(
        string value,
        string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException(
                "Value cannot be empty.",
                parameterName);

        return value.Trim();
    }

    private static string? Clean(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : value.Trim();
    }
}

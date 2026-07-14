namespace EndpointSecurity.Domain.Entities;

public sealed class WindowsSecurityEventRecord
{
    private WindowsSecurityEventRecord()
    {
    }

    public WindowsSecurityEventRecord(
        Guid deviceId,
        string eventKey,
        string providerName,
        string logName,
        int eventId,
        string level,
        string severity,
        string category,
        string title,
        string message,
        long recordId,
        DateTime occurredAtUtc)
    {
        if (deviceId == Guid.Empty)
        {
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));
        }

        Id = Guid.NewGuid();
        DeviceId = deviceId;
        EventKey = Required(
            eventKey,
            nameof(eventKey));
        ProviderName = Required(
            providerName,
            nameof(providerName));
        LogName = Required(
            logName,
            nameof(logName));
        EventId = eventId;
        Level = Required(
            level,
            nameof(level));
        Severity = Required(
            severity,
            nameof(severity));
        Category = Required(
            category,
            nameof(category));
        Title = Required(
            title,
            nameof(title));
        Message = Required(
            message,
            nameof(message));
        RecordId = recordId;

        OccurredAtUtc =
            occurredAtUtc.Kind == DateTimeKind.Utc
                ? occurredAtUtc
                : occurredAtUtc.ToUniversalTime();

        CollectedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid DeviceId { get; private set; }

    public string EventKey { get; private set; } =
        string.Empty;

    public string ProviderName { get; private set; } =
        string.Empty;

    public string LogName { get; private set; } =
        string.Empty;

    public int EventId { get; private set; }

    public string Level { get; private set; } =
        string.Empty;

    public string Severity { get; private set; } =
        string.Empty;

    public string Category { get; private set; } =
        string.Empty;

    public string Title { get; private set; } =
        string.Empty;

    public string Message { get; private set; } =
        string.Empty;

    public long RecordId { get; private set; }

    public DateTime OccurredAtUtc { get; private set; }

    public DateTime CollectedAtUtc { get; private set; }

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

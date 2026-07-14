using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Domain.Entities;

public sealed class SecurityFinding
{
    private SecurityFinding()
    {
    }

    public SecurityFinding(
        Guid scanId,
        Guid deviceId,
        FindingCategory category,
        FindingSeverity severity,
        string title,
        string description,
        string? processName,
        int? processId,
        string? filePath,
        string? commandLine)
    {
        if (scanId == Guid.Empty)
            throw new ArgumentException(
                "Scan ID cannot be empty.",
                nameof(scanId));

        if (deviceId == Guid.Empty)
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));

        Id = Guid.NewGuid();
        ScanId = scanId;
        DeviceId = deviceId;
        Category = category;
        Severity = severity;
        Title = Required(title, nameof(title));
        Description = Required(
            description,
            nameof(description));
        ProcessName = Clean(processName);
        ProcessId = processId;
        FilePath = Clean(filePath);
        CommandLine = Clean(commandLine);
        DetectedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid ScanId { get; private set; }

    public Guid DeviceId { get; private set; }

    public FindingCategory Category { get; private set; }

    public FindingSeverity Severity { get; private set; }

    public string Title { get; private set; } = string.Empty;

    public string Description { get; private set; } = string.Empty;

    public string? ProcessName { get; private set; }

    public int? ProcessId { get; private set; }

    public string? FilePath { get; private set; }

    public string? CommandLine { get; private set; }

    public DateTime DetectedAtUtc { get; private set; }

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

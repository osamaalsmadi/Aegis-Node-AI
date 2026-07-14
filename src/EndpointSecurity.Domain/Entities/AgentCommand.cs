using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Domain.Entities;

public sealed class AgentCommand
{
    private AgentCommand()
    {
    }

    public AgentCommand(
        Guid deviceId,
        AgentCommandType type)
        : this(deviceId, type, null)
    {
    }

    public AgentCommand(
        Guid deviceId,
        AgentCommandType type,
        string? targetPath)
    {
        if (deviceId == Guid.Empty)
        {
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));
        }

        Id = Guid.NewGuid();
        DeviceId = deviceId;
        Type = type;
        TargetPath = Limit(targetPath, 1024);
        Status = AgentCommandStatus.Pending;
        RequestedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid DeviceId { get; private set; }

    public AgentCommandType Type { get; private set; }

    public string? TargetPath { get; private set; }

    public AgentCommandStatus Status { get; private set; }

    public DateTime RequestedAtUtc { get; private set; }

    public DateTime? StartedAtUtc { get; private set; }

    public DateTime? CompletedAtUtc { get; private set; }

    public int? ThreatCount { get; private set; }

    public string? ResultMessage { get; private set; }

    public string? ErrorMessage { get; private set; }

    public void MarkRunning()
    {
        if (Status == AgentCommandStatus.Running)
        {
            return;
        }

        if (Status != AgentCommandStatus.Pending)
        {
            throw new InvalidOperationException(
                $"Command cannot start from status {Status}.");
        }

        Status = AgentCommandStatus.Running;
        StartedAtUtc = DateTime.UtcNow;
        ErrorMessage = null;
    }

    public void MarkCompleted(
        int threatCount,
        string? resultMessage)
    {
        if (threatCount < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(threatCount));
        }

        if (Status is not (
            AgentCommandStatus.Pending or
            AgentCommandStatus.Running))
        {
            throw new InvalidOperationException(
                $"Command cannot complete from status {Status}.");
        }

        Status = AgentCommandStatus.Completed;
        StartedAtUtc ??= DateTime.UtcNow;
        CompletedAtUtc = DateTime.UtcNow;
        ThreatCount = threatCount;
        ResultMessage = Limit(resultMessage, 1000);
        ErrorMessage = null;
    }

    public void MarkFailed(string? errorMessage)
    {
        if (Status is not (
            AgentCommandStatus.Pending or
            AgentCommandStatus.Running))
        {
            throw new InvalidOperationException(
                $"Command cannot fail from status {Status}.");
        }

        Status = AgentCommandStatus.Failed;
        StartedAtUtc ??= DateTime.UtcNow;
        CompletedAtUtc = DateTime.UtcNow;

        ErrorMessage = Limit(
            string.IsNullOrWhiteSpace(errorMessage)
                ? "The command failed without an error message."
                : errorMessage,
            2000);
    }

    private static string? Limit(
        string? value,
        int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var cleanValue = value.Trim();

        return cleanValue.Length <= maxLength
            ? cleanValue
            : cleanValue[..maxLength];
    }
}

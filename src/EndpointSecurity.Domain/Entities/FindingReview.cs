using EndpointSecurity.Domain.Enums;

namespace EndpointSecurity.Domain.Entities;

public sealed class FindingReview
{
    private FindingReview()
    {
    }

    public FindingReview(
        Guid findingId,
        Guid deviceId,
        string fingerprint,
        FindingReviewStatus status,
        string? analystNote,
        string analystName)
    {
        if (findingId == Guid.Empty)
            throw new ArgumentException(
                "Finding ID cannot be empty.",
                nameof(findingId));

        if (deviceId == Guid.Empty)
            throw new ArgumentException(
                "Device ID cannot be empty.",
                nameof(deviceId));

        Id = Guid.NewGuid();
        FindingId = findingId;
        DeviceId = deviceId;
        Fingerprint = Required(
            fingerprint,
            nameof(fingerprint));
        Status = status;
        AnalystNote = Clean(analystNote);
        AnalystName = Required(
            analystName,
            nameof(analystName));
        ReviewedAtUtc = DateTime.UtcNow;
    }

    public Guid Id { get; private set; }

    public Guid FindingId { get; private set; }

    public Guid DeviceId { get; private set; }

    public string Fingerprint { get; private set; } =
        string.Empty;

    public FindingReviewStatus Status { get; private set; }

    public string? AnalystNote { get; private set; }

    public string AnalystName { get; private set; } =
        string.Empty;

    public DateTime ReviewedAtUtc { get; private set; }

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

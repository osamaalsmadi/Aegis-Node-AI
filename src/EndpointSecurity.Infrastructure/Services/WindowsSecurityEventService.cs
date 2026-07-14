using EndpointSecurity.Application.SecurityEvents;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Infrastructure.Services;

public sealed class WindowsSecurityEventService(
    EndpointSecurityDbContext dbContext)
    : IWindowsSecurityEventService
{
    public async Task<
        IReadOnlyList<WindowsSecurityEventResponse>>
        SubmitBatchAsync(
            SubmitWindowsSecurityEventBatchRequest request,
            CancellationToken cancellationToken = default)
    {
        var deviceExists = await dbContext.ManagedDevices
            .AsNoTracking()
            .AnyAsync(
                x => x.Id == request.DeviceId,
                cancellationToken);

        if (!deviceExists)
        {
            throw new KeyNotFoundException(
                "The endpoint is not registered.");
        }

        var incomingEvents =
            (request.Events ??
             Array.Empty<
                 SubmitWindowsSecurityEventRequest>())
            .Where(x =>
                !string.IsNullOrWhiteSpace(x.EventKey) &&
                !string.IsNullOrWhiteSpace(x.Title))
            .DistinctBy(
                x => x.EventKey,
                StringComparer.Ordinal)
            .Take(500)
            .ToList();

        if (incomingEvents.Count == 0)
        {
            return Array.Empty<
                WindowsSecurityEventResponse>();
        }

        var incomingKeys = incomingEvents
            .Select(x => x.EventKey)
            .ToList();

        var existingKeys = await dbContext
            .WindowsSecurityEvents
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == request.DeviceId &&
                incomingKeys.Contains(x.EventKey))
            .Select(x => x.EventKey)
            .ToListAsync(cancellationToken);

        var existingKeySet = existingKeys.ToHashSet(
            StringComparer.Ordinal);

        var newRecords = incomingEvents
            .Where(x =>
                !existingKeySet.Contains(x.EventKey))
            .Select(x => new WindowsSecurityEventRecord(
                request.DeviceId,
                Limit(x.EventKey, 300),
                Limit(
                    x.ProviderName,
                    255,
                    "Unknown provider"),
                Limit(
                    x.LogName,
                    255,
                    "Unknown log"),
                x.EventId,
                Limit(x.Level, 30, "Information"),
                NormalizeSeverity(x.Severity),
                Limit(x.Category, 100, "System"),
                Limit(
                    x.Title,
                    255,
                    "Windows security event"),
                Limit(
                    x.Message,
                    4000,
                    "Event message was unavailable."),
                x.RecordId,
                x.OccurredAtUtc))
            .ToList();

        if (newRecords.Count == 0)
        {
            return Array.Empty<
                WindowsSecurityEventResponse>();
        }

        await dbContext.WindowsSecurityEvents
            .AddRangeAsync(
                newRecords,
                cancellationToken);

        await dbContext.SaveChangesAsync(
            cancellationToken);

        return newRecords
            .Select(ToResponse)
            .ToList();
    }

    public async Task<
        IReadOnlyList<WindowsSecurityEventResponse>>
        GetRecentAsync(
            Guid deviceId,
            int limit = 200,
            CancellationToken cancellationToken = default)
    {
        var safeLimit = Math.Clamp(
            limit,
            1,
            500);

        var events = await dbContext
            .WindowsSecurityEvents
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.OccurredAtUtc)
            .Take(safeLimit)
            .ToListAsync(cancellationToken);

        return events
            .Select(ToResponse)
            .ToList();
    }

    public async Task<
        WindowsSecurityEventSummaryResponse>
        GetSummaryAsync(
            Guid deviceId,
            CancellationToken cancellationToken = default)
    {
        var historyCutoff =
            DateTime.UtcNow.AddHours(-24);

        var riskCutoff =
            DateTime.UtcNow.AddMinutes(-30);

        var events = await dbContext
            .WindowsSecurityEvents
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.OccurredAtUtc >= historyCutoff)
            .Select(x => new
            {
                x.EventId,
                x.ProviderName,
                x.Severity,
                x.OccurredAtUtc
            })
            .ToListAsync(cancellationToken);

        var riskScore = events
            .Where(x =>
                x.OccurredAtUtc >= riskCutoff)
            .Select(x => SeverityRisk(x.Severity))
            .DefaultIfEmpty(0)
            .Max();

        return new WindowsSecurityEventSummaryResponse(
            deviceId,
            events.Count,
            events.Count(x =>
                x.Severity == "Critical"),
            events.Count(x =>
                x.Severity == "High"),
            events.Count(x =>
                x.Severity == "Medium"),
            events.Count(x =>
                x.Severity == "Low"),
            events.Count(x =>
                x.EventId == 4625),
            events.Count(x =>
                x.ProviderName.Contains(
                    "Defender",
                    StringComparison.OrdinalIgnoreCase)),
            riskScore,
            events.Count == 0
                ? null
                : events.Max(x => x.OccurredAtUtc));
    }

    private static WindowsSecurityEventResponse
        ToResponse(
            WindowsSecurityEventRecord securityEvent)
    {
        return new WindowsSecurityEventResponse(
            securityEvent.Id,
            securityEvent.DeviceId,
            securityEvent.EventKey,
            securityEvent.ProviderName,
            securityEvent.LogName,
            securityEvent.EventId,
            securityEvent.Level,
            securityEvent.Severity,
            securityEvent.Category,
            securityEvent.Title,
            securityEvent.Message,
            securityEvent.RecordId,
            securityEvent.OccurredAtUtc,
            securityEvent.CollectedAtUtc);
    }

    private static int SeverityRisk(string severity)
    {
        return severity switch
        {
            "Critical" => 50,
            "High" => 30,
            "Medium" => 15,
            "Low" => 5,
            _ => 0
        };
    }

    private static string NormalizeSeverity(
        string? severity)
    {
        return severity?.Trim().ToLowerInvariant()
            switch
            {
                "critical" => "Critical",
                "high" => "High",
                "medium" => "Medium",
                "low" => "Low",
                _ => "Informational"
            };
    }

    private static string Limit(
        string? value,
        int maximumLength,
        string? fallback = null)
    {
        var result =
            string.IsNullOrWhiteSpace(value)
                ? fallback ?? string.Empty
                : value.Trim();

        return result.Length <= maximumLength
            ? result
            : result[..maximumLength];
    }
}

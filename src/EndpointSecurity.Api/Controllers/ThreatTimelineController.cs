using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Domain.Services;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/threat-timeline")]
public sealed class ThreatTimelineController(
    EndpointSecurityDbContext dbContext)
    : ControllerBase
{
    [HttpGet("devices/{deviceId:guid}")]
    public async Task<ActionResult<ThreatTimelineResponse>>
        GetTimeline(
            Guid deviceId,
            [FromQuery] int hours = 24,
            [FromQuery] int limit = 200,
            CancellationToken cancellationToken = default)
    {
        var safeHours = Math.Clamp(
            hours <= 0 ? 24 : hours,
            1,
            168);

        var safeLimit = Math.Clamp(
            limit <= 0 ? 200 : limit,
            20,
            500);

        var device = await dbContext.ManagedDevices
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.Id == deviceId,
                cancellationToken);

        if (device is null)
        {
            return NotFound(new
            {
                message = "The requested endpoint was not found."
            });
        }

        var cutoff = DateTime.UtcNow.AddHours(-safeHours);
        var sourceLimit = Math.Max(safeLimit, 200);

        var securityEvents = await dbContext
            .WindowsSecurityEvents
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.OccurredAtUtc >= cutoff)
            .OrderByDescending(x => x.OccurredAtUtc)
            .Take(sourceLimit)
            .ToListAsync(cancellationToken);

        var findings = await dbContext.SecurityFindings
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.DetectedAtUtc >= cutoff)
            .OrderByDescending(x => x.DetectedAtUtc)
            .Take(sourceLimit)
            .ToListAsync(cancellationToken);

        var fingerprints = findings
            .Select(FindingFingerprint.Create)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var latestReviews = new Dictionary<
            string,
            FindingReview>(StringComparer.OrdinalIgnoreCase);

        if (fingerprints.Count > 0)
        {
            var reviews = await dbContext.FindingReviews
                .AsNoTracking()
                .Where(x =>
                    x.DeviceId == deviceId &&
                    fingerprints.Contains(x.Fingerprint))
                .OrderByDescending(x => x.ReviewedAtUtc)
                .ToListAsync(cancellationToken);

            latestReviews = reviews
                .GroupBy(
                    x => x.Fingerprint,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.First(),
                    StringComparer.OrdinalIgnoreCase);
        }

        var commands = await dbContext.Set<AgentCommand>()
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.RequestedAtUtc >= cutoff)
            .OrderByDescending(x => x.RequestedAtUtc)
            .Take(sourceLimit)
            .ToListAsync(cancellationToken);

        var postures = await dbContext.SecurityPostureSnapshots
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.CollectedAtUtc >= cutoff)
            .OrderByDescending(x => x.CollectedAtUtc)
            .Take(sourceLimit)
            .ToListAsync(cancellationToken);

        var telemetryScans = await dbContext.EndpointTelemetryScans
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.CollectedAtUtc >= cutoff)
            .OrderByDescending(x => x.CollectedAtUtc)
            .Take(sourceLimit)
            .ToListAsync(cancellationToken);

        var items = new List<ThreatTimelineItem>(
            securityEvents.Count +
            findings.Count +
            commands.Count +
            postures.Count +
            telemetryScans.Count +
            1);

        items.AddRange(
            securityEvents.Select(ToTimelineItem));

        items.AddRange(
            findings.Select(finding =>
                ToTimelineItem(
                    finding,
                    latestReviews)));

        items.AddRange(
            commands.Select(ToTimelineItem));

        items.AddRange(
            postures.Select(ToTimelineItem));

        items.AddRange(
            telemetryScans.Select(ToTimelineItem));

        if (Utc(device.LastSeenUtc) >= cutoff)
        {
            var online =
                DateTime.UtcNow - Utc(device.LastSeenUtc) <
                TimeSpan.FromMinutes(3);

            items.Add(new ThreatTimelineItem(
                $"heartbeat-{device.Id:N}",
                "Agent",
                online ? "Informational" : "Medium",
                online
                    ? "Endpoint heartbeat received"
                    : "Endpoint heartbeat is stale",
                online
                    ? "The Windows Agent confirmed that the endpoint is online."
                    : "The endpoint has not sent a heartbeat within the expected interval.",
                online ? "Online" : "Offline",
                "Agent",
                $"Host: {device.HostName}; Agent: {device.AgentVersion}",
                online
                    ? "No action is required."
                    : "Check the EndpointSecurityAgent Windows service.",
                Utc(device.LastSeenUtc)));
        }

        var orderedItems = items
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => SeverityRank(x.Severity))
            .ToList();

        var summary = BuildSummary(
            orderedItems,
            device.RiskScore,
            postures.FirstOrDefault()?.RiskScore,
            telemetryScans.FirstOrDefault()?.RiskScore);

        var responseItems = orderedItems
            .Take(safeLimit)
            .ToList();

        return Ok(new ThreatTimelineResponse(
            device.Id,
            device.HostName,
            DateTime.UtcNow,
            safeHours,
            responseItems.Count,
            summary,
            responseItems));
    }

    private static ThreatTimelineItem ToTimelineItem(
        WindowsSecurityEventRecord securityEvent)
    {
        var severity = NormalizeSeverity(
            securityEvent.Severity);

        var action = securityEvent.EventId == 4625
            ? "Review the failed sign-in source, account, and nearby authentication events."
            : severity is "Critical" or "High"
                ? "Investigate this Windows event and correlate it with endpoint activity."
                : "No immediate action is required unless this event is unexpected.";

        return new ThreatTimelineItem(
            securityEvent.Id.ToString("N"),
            "SecurityEvent",
            severity,
            securityEvent.Title,
            Limit(securityEvent.Message, 700),
            securityEvent.Level,
            securityEvent.Category,
            $"Event ID {securityEvent.EventId}; Provider: {securityEvent.ProviderName}; Log: {securityEvent.LogName}",
            action,
            Utc(securityEvent.OccurredAtUtc));
    }

    private static ThreatTimelineItem ToTimelineItem(
        SecurityFinding finding,
        IReadOnlyDictionary<string, FindingReview> reviews)
    {
        var fingerprint = FindingFingerprint.Create(finding);
        reviews.TryGetValue(fingerprint, out var review);

        var status = review?.Status.ToString() ?? "Open";
        var evidence = FirstValue(
            finding.FilePath,
            finding.CommandLine,
            finding.ProcessName is null
                ? null
                : $"{finding.ProcessName} (PID {finding.ProcessId?.ToString() ?? "unknown"})",
            $"Scan: {finding.ScanId}");

        var action = status == "Open"
            ? "Review the evidence and use the Remediation Center when corrective action is required."
            : $"The finding is marked {status}. Reopen it only if the behavior returns.";

        return new ThreatTimelineItem(
            finding.Id.ToString("N"),
            "Finding",
            finding.Severity.ToString(),
            finding.Title,
            finding.Description,
            status,
            finding.Category.ToString(),
            evidence,
            action,
            Utc(finding.DetectedAtUtc));
    }

    private static ThreatTimelineItem ToTimelineItem(
        AgentCommand command)
    {
        var isRemediation = command.Type is
            AgentCommandType.DefenderUpdateSignatures or
            AgentCommandType.DefenderRemediateThreats;

        var type = isRemediation
            ? "Remediation"
            : "Scan";

        var severity = command.Status switch
        {
            AgentCommandStatus.Failed => "High",
            _ when command.ThreatCount > 0 => "High",
            AgentCommandStatus.Pending => "Low",
            AgentCommandStatus.Running => "Low",
            _ => "Informational"
        };

        var description = FirstValue(
            command.ErrorMessage,
            command.ResultMessage,
            command.Status switch
            {
                AgentCommandStatus.Pending =>
                    "The action is waiting for the Windows Agent.",
                AgentCommandStatus.Running =>
                    "The action is currently running on the endpoint.",
                _ => "The endpoint action completed."
            });

        var evidence = FirstValue(
            command.TargetPath,
            command.ThreatCount is null
                ? null
                : $"Threat count: {command.ThreatCount}",
            $"Command: {command.Type}");

        var action = command.Status == AgentCommandStatus.Failed
            ? "Review the command error, confirm the Agent is running, and retry the action."
            : command.ThreatCount > 0
                ? "Review the detected threats and verify that remediation completed."
                : command.Status is AgentCommandStatus.Pending or AgentCommandStatus.Running
                    ? "Wait for the Agent to finish and refresh the timeline."
                    : "No additional action is required.";

        return new ThreatTimelineItem(
            command.Id.ToString("N"),
            type,
            severity,
            CommandTitle(command.Type),
            description,
            command.Status.ToString(),
            isRemediation ? "Defender Action" : "Defender Scan",
            evidence,
            action,
            Utc(
                command.CompletedAtUtc ??
                command.StartedAtUtc ??
                command.RequestedAtUtc));
    }

    private static ThreatTimelineItem ToTimelineItem(
        SecurityPostureSnapshot posture)
    {
        var issues = new List<string>();

        AddControlIssue(
            issues,
            posture.DefenderEnabled,
            "Microsoft Defender");
        AddControlIssue(
            issues,
            posture.RealTimeProtectionEnabled,
            "Real-time protection");
        AddControlIssue(
            issues,
            posture.FirewallDomainEnabled,
            "Domain Firewall");
        AddControlIssue(
            issues,
            posture.FirewallPrivateEnabled,
            "Private Firewall");
        AddControlIssue(
            issues,
            posture.FirewallPublicEnabled,
            "Public Firewall");

        if (posture.RebootRequired == true)
        {
            issues.Add("Security reboot pending");
        }

        var description = issues.Count == 0
            ? "Defender, real-time protection, firewall profiles, signatures, and reboot state were healthy."
            : $"Posture issues: {string.Join(", ", issues)}.";

        var evidence =
            $"Risk {posture.RiskScore}/100; " +
            $"Signature age: {posture.AntivirusSignatureAgeDays?.ToString() ?? "unknown"} days";

        return new ThreatTimelineItem(
            posture.Id.ToString("N"),
            "Posture",
            RiskSeverity(posture.RiskScore),
            posture.RiskScore == 0
                ? "Security posture verified"
                : "Security posture requires attention",
            description,
            posture.RiskScore == 0 ? "Healthy" : "Attention",
            "Protection Controls",
            evidence,
            posture.RiskScore == 0
                ? "No action is required."
                : "Open Overview and correct each disabled or outdated protection control.",
            Utc(posture.CollectedAtUtc));
    }

    private static ThreatTimelineItem ToTimelineItem(
        EndpointTelemetryScan telemetry)
    {
        return new ThreatTimelineItem(
            telemetry.Id.ToString("N"),
            "Telemetry",
            RiskSeverity(telemetry.RiskScore),
            "Endpoint telemetry collected",
            $"The Agent analyzed {telemetry.ProcessCount} running processes and {telemetry.ActiveTcpConnectionCount} active TCP connections.",
            telemetry.RiskScore == 0 ? "Healthy" : "Attention",
            "Endpoint Activity",
            $"Risk {telemetry.RiskScore}/100; Scan: {telemetry.Id}",
            telemetry.RiskScore == 0
                ? "No action is required."
                : "Review Findings and Network Activity for the evidence that increased risk.",
            Utc(telemetry.CollectedAtUtc));
    }

    private static ThreatTimelineSummary BuildSummary(
        IReadOnlyList<ThreatTimelineItem> items,
        int deviceRisk,
        int? postureRisk,
        int? telemetryRisk)
    {
        DateTime? latestActivity = items.Count == 0
            ? null
            : items.Max(x => x.OccurredAtUtc);

        return new ThreatTimelineSummary(
            items.Count,
            items.Count(x => x.Severity == "Critical"),
            items.Count(x => x.Severity == "High"),
            items.Count(x => x.Severity == "Medium"),
            items.Count(x => x.Severity == "Low"),
            items.Count(x => x.Severity == "Informational"),
            items.Count(x =>
                x.Severity is "Critical" or "High" ||
                x.Type == "Finding" && x.Status == "Open"),
            items.Count(x => x.Type == "SecurityEvent"),
            items.Count(x => x.Type == "Finding"),
            items.Count(x => x.Type == "Remediation"),
            items.Count(x => x.Type == "Scan"),
            items.Count(x => x.Type == "Telemetry"),
            items.Count(x => x.Type == "Posture"),
            Math.Max(
                deviceRisk,
                Math.Max(
                    postureRisk ?? 0,
                    telemetryRisk ?? 0)),
            latestActivity);
    }

    private static int SeverityRank(string severity)
    {
        return severity switch
        {
            "Critical" => 5,
            "High" => 4,
            "Medium" => 3,
            "Low" => 2,
            _ => 1
        };
    }

    private static string RiskSeverity(int riskScore)
    {
        return riskScore switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 30 => "Medium",
            > 0 => "Low",
            _ => "Informational"
        };
    }

    private static string NormalizeSeverity(
        string? severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "critical" => "Critical",
            "high" => "High",
            "medium" => "Medium",
            "low" => "Low",
            _ => "Informational"
        };
    }

    private static string CommandTitle(
        AgentCommandType type)
    {
        return type switch
        {
            AgentCommandType.DefenderQuickScan =>
                "Microsoft Defender Quick Scan",
            AgentCommandType.DefenderFullScan =>
                "Microsoft Defender Full Scan",
            AgentCommandType.DefenderCustomScan =>
                "Microsoft Defender Custom Scan",
            AgentCommandType.DefenderUpdateSignatures =>
                "Defender signatures update",
            AgentCommandType.DefenderRemediateThreats =>
                "Microsoft Defender threat remediation",
            _ => "Endpoint security action"
        };
    }

    private static void AddControlIssue(
        ICollection<string> issues,
        bool? enabled,
        string controlName)
    {
        if (enabled == false)
        {
            issues.Add($"{controlName} disabled");
        }
        else if (enabled is null)
        {
            issues.Add($"{controlName} status unavailable");
        }
    }

    private static string FirstValue(
        params string?[] values)
    {
        return values.FirstOrDefault(
                   value =>
                       !string.IsNullOrWhiteSpace(value))
               ?.Trim()
               ?? "No additional evidence was supplied.";
    }

    private static string Limit(
        string value,
        int maximumLength)
    {
        return value.Length <= maximumLength
            ? value
            : value[..maximumLength] + "...";
    }

    private static DateTime Utc(DateTime value)
    {
        return value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(
                value,
                DateTimeKind.Utc)
        };
    }
}

public sealed record ThreatTimelineResponse(
    Guid DeviceId,
    string HostName,
    DateTime GeneratedAtUtc,
    int WindowHours,
    int ReturnedItems,
    ThreatTimelineSummary Summary,
    IReadOnlyList<ThreatTimelineItem> Items);

public sealed record ThreatTimelineSummary(
    int TotalItems,
    int CriticalCount,
    int HighCount,
    int MediumCount,
    int LowCount,
    int InformationalCount,
    int ActionRequiredCount,
    int SecurityEventCount,
    int FindingCount,
    int RemediationCount,
    int ScanCount,
    int TelemetryCount,
    int PostureCount,
    int CurrentRiskScore,
    DateTime? LatestActivityAtUtc);

public sealed record ThreatTimelineItem(
    string Id,
    string Type,
    string Severity,
    string Title,
    string Description,
    string Status,
    string Category,
    string Evidence,
    string RecommendedAction,
    DateTime OccurredAtUtc);

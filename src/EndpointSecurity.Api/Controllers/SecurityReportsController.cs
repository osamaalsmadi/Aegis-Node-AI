using EndpointSecurity.Api.Reporting;
using EndpointSecurity.Domain.Entities;
using EndpointSecurity.Domain.Enums;
using EndpointSecurity.Domain.Services;
using EndpointSecurity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Infrastructure;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/security-reports")]
public sealed class SecurityReportsController(
    EndpointSecurityDbContext dbContext)
    : ControllerBase
{
    [HttpGet("devices/{deviceId:guid}")]
    public async Task<ActionResult<SecurityReportPreviewResponse>>
        GetPreview(
            Guid deviceId,
            [FromQuery] int hours = 24,
            CancellationToken cancellationToken = default)
    {
        var model = await BuildReportAsync(
            deviceId,
            hours,
            cancellationToken);

        if (model is null)
        {
            return NotFound(new
            {
                message = "The requested endpoint was not found."
            });
        }

        return Ok(new SecurityReportPreviewResponse(
            model.GeneratedAtUtc,
            model.WindowHours,
            model.OverallRisk,
            model.RiskLevel,
            model.AssessmentStatus,
            model.ExecutiveSummary,
            model.Device,
            model.Counts,
            model.Protection,
            model.Issues,
            model.Recommendations,
            model.DataFreshness));
    }

    [HttpGet("devices/{deviceId:guid}/pdf")]
    [Produces("application/pdf")]
    public async Task<IActionResult> DownloadPdf(
        Guid deviceId,
        [FromQuery] int hours = 24,
        CancellationToken cancellationToken = default)
    {
        var model = await BuildReportAsync(
            deviceId,
            hours,
            cancellationToken);

        if (model is null)
        {
            return NotFound(new
            {
                message = "The requested endpoint was not found."
            });
        }

        QuestPDF.Settings.License = LicenseType.Community;

        var document = new SecurityReportDocument(model);
        var pdf = document.GeneratePdf();
        var hostName = SafeFilePart(model.Device.HostName);
        var date = model.GeneratedAtUtc.ToString("yyyy-MM-dd");

        return File(
            pdf,
            "application/pdf",
            $"Endpoint-Security-Report-{hostName}-{date}.pdf");
    }

    private async Task<SecurityReportModel?> BuildReportAsync(
        Guid deviceId,
        int hours,
        CancellationToken cancellationToken)
    {
        var safeHours = Math.Clamp(
            hours <= 0 ? 24 : hours,
            1,
            168);

        var generatedAtUtc = DateTime.UtcNow;
        var cutoff = generatedAtUtc.AddHours(-safeHours);
        var recentRiskCutoff = generatedAtUtc.AddMinutes(-30);

        var device = await dbContext.ManagedDevices
            .AsNoTracking()
            .SingleOrDefaultAsync(
                x => x.Id == deviceId,
                cancellationToken);

        if (device is null)
        {
            return null;
        }

        var posture = await dbContext.SecurityPostureSnapshots
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.CollectedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        var telemetry = await dbContext.EndpointTelemetryScans
            .AsNoTracking()
            .Where(x => x.DeviceId == deviceId)
            .OrderByDescending(x => x.CollectedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        var findings = telemetry is null
            ? new List<SecurityFinding>()
            : await dbContext.SecurityFindings
                .AsNoTracking()
                .Where(x => x.ScanId == telemetry.Id)
                .OrderByDescending(x => x.Severity)
                .ThenByDescending(x => x.DetectedAtUtc)
                .ToListAsync(cancellationToken);

        var connections = telemetry is null
            ? new List<NetworkConnectionSnapshot>()
            : await dbContext.NetworkConnectionSnapshots
                .AsNoTracking()
                .Where(x => x.ScanId == telemetry.Id)
                .OrderBy(x => x.ProcessName)
                .ThenBy(x => x.RemoteAddress)
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

        var events = await dbContext.WindowsSecurityEvents
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.OccurredAtUtc >= cutoff)
            .OrderByDescending(x => x.OccurredAtUtc)
            .Take(500)
            .ToListAsync(cancellationToken);

        var commands = await dbContext.Set<AgentCommand>()
            .AsNoTracking()
            .Where(x =>
                x.DeviceId == deviceId &&
                x.RequestedAtUtc >= cutoff)
            .OrderByDescending(x => x.RequestedAtUtc)
            .Take(100)
            .ToListAsync(cancellationToken);

        var reportFindings = findings
            .Select(finding =>
            {
                var fingerprint =
                    FindingFingerprint.Create(finding);

                latestReviews.TryGetValue(
                    fingerprint,
                    out var review);

                return new SecurityReportFinding(
                    finding.Severity.ToString(),
                    finding.Category.ToString(),
                    finding.Title,
                    finding.Description,
                    FindingEvidence(finding),
                    review?.Status.ToString() ?? "Open",
                    review?.AnalystNote,
                    Utc(finding.DetectedAtUtc));
            })
            .ToList();

        var activeFindings = reportFindings
            .Where(x => x.Status == "Open")
            .ToList();

        var currentFindingRisk = Math.Min(
            100,
            activeFindings.Sum(x => SeverityRisk(x.Severity)));

        var eventRisk = events
            .Where(x => x.OccurredAtUtc >= recentRiskCutoff)
            .Select(x => SeverityRisk(x.Severity))
            .DefaultIfEmpty(0)
            .Max();

        var overallRisk = Math.Max(
            device.RiskScore,
            Math.Max(
                posture?.RiskScore ?? 0,
                Math.Max(currentFindingRisk, eventRisk)));

        var reportEvents = events
            .OrderByDescending(x => SeverityRank(x.Severity))
            .ThenByDescending(x => x.OccurredAtUtc)
            .Take(20)
            .Select(x => new SecurityReportEvent(
                NormalizeSeverity(x.Severity),
                x.EventId,
                x.Category,
                x.Title,
                Limit(
                    $"{x.ProviderName}: {x.Message}",
                    600),
                Utc(x.OccurredAtUtc)))
            .ToList();

        var reportConnections = connections
            .Where(x =>
                !IsLoopback(x.RemoteAddress) &&
                x.RemotePort > 0)
            .GroupBy(x => new
            {
                ProcessName = x.ProcessName ?? "Unknown",
                x.ProcessId,
                x.RemoteAddress,
                x.RemotePort,
                x.State
            })
            .Select(group => new SecurityReportConnection(
                group.Key.ProcessName,
                group.Key.ProcessId,
                $"{group.Key.RemoteAddress}:{group.Key.RemotePort}",
                ServiceName(group.Key.RemotePort),
                group.Key.State,
                group.Count()))
            .OrderByDescending(x => x.ConnectionCount)
            .ThenBy(x => x.ProcessName)
            .Take(20)
            .ToList();

        var reportActions = commands
            .Take(20)
            .Select(command => new SecurityReportAction(
                CommandName(command.Type),
                command.Status.ToString(),
                Limit(
                    FirstValue(
                        command.ErrorMessage,
                        command.ResultMessage,
                        command.TargetPath,
                        "No additional result was supplied."),
                    500),
                Utc(command.RequestedAtUtc)))
            .ToList();

        var issues = BuildIssues(
            posture,
            activeFindings,
            events,
            commands);

        var recommendations = issues
            .Select(x => x.RecommendedAction)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        if (recommendations.Count == 0)
        {
            recommendations.Add(
                "No corrective action is currently required. Continue local monitoring and keep Microsoft Defender signatures current.");
        }

        var scanCount = commands.Count(x =>
            x.Type is
                AgentCommandType.DefenderQuickScan or
                AgentCommandType.DefenderFullScan or
                AgentCommandType.DefenderCustomScan);

        var remediationCount = commands.Count(x =>
            x.Type is
                AgentCommandType.DefenderUpdateSignatures or
                AgentCommandType.DefenderRemediateThreats);

        var highCriticalEvents = events.Count(x =>
            NormalizeSeverity(x.Severity) is
                "Critical" or "High");

        var counts = new SecurityReportCounts(
            activeFindings.Count,
            reportFindings.Count - activeFindings.Count,
            reportFindings.Count,
            telemetry?.ProcessCount ?? 0,
            telemetry?.ActiveTcpConnectionCount ?? 0,
            events.Count,
            highCriticalEvents,
            events.Count(x => x.EventId == 4625),
            events.Count(x =>
                x.ProviderName.Contains(
                    "Defender",
                    StringComparison.OrdinalIgnoreCase)),
            scanCount,
            remediationCount,
            commands.Count(x =>
                x.Status == AgentCommandStatus.Failed),
            connections.Count(x => IsSecurePort(x.RemotePort)),
            connections
                .Where(x => !IsLoopback(x.RemoteAddress))
                .Select(x => x.RemoteAddress)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count());

        var riskLevel = RiskLevel(overallRisk);
        var assessmentStatus = AssessmentStatus(
            issues,
            overallRisk);

        var executiveSummary =
            $"{device.HostName} has a current risk score of " +
            $"{overallRisk}/100 ({riskLevel}). " +
            $"The latest telemetry contains {counts.Processes} running " +
            $"processes, {counts.TcpConnections} active TCP connections, " +
            $"and {counts.OpenFindings} open finding(s). " +
            $"During the selected {safeHours}-hour window, the platform " +
            $"recorded {counts.SecurityEvents} Windows security event(s), " +
            $"including {counts.HighCriticalEvents} high or critical event(s) " +
            $"and {counts.FailedLogons} failed logon attempt(s).";

        return new SecurityReportModel(
            generatedAtUtc,
            safeHours,
            overallRisk,
            riskLevel,
            assessmentStatus,
            executiveSummary,
            new SecurityReportDevice(
                device.Id,
                device.HostName,
                device.OperatingSystem,
                device.OperatingSystemVersion,
                device.Architecture,
                device.AgentVersion,
                device.Status.ToString(),
                Utc(device.FirstSeenUtc),
                Utc(device.LastSeenUtc)),
            counts,
            new SecurityReportProtection(
                posture?.DefenderEnabled,
                posture?.RealTimeProtectionEnabled,
                posture?.AntivirusSignatureAgeDays,
                posture?.FirewallDomainEnabled,
                posture?.FirewallPrivateEnabled,
                posture?.FirewallPublicEnabled,
                posture?.RebootRequired,
                posture is null
                    ? null
                    : Utc(posture.CollectedAtUtc)),
            issues,
            recommendations,
            reportFindings,
            reportEvents,
            reportConnections,
            reportActions,
            new SecurityReportDataFreshness(
                telemetry is null
                    ? null
                    : Utc(telemetry.CollectedAtUtc),
                posture is null
                    ? null
                    : Utc(posture.CollectedAtUtc),
                events.Count == 0
                    ? null
                    : Utc(events.Max(x => x.OccurredAtUtc))));
    }

    private static List<SecurityReportIssue> BuildIssues(
        SecurityPostureSnapshot? posture,
        IReadOnlyList<SecurityReportFinding> findings,
        IReadOnlyList<WindowsSecurityEventRecord> events,
        IReadOnlyList<AgentCommand> commands)
    {
        var issues = new List<SecurityReportIssue>();

        AddControlIssue(
            issues,
            posture?.DefenderEnabled,
            "Microsoft Defender",
            "Microsoft Defender is disabled or its state is unavailable.",
            "Enable Microsoft Defender and run a quick scan to verify protection.",
            "High");

        AddControlIssue(
            issues,
            posture?.RealTimeProtectionEnabled,
            "Real-time Protection",
            "Real-time malware monitoring is disabled or unavailable.",
            "Enable real-time protection and confirm that policy does not disable it.",
            "High");

        AddControlIssue(
            issues,
            posture?.FirewallDomainEnabled,
            "Domain Firewall",
            "The Domain firewall profile is disabled or unavailable.",
            "Enable the Windows Domain firewall profile and review allowed rules.",
            "Medium");

        AddControlIssue(
            issues,
            posture?.FirewallPrivateEnabled,
            "Private Firewall",
            "The Private firewall profile is disabled or unavailable.",
            "Enable the Windows Private firewall profile and review allowed rules.",
            "Medium");

        AddControlIssue(
            issues,
            posture?.FirewallPublicEnabled,
            "Public Firewall",
            "The Public firewall profile is disabled or unavailable.",
            "Enable the Windows Public firewall profile before using untrusted networks.",
            "High");

        if (posture?.AntivirusSignatureAgeDays is > 1)
        {
            issues.Add(new SecurityReportIssue(
                "Medium",
                "Protection",
                "Defender signatures are outdated",
                $"Signature age: {posture.AntivirusSignatureAgeDays} days.",
                "Attention",
                "Update Microsoft Defender signatures, then verify that the signature age returns to zero or one day."));
        }

        if (posture?.RebootRequired == true)
        {
            issues.Add(new SecurityReportIssue(
                "Medium",
                "Posture",
                "Security reboot is pending",
                "Windows reports that a reboot is required to complete security maintenance.",
                "Attention",
                "Save work and restart Windows, then refresh the security posture."));
        }

        issues.AddRange(findings
            .OrderByDescending(x => SeverityRank(x.Severity))
            .Take(10)
            .Select(finding => new SecurityReportIssue(
                finding.Severity,
                finding.Category,
                finding.Title,
                finding.Evidence,
                finding.Status,
                FindingAction(finding))));

        var groupedEvents = events
            .Where(x =>
                NormalizeSeverity(x.Severity) is
                    "Critical" or "High")
            .GroupBy(x => new
            {
                x.EventId,
                x.Title,
                x.Category
            })
            .OrderByDescending(group =>
                SeverityRank(group.First().Severity))
            .ThenByDescending(group =>
                group.Max(x => x.OccurredAtUtc))
            .Take(6);

        foreach (var group in groupedEvents)
        {
            var securityEvent = group
                .OrderByDescending(x => x.OccurredAtUtc)
                .First();

            var action = securityEvent.EventId == 4625
                ? "Review the failed sign-in account, source, and nearby authentication activity. Change credentials if the attempt was not expected."
                : "Review this Windows event and verify that the related system change or activity was authorized.";

            issues.Add(new SecurityReportIssue(
                NormalizeSeverity(securityEvent.Severity),
                securityEvent.Category,
                securityEvent.Title,
                Limit(
                    $"Event ID {securityEvent.EventId}; " +
                    $"Provider: {securityEvent.ProviderName}; " +
                    $"Occurrences: {group.Count()}; " +
                    $"{securityEvent.Message}",
                    800),
                "Review",
                action));
        }

        var latestByType = commands
            .GroupBy(x => x.Type)
            .Select(group => group
                .OrderByDescending(x => x.RequestedAtUtc)
                .First());

        foreach (var command in latestByType.Where(x =>
                     x.Status is
                         AgentCommandStatus.Failed or
                         AgentCommandStatus.Pending or
                         AgentCommandStatus.Running))
        {
            var running = command.Status is
                AgentCommandStatus.Pending or
                AgentCommandStatus.Running;

            issues.Add(new SecurityReportIssue(
                running ? "Low" : "Medium",
                "Security Action",
                $"{CommandName(command.Type)} is {command.Status}",
                Limit(
                    FirstValue(
                        command.ErrorMessage,
                        command.ResultMessage,
                        command.TargetPath,
                        "No additional result was supplied."),
                    700),
                command.Status.ToString(),
                running
                    ? "Allow the Windows Agent to finish the action, then refresh the report."
                    : "Review the action error, confirm the Windows Agent is running, and retry the action if it is still required."));
        }

        return issues
            .OrderByDescending(x => SeverityRank(x.Severity))
            .ThenBy(x => x.Type)
            .ThenBy(x => x.Title)
            .Take(20)
            .ToList();
    }

    private static void AddControlIssue(
        ICollection<SecurityReportIssue> issues,
        bool? value,
        string title,
        string evidence,
        string action,
        string severity)
    {
        if (value == true)
        {
            return;
        }

        issues.Add(new SecurityReportIssue(
            value == false ? severity : "Medium",
            "Protection",
            title,
            evidence,
            value == false ? "Disabled" : "Unavailable",
            action));
    }

    private static string FindingAction(
        SecurityReportFinding finding)
    {
        return finding.Category switch
        {
            "SuspiciousFileLocation" =>
                "Verify the file publisher and digital signature. If the process is unexpected, stop it and scan the file with Microsoft Defender.",
            "SuspiciousCommandLine" =>
                "Review the full command line and parent process. Stop and isolate the process if the command was not authorized.",
            "UnsignedExecutable" =>
                "Verify the executable source and hash. Quarantine or remove it if its origin cannot be trusted.",
            _ =>
                "Review the evidence and use the Remediation Center when corrective action is required."
        };
    }

    private static string FindingEvidence(
        SecurityFinding finding)
    {
        return FirstValue(
            finding.FilePath,
            finding.CommandLine,
            finding.ProcessName is null
                ? null
                : $"{finding.ProcessName} (PID {finding.ProcessId?.ToString() ?? "unknown"})",
            finding.Description);
    }

    private static string AssessmentStatus(
        IReadOnlyList<SecurityReportIssue> issues,
        int risk)
    {
        if (issues.Count == 0)
        {
            return risk == 0
                ? "No current security issues detected"
                : "No active issue currently requires remediation";
        }

        var priorityCount = issues.Count(x =>
            x.Severity is "Critical" or "High");

        return priorityCount > 0
            ? $"{priorityCount} priority security item(s) require review"
            : $"{issues.Count} security item(s) require attention";
    }

    private static int SeverityRisk(string severity)
    {
        return NormalizeSeverity(severity) switch
        {
            "Critical" => 50,
            "High" => 30,
            "Medium" => 15,
            "Low" => 5,
            _ => 0
        };
    }

    private static int SeverityRank(string severity)
    {
        return NormalizeSeverity(severity) switch
        {
            "Critical" => 5,
            "High" => 4,
            "Medium" => 3,
            "Low" => 2,
            _ => 1
        };
    }

    private static string NormalizeSeverity(string? severity)
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

    private static string RiskLevel(int risk)
    {
        return risk switch
        {
            >= 80 => "Critical",
            >= 60 => "High",
            >= 30 => "Medium",
            > 0 => "Low",
            _ => "Secure"
        };
    }

    private static string CommandName(AgentCommandType type)
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
                "Defender Signatures Update",
            AgentCommandType.DefenderRemediateThreats =>
                "Defender Threat Remediation",
            _ => "Endpoint Security Action"
        };
    }

    private static string ServiceName(int port)
    {
        return port switch
        {
            443 => "HTTPS",
            853 => "DNS over TLS",
            993 => "IMAPS",
            995 => "POP3S",
            2053 or 2083 or 2087 or 2096 =>
                "Secure web service",
            _ => $"TCP/{port}"
        };
    }

    private static bool IsSecurePort(int port)
    {
        return port is
            443 or 853 or 993 or 995 or
            2053 or 2083 or 2087 or 2096;
    }

    private static bool IsLoopback(string value)
    {
        return value is "127.0.0.1" or "::1" ||
               value.StartsWith("127.", StringComparison.Ordinal);
    }

    private static string SafeFilePart(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var result = new string(value
            .Select(character =>
                invalid.Contains(character)
                    ? '-'
                    : character)
            .ToArray());

        return string.IsNullOrWhiteSpace(result)
            ? "Endpoint"
            : result;
    }

    private static string FirstValue(
        params string?[] values)
    {
        return values.FirstOrDefault(value =>
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

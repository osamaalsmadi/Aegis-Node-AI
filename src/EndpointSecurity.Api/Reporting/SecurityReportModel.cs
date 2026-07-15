namespace EndpointSecurity.Api.Reporting;

public sealed record SecurityReportModel(
    DateTime GeneratedAtUtc,
    int WindowHours,
    int OverallRisk,
    string RiskLevel,
    string AssessmentStatus,
    string ExecutiveSummary,
    SecurityReportDevice Device,
    SecurityReportCounts Counts,
    SecurityReportProtection Protection,
    IReadOnlyList<SecurityReportIssue> Issues,
    IReadOnlyList<string> Recommendations,
    IReadOnlyList<SecurityReportFinding> Findings,
    IReadOnlyList<SecurityReportEvent> Events,
    IReadOnlyList<SecurityReportConnection> Connections,
    IReadOnlyList<SecurityReportAction> Actions,
    SecurityReportDataFreshness DataFreshness);

public sealed record SecurityReportDevice(
    Guid Id,
    string HostName,
    string OperatingSystem,
    string OperatingSystemVersion,
    string Architecture,
    string AgentVersion,
    string Status,
    DateTime FirstSeenUtc,
    DateTime LastSeenUtc);

public sealed record SecurityReportCounts(
    int OpenFindings,
    int ReviewedFindings,
    int TotalFindings,
    int Processes,
    int TcpConnections,
    int SecurityEvents,
    int HighCriticalEvents,
    int FailedLogons,
    int DefenderEvents,
    int Scans,
    int RemediationActions,
    int FailedActions,
    int SecurePortConnections,
    int UniqueRemoteEndpoints);

public sealed record SecurityReportProtection(
    bool? DefenderEnabled,
    bool? RealTimeProtectionEnabled,
    int? AntivirusSignatureAgeDays,
    bool? FirewallDomainEnabled,
    bool? FirewallPrivateEnabled,
    bool? FirewallPublicEnabled,
    bool? RebootRequired,
    DateTime? CollectedAtUtc);

public sealed record SecurityReportIssue(
    string Severity,
    string Type,
    string Title,
    string Evidence,
    string Status,
    string RecommendedAction);

public sealed record SecurityReportFinding(
    string Severity,
    string Category,
    string Title,
    string Description,
    string Evidence,
    string Status,
    string? AnalystNote,
    DateTime DetectedAtUtc);

public sealed record SecurityReportEvent(
    string Severity,
    int EventId,
    string Category,
    string Title,
    string Evidence,
    DateTime OccurredAtUtc);

public sealed record SecurityReportConnection(
    string ProcessName,
    int ProcessId,
    string RemoteEndpoint,
    string Service,
    string State,
    int ConnectionCount);

public sealed record SecurityReportAction(
    string Type,
    string Status,
    string Result,
    DateTime RequestedAtUtc);

public sealed record SecurityReportDataFreshness(
    DateTime? TelemetryAtUtc,
    DateTime? PostureAtUtc,
    DateTime? LatestEventAtUtc);

public sealed record SecurityReportPreviewResponse(
    DateTime GeneratedAtUtc,
    int WindowHours,
    int OverallRisk,
    string RiskLevel,
    string AssessmentStatus,
    string ExecutiveSummary,
    SecurityReportDevice Device,
    SecurityReportCounts Counts,
    SecurityReportProtection Protection,
    IReadOnlyList<SecurityReportIssue> Issues,
    IReadOnlyList<string> Recommendations,
    SecurityReportDataFreshness DataFreshness);

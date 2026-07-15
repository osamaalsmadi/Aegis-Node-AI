using System.Globalization;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace EndpointSecurity.Api.Reporting;

public sealed class SecurityReportDocument(
    SecurityReportModel model) : IDocument
{
    private const string Navy = "#071827";
    private const string NavySoft = "#0D263A";
    private const string Panel = "#F6F9FC";
    private const string Border = "#DCE7EF";
    private const string Ink = "#102A3C";
    private const string Muted = "#617D90";
    private const string Cyan = "#08A8D6";
    private const string Green = "#159B6B";
    private const string Amber = "#D88416";
    private const string Red = "#D7435B";

    public DocumentMetadata GetMetadata()
    {
        return new DocumentMetadata
        {
            Title =
                $"Endpoint Security Report - {model.Device.HostName}",
            Author = "Endpoint Security Platform",
            Subject =
                "Evidence-based endpoint security assessment"
        };
    }

    public void Compose(IDocumentContainer container)
    {
        container.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.MarginHorizontal(32);
            page.MarginVertical(28);
            page.PageColor(Colors.White);
            page.ContentFromLeftToRight();
            page.DefaultTextStyle(style => style
                .FontFamily("Arial")
                .FontSize(9)
                .FontColor(Ink));

            page.Header().Element(ComposeHeader);

            page.Content()
                .PaddingVertical(16)
                .Column(column =>
                {
                    column.Spacing(13);

                    column.Item().Element(ComposeAssessment);
                    column.Item().Element(ComposeMetrics);
                    column.Item().Element(ComposeExecutiveSummary);
                    column.Item().Element(ComposeEndpointIdentity);

                    column.Item().PageBreak();
                    column.Item().Element(ComposeProtection);
                    column.Item().Element(ComposeFindings);

                    column.Item().PageBreak();
                    column.Item().Element(ComposeSecurityEvents);

                    column.Item().PageBreak();
                    column.Item().Element(ComposeNetworkActivity);

                    column.Item().PageBreak();
                    column.Item().Element(ComposeActionHistory);

                    column.Item().PageBreak();
                    column.Item().Element(ComposeRecommendations);
                    column.Item().Element(ComposeMethodology);
                });

            page.Footer().Element(ComposeFooter);
        });
    }

    private void ComposeHeader(IContainer container)
    {
        container.Row(row =>
        {
            row.ConstantItem(42)
                .Height(42)
                .Background(Cyan)
                .AlignCenter()
                .AlignMiddle()
                .Text("ESP")
                .Bold()
                .FontSize(12)
                .FontColor(Colors.White);

            row.RelativeItem()
                .PaddingLeft(12)
                .Column(column =>
                {
                    column.Item()
                        .Text("ENDPOINT SECURITY PLATFORM")
                        .Bold()
                        .FontSize(12)
                        .FontColor(Navy);

                    column.Item()
                        .Text("Professional Endpoint Security Assessment")
                        .FontSize(8)
                        .FontColor(Muted);
                });

            row.ConstantItem(185)
                .AlignRight()
                .Column(column =>
                {
                    column.Item()
                        .AlignRight()
                        .Text(model.Device.HostName)
                        .SemiBold()
                        .FontColor(Navy);

                    column.Item()
                        .AlignRight()
                        .Text(
                            $"Generated {FormatDate(model.GeneratedAtUtc)}")
                        .FontSize(8)
                        .FontColor(Muted);
                });
        });
    }

    private void ComposeAssessment(IContainer container)
    {
        container
            .Background(NavySoft)
            .Padding(18)
            .Row(row =>
            {
                row.ConstantItem(88)
                    .Height(88)
                    .Border(6)
                    .BorderColor(RiskColor(model.OverallRisk))
                    .AlignCenter()
                    .AlignMiddle()
                    .Column(column =>
                    {
                        column.Item()
                            .AlignCenter()
                            .Text(model.OverallRisk.ToString(
                                CultureInfo.InvariantCulture))
                            .Bold()
                            .FontSize(27)
                            .FontColor(Colors.White);

                        column.Item()
                            .AlignCenter()
                            .Text("RISK / 100")
                            .FontSize(6.5f)
                            .FontColor("#91B8CC");
                    });

                row.RelativeItem()
                    .PaddingLeft(18)
                    .Column(column =>
                    {
                        column.Spacing(5);

                        column.Item()
                            .Text($"{model.RiskLevel.ToUpperInvariant()} RISK")
                            .Bold()
                            .FontSize(8)
                            .FontColor(RiskColor(model.OverallRisk));

                        column.Item()
                            .Text(model.AssessmentStatus)
                            .Bold()
                            .FontSize(18)
                            .FontColor(Colors.White);

                        column.Item()
                            .Text(
                                $"Assessment window: last {model.WindowHours} hours | " +
                                $"Endpoint status: {model.Device.Status}")
                            .FontSize(8)
                            .FontColor("#A9C4D3");
                    });
            });
    }

    private void ComposeMetrics(IContainer container)
    {
        container.Row(row =>
        {
            row.Spacing(7);
            row.RelativeItem().Element(value =>
                ComposeMetric(
                    value,
                    model.Counts.OpenFindings.ToString(),
                    "OPEN FINDINGS"));
            row.RelativeItem().Element(value =>
                ComposeMetric(
                    value,
                    model.Counts.SecurityEvents.ToString(),
                    "WINDOWS EVENTS"));
            row.RelativeItem().Element(value =>
                ComposeMetric(
                    value,
                    model.Counts.Processes.ToString(),
                    "PROCESSES"));
            row.RelativeItem().Element(value =>
                ComposeMetric(
                    value,
                    model.Counts.TcpConnections.ToString(),
                    "TCP CONNECTIONS"));
        });
    }

    private static void ComposeMetric(
        IContainer container,
        string value,
        string label)
    {
        container
            .Border(1)
            .BorderColor(Border)
            .Background(Panel)
            .Padding(10)
            .Column(column =>
            {
                column.Item()
                    .Text(value)
                    .Bold()
                    .FontSize(18)
                    .FontColor(Navy);

                column.Item()
                    .Text(label)
                    .Bold()
                    .FontSize(6.5f)
                    .FontColor(Muted);
            });
    }

    private void ComposeExecutiveSummary(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "1",
            "Executive Summary",
            section =>
            {
                section.Item()
                    .Text(model.ExecutiveSummary)
                    .FontSize(9.5f)
                    .LineHeight(1.45f);

                section.Item()
                    .PaddingTop(7)
                    .Text(text =>
                    {
                        text.Span("Assessment: ")
                            .SemiBold();
                        text.Span(model.AssessmentStatus);
                    });
            });
    }

    private void ComposeEndpointIdentity(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "2",
            "Endpoint Identity and Data Window",
            section =>
            {
                section.Item().Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(105);
                        columns.RelativeColumn();
                        columns.ConstantColumn(105);
                        columns.RelativeColumn();
                    });

                    AddKeyValue(table, "Host name", model.Device.HostName);
                    AddKeyValue(table, "Device ID", model.Device.Id.ToString());
                    AddKeyValue(
                        table,
                        "Operating system",
                        $"{model.Device.OperatingSystem} " +
                        $"{model.Device.OperatingSystemVersion}");
                    AddKeyValue(table, "Architecture", model.Device.Architecture);
                    AddKeyValue(table, "Agent version", model.Device.AgentVersion);
                    AddKeyValue(table, "Device state", model.Device.Status);
                    AddKeyValue(
                        table,
                        "First seen",
                        FormatDate(model.Device.FirstSeenUtc));
                    AddKeyValue(
                        table,
                        "Last seen",
                        FormatDate(model.Device.LastSeenUtc));
                });
            });
    }

    private void ComposeProtection(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "3",
            "Microsoft Defender and Firewall",
            section =>
            {
                section.Item().Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.RelativeColumn(2);
                        columns.RelativeColumn();
                        columns.RelativeColumn(2.3f);
                    });

                    table.Header(header =>
                    {
                        header.Cell().Element(TableHeader).Text("CONTROL");
                        header.Cell().Element(TableHeader).Text("STATE");
                        header.Cell().Element(TableHeader).Text("EVIDENCE");
                    });

                    AddProtectionRow(
                        table,
                        "Microsoft Defender",
                        model.Protection.DefenderEnabled,
                        "Antivirus engine state");

                    AddProtectionRow(
                        table,
                        "Real-time Protection",
                        model.Protection.RealTimeProtectionEnabled,
                        "Live malware monitoring");

                    AddProtectionRow(
                        table,
                        "Domain Firewall",
                        model.Protection.FirewallDomainEnabled,
                        "Domain network profile");

                    AddProtectionRow(
                        table,
                        "Private Firewall",
                        model.Protection.FirewallPrivateEnabled,
                        "Private network profile");

                    AddProtectionRow(
                        table,
                        "Public Firewall",
                        model.Protection.FirewallPublicEnabled,
                        "Public network profile");

                    table.Cell().Element(TableCell).Text("Signature age");
                    table.Cell().Element(TableCell).Text(
                        model.Protection.AntivirusSignatureAgeDays is null
                            ? "Unavailable"
                            : $"{model.Protection.AntivirusSignatureAgeDays} day(s)");
                    table.Cell().Element(TableCell).Text(
                        "Latest Microsoft Defender signature age");

                    table.Cell().Element(TableCell).Text("Security reboot");
                    table.Cell().Element(TableCell).Text(
                        model.Protection.RebootRequired switch
                        {
                            true => "Required",
                            false => "Not required",
                            _ => "Unavailable"
                        });
                    table.Cell().Element(TableCell).Text(
                        "Pending security maintenance state");
                });
            });
    }

    private void ComposeFindings(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "4",
            "Current Security Findings",
            section =>
            {
                section.Item()
                    .Text(
                        $"Latest telemetry: {model.Counts.OpenFindings} open, " +
                        $"{model.Counts.ReviewedFindings} reviewed, " +
                        $"{model.Counts.TotalFindings} total finding(s).")
                    .FontColor(Muted);

                if (model.Findings.Count == 0)
                {
                    section.Item().Element(value =>
                        ComposeNoIssues(
                            value,
                            "No finding was returned by the latest endpoint telemetry."));
                    return;
                }

                foreach (var finding in model.Findings.Take(3))
                {
                    section.Item()
                        .PaddingTop(7)
                        .Border(1)
                        .BorderColor(Border)
                        .Padding(10)
                        .Column(column =>
                        {
                            column.Spacing(4);

                            column.Item().Row(row =>
                            {
                                row.RelativeItem()
                                    .Text(
                                        $"{finding.Severity.ToUpperInvariant()} | " +
                                        finding.Category)
                                    .Bold()
                                    .FontSize(7)
                                    .FontColor(SeverityColor(finding.Severity));

                                row.ConstantItem(90)
                                    .AlignRight()
                                    .Text(finding.Status)
                                    .SemiBold()
                                    .FontSize(7)
                                    .FontColor(StatusColor(finding.Status));
                            });

                            column.Item()
                                .Text(finding.Title)
                                .SemiBold()
                                .FontSize(10);

                            column.Item()
                                .Text(Compact(finding.Description, 180))
                                .FontColor(Muted)
                                .LineHeight(1.3f);

                            column.Item().Text(text =>
                            {
                                text.Span("Evidence: ").SemiBold();
                                text.Span(Compact(finding.Evidence, 160));
                            });

                            if (!string.IsNullOrWhiteSpace(
                                    finding.AnalystNote))
                            {
                                column.Item().Text(text =>
                                {
                                    text.Span("Analyst note: ").SemiBold();
                                    text.Span(Compact(finding.AnalystNote, 160));
                                });
                            }
                        });
                }
            });
    }

    private void ComposeSecurityEvents(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "5",
            "Windows Security Events",
            section =>
            {
                section.Item()
                    .Text(
                        $"{model.Counts.SecurityEvents} event(s) in the selected window; " +
                        $"{model.Counts.HighCriticalEvents} high or critical; " +
                        $"{model.Counts.FailedLogons} failed logon(s); " +
                        $"{model.Counts.DefenderEvents} Defender event(s).")
                    .FontColor(Muted);

                if (model.Events.Count == 0)
                {
                    section.Item()
                        .PaddingTop(7)
                        .Element(value => ComposeNoIssues(
                            value,
                            "No Windows security event was recorded in this window."));
                    return;
                }

                section.Item().PaddingTop(7).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(62);
                        columns.ConstantColumn(48);
                        columns.RelativeColumn(1.4f);
                        columns.RelativeColumn(2.6f);
                    });

                    table.Header(header =>
                    {
                        header.Cell().Element(TableHeader).Text("TIME UTC");
                        header.Cell().Element(TableHeader).Text("SEVERITY");
                        header.Cell().Element(TableHeader).Text("EVENT");
                        header.Cell().Element(TableHeader).Text("EVIDENCE");
                    });

                    foreach (var securityEvent in model.Events.Take(8))
                    {
                        table.Cell().Element(TableCell).Text(
                            securityEvent.OccurredAtUtc.ToString(
                                "dd MMM HH:mm",
                                CultureInfo.InvariantCulture));

                        table.Cell().Element(TableCell).Text(
                                securityEvent.Severity)
                            .SemiBold()
                            .FontColor(
                                SeverityColor(securityEvent.Severity));

                        table.Cell().Element(TableCell).Text(
                            $"{securityEvent.Title}\n" +
                            $"ID {securityEvent.EventId} | " +
                            securityEvent.Category);

                        table.Cell().Element(TableCell).Text(
                            Compact(securityEvent.Evidence, 140));
                    }
                });
            });
    }

    private void ComposeNetworkActivity(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "6",
            "Network Activity",
            section =>
            {
                section.Item()
                    .Text(
                        $"{model.Counts.TcpConnections} active TCP connection(s), " +
                        $"{model.Counts.UniqueRemoteEndpoints} unique remote endpoint(s), " +
                        $"and {model.Counts.SecurePortConnections} connection(s) " +
                        "using known TLS-capable ports.")
                    .FontColor(Muted);

                if (model.Connections.Count == 0)
                {
                    section.Item()
                        .PaddingTop(7)
                        .Element(value => ComposeNoIssues(
                            value,
                            "No external TCP connection was returned by the latest telemetry."));
                    return;
                }

                section.Item().PaddingTop(7).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.RelativeColumn(1.5f);
                        columns.RelativeColumn(2.2f);
                        columns.RelativeColumn();
                        columns.ConstantColumn(55);
                    });

                    table.Header(header =>
                    {
                        header.Cell().Element(TableHeader).Text("PROCESS");
                        header.Cell().Element(TableHeader).Text("REMOTE ENDPOINT");
                        header.Cell().Element(TableHeader).Text("SERVICE / STATE");
                        header.Cell().Element(TableHeader).Text("COUNT");
                    });

                    foreach (var connection in model.Connections.Take(12))
                    {
                        table.Cell().Element(TableCell).Text(
                            $"{connection.ProcessName}\nPID {connection.ProcessId}");
                        table.Cell().Element(TableCell).Text(
                            connection.RemoteEndpoint);
                        table.Cell().Element(TableCell).Text(
                            $"{connection.Service} | {connection.State}");
                        table.Cell().Element(TableCell).Text(
                            connection.ConnectionCount.ToString());
                    }
                });

                section.Item()
                    .PaddingTop(6)
                    .Text(
                        "Network scope labels and secure-port counts describe connection characteristics; they do not independently prove that a destination is safe or malicious.")
                    .Italic()
                    .FontSize(7.5f)
                    .FontColor(Muted);
            });
    }

    private void ComposeActionHistory(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "7",
            "Scan and Remediation History",
            section =>
            {
                section.Item()
                    .Text(
                        $"{model.Counts.Scans} scan(s), " +
                        $"{model.Counts.RemediationActions} remediation action(s), " +
                        $"and {model.Counts.FailedActions} failed action(s) " +
                        "inside the selected report window.")
                    .FontColor(Muted);

                if (model.Actions.Count == 0)
                {
                    section.Item()
                        .PaddingTop(7)
                        .Element(value => ComposeNoIssues(
                            value,
                            "No scan or remediation action was recorded in this window."));
                    return;
                }

                section.Item().PaddingTop(7).Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(82);
                        columns.RelativeColumn(1.5f);
                        columns.ConstantColumn(58);
                        columns.RelativeColumn(2.4f);
                    });

                    table.Header(header =>
                    {
                        header.Cell().Element(TableHeader).Text("REQUESTED UTC");
                        header.Cell().Element(TableHeader).Text("ACTION");
                        header.Cell().Element(TableHeader).Text("STATUS");
                        header.Cell().Element(TableHeader).Text("RESULT");
                    });

                    foreach (var action in model.Actions.Take(8))
                    {
                        table.Cell().Element(TableCell).Text(
                            action.RequestedAtUtc.ToString(
                                "dd MMM yyyy HH:mm",
                                CultureInfo.InvariantCulture));
                        table.Cell().Element(TableCell).Text(action.Type);
                        table.Cell().Element(TableCell).Text(action.Status)
                            .SemiBold()
                            .FontColor(StatusColor(action.Status));
                        table.Cell().Element(TableCell).Text(Compact(action.Result, 140));
                    }
                });
            });
    }

    private void ComposeRecommendations(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "8",
            "Prioritized Recommendations",
            section =>
            {
                var recommendations = model.Recommendations
                    .Take(6)
                    .ToList();

                for (var index = 0;
                     index < recommendations.Count;
                     index++)
                {
                    var recommendation = recommendations[index];

                    section.Item()
                        .PaddingBottom(5)
                        .Row(row =>
                        {
                            row.ConstantItem(24)
                                .Height(24)
                                .Background(Cyan)
                                .AlignCenter()
                                .AlignMiddle()
                                .Text((index + 1).ToString())
                                .Bold()
                                .FontColor(Colors.White);

                            row.RelativeItem()
                                .PaddingLeft(9)
                                .PaddingTop(3)
                                .Text(Compact(recommendation, 220))
                                .LineHeight(1.35f);
                        });
                }
            });
    }

    private void ComposeMethodology(IContainer container)
    {
        ComposeSectionTitle(
            container,
            "9",
            "Data Freshness and Methodology",
            section =>
            {
                section.Item().Table(table =>
                {
                    table.ColumnsDefinition(columns =>
                    {
                        columns.ConstantColumn(120);
                        columns.RelativeColumn();
                    });

                    AddKeyValue(
                        table,
                        "Telemetry snapshot",
                        FormatOptionalDate(
                            model.DataFreshness.TelemetryAtUtc));
                    AddKeyValue(
                        table,
                        "Protection posture",
                        FormatOptionalDate(
                            model.DataFreshness.PostureAtUtc));
                    AddKeyValue(
                        table,
                        "Latest security event",
                        FormatOptionalDate(
                            model.DataFreshness.LatestEventAtUtc));
                    AddKeyValue(
                        table,
                        "Report generated",
                        FormatDate(model.GeneratedAtUtc));
                });

                section.Item()
                    .PaddingTop(8)
                    .Text(
                        "This report is generated locally from endpoint telemetry stored by Endpoint Security Platform. Risk is calculated from current findings, Defender and firewall posture, recent Windows event severity, and the latest endpoint state. The report does not classify normal network destinations as threats without supporting evidence.")
                    .FontSize(8)
                    .LineHeight(1.4f)
                    .FontColor(Muted);
            });
    }

    private static string Compact(
        string? value,
        int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "Unavailable";

        var normalized = value
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Trim();

        while (normalized.Contains(
                   "  ",
                   StringComparison.Ordinal))
        {
            normalized = normalized.Replace(
                "  ",
                " ",
                StringComparison.Ordinal);
        }

        if (normalized.Length <= maximumLength)
            return normalized;

        return normalized[..Math.Max(1, maximumLength - 1)] +
               "\u2026";
    }

    private static void ComposeSectionTitle(
        IContainer container,
        string number,
        string title,
        Action<ColumnDescriptor> content)
    {
        container.Column(column =>
        {
            column.Spacing(7);

            column.Item()
                .BorderBottom(1)
                .BorderColor(Border)
                .PaddingBottom(6)
                .Row(row =>
                {
                    row.ConstantItem(24)
                        .Height(24)
                        .Background(Navy)
                        .AlignCenter()
                        .AlignMiddle()
                        .Text(number)
                        .Bold()
                        .FontColor(Colors.White);

                    row.RelativeItem()
                        .PaddingLeft(9)
                        .PaddingTop(3)
                        .Text(title)
                        .Bold()
                        .FontSize(12)
                        .FontColor(Navy);
                });

            content(column);
        });
    }

    private static void AddProtectionRow(
        TableDescriptor table,
        string control,
        bool? enabled,
        string evidence)
    {
        table.Cell().Element(TableCell).Text(control);
        table.Cell().Element(TableCell).Text(
                enabled switch
                {
                    true => "Enabled",
                    false => "Disabled",
                    _ => "Unavailable"
                })
            .SemiBold()
            .FontColor(enabled switch
            {
                true => Green,
                false => Red,
                _ => Amber
            });
        table.Cell().Element(TableCell).Text(evidence);
    }

    private static void AddKeyValue(
        TableDescriptor table,
        string key,
        string value)
    {
        table.Cell().Element(KeyCell).Text(key);
        table.Cell().Element(ValueCell).Text(value);
    }

    private static IContainer TableHeader(IContainer container)
    {
        return container
            .Background(Navy)
            .PaddingVertical(6)
            .PaddingHorizontal(7)
            .DefaultTextStyle(style => style
                .Bold()
                .FontSize(6.5f)
                .FontColor(Colors.White));
    }

    private static IContainer TableCell(IContainer container)
    {
        return container
            .BorderBottom(1)
            .BorderColor(Border)
            .PaddingVertical(6)
            .PaddingHorizontal(7)
            .DefaultTextStyle(style => style
                .FontSize(7.5f));
    }

    private static IContainer KeyCell(IContainer container)
    {
        return TableCell(container)
            .Background(Panel)
            .DefaultTextStyle(style => style.SemiBold());
    }

    private static IContainer ValueCell(IContainer container)
    {
        return TableCell(container);
    }

    private static void ComposeNoIssues(
        IContainer container,
        string message)
    {
        container
            .Background("#EAF8F2")
            .Border(1)
            .BorderColor("#B9E6D4")
            .Padding(10)
            .Text(message)
            .SemiBold()
            .FontColor(Green);
    }

    private void ComposeFooter(IContainer container)
    {
        container
            .BorderTop(1)
            .BorderColor(Border)
            .PaddingTop(7)
            .Row(row =>
            {
                row.RelativeItem()
                    .Text(
                        "CONFIDENTIAL | Generated locally by Endpoint Security Platform")
                    .FontSize(7)
                    .FontColor(Muted);

                row.ConstantItem(110)
                    .AlignRight()
                    .Text(text =>
                    {
                        text.DefaultTextStyle(style => style
                            .FontSize(7)
                            .FontColor(Muted));
                        text.Span("Page ");
                        text.CurrentPageNumber();
                        text.Span(" of ");
                        text.TotalPages();
                    });
            });
    }

    private static string RiskColor(int risk)
    {
        return risk switch
        {
            >= 60 => Red,
            >= 30 => Amber,
            > 0 => "#E8A63A",
            _ => Green
        };
    }

    private static string SeverityColor(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "critical" or "high" => Red,
            "medium" => Amber,
            "low" => Cyan,
            _ => Muted
        };
    }

    private static string StatusColor(string status)
    {
        return status.ToLowerInvariant() switch
        {
            "completed" or "healthy" or "resolved" or
                "falsepositive" => Green,
            "failed" or "disabled" => Red,
            "open" or "pending" or "running" or
                "attention" or "review" => Amber,
            _ => Muted
        };
    }

    private static string FormatDate(DateTime value)
    {
        return value.ToUniversalTime().ToString(
            "dd MMM yyyy HH:mm 'UTC'",
            CultureInfo.InvariantCulture);
    }

    private static string FormatOptionalDate(DateTime? value)
    {
        return value is null
            ? "Not available"
            : FormatDate(value.Value);
    }
}

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace EndpointSecurity.Api.Controllers;

[ApiController]
[Route("api/ai-security")]
public sealed class AiSecurityController : ControllerBase
{
    private const string ModelName = "qwen2.5:1.5b";
    private static readonly Uri OllamaBaseAddress =
        new("http://127.0.0.1:11434");

    private static readonly HttpClient OllamaClient = new()
    {
        BaseAddress = OllamaBaseAddress,
        Timeout = Timeout.InfiniteTimeSpan
    };

    private static readonly ConcurrentDictionary<string, AiCacheEntry>
        AiCache = new();

    private readonly ILogger<AiSecurityController> _logger;

    public AiSecurityController(
        ILogger<AiSecurityController> logger)
    {
        _logger = logger;
    }

    [HttpGet("status")]
    public async Task<IActionResult> GetStatus(
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);

            timeout.CancelAfter(TimeSpan.FromSeconds(3));

            using var response = await OllamaClient.GetAsync(
                "/api/tags",
                timeout.Token);

            return Ok(new
            {
                available = response.IsSuccessStatusCode,
                provider = "Ollama",
                model = ModelName,
                local = true,
                maximumAnalysisSeconds = 18
            });
        }
        catch
        {
            return Ok(new
            {
                available = false,
                provider = "Ollama",
                model = ModelName,
                local = true,
                maximumAnalysisSeconds = 18
            });
        }
    }

    [HttpPost("analyze")]
    public async Task<IActionResult> Analyze(
        [FromBody] AnalyzeSecurityRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Context.ValueKind is
            JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return BadRequest(new
            {
                message = "Security evidence is required."
            });
        }

        var stopwatch = Stopwatch.StartNew();
        var arabic = IsArabicRequest(
            request.Language,
            request.Question);

        var evidence = EvidenceSnapshot.Read(request.Context);
        var grounded = BuildGroundedAnalysis(evidence, arabic);

        var enrichment = await TryGetAiEnrichmentAsync(
            evidence,
            request.Question,
            arabic,
            cancellationToken);

        var observations = grounded.Observations.ToList();
        var actions = grounded.PriorityActions.ToList();

        if (enrichment is not null)
        {
            AddUnique(
                observations,
                enrichment.ExtraObservation,
                arabic);

            AddUnique(
                actions,
                enrichment.ExtraAction,
                arabic);
        }

        stopwatch.Stop();

        return Ok(new
        {
            model = ModelName,
            provider = "Verified security engine + local Ollama",
            local = true,
            language = arabic ? "Arabic" : "English",
            aiEnhanced = enrichment is not null,
            responseTimeMs = stopwatch.ElapsedMilliseconds,
            generatedAtUtc = DateTime.UtcNow,
            evidence = new
            {
                riskScore = evidence.RiskScore,
                activeAlertCount = evidence.Findings.Count,
                protectionIssueCount =
                    CountControlIssues(evidence),
                totalIssueCount =
                    evidence.Findings.Count +
                    CountControlIssues(evidence),
                securityEventsLast24Hours =
                    evidence.EventsLast24Hours,
                highOrCriticalEvents =
                    evidence.HighOrCriticalEvents,
                failedSignIns = evidence.FailedSignIns,
                processCount = evidence.ProcessCount,
                activeTcpConnectionCount =
                    evidence.ActiveTcpConnections,
                defenderEnabled = evidence.DefenderEnabled,
                realTimeProtectionEnabled =
                    evidence.RealTimeProtectionEnabled,
                firewallDomainEnabled =
                    evidence.FirewallDomainEnabled,
                firewallPrivateEnabled =
                    evidence.FirewallPrivateEnabled,
                firewallPublicEnabled =
                    evidence.FirewallPublicEnabled,
                rebootRequired = evidence.RebootRequired,
                antivirusSignatureAgeDays =
                    evidence.AntivirusSignatureAgeDays
            },
            issues = evidence.Findings.Select(
                (finding, index) => new
                {
                    number = index + 1,
                    type = finding.Category,
                    severity = finding.Severity,
                    title = finding.Title,
                    processName = finding.ProcessName,
                    processId = finding.ProcessId,
                    filePath = finding.FilePath,
                    solution = BuildFindingSolution(
                        finding,
                        arabic)
                }),
            analysis = new
            {
                overallRisk = GetRiskLabel(
                    evidence.RiskScore,
                    arabic),
                headline = grounded.Headline,
                executiveSummary = grounded.Summary,
                observations = observations.Select(
                    (text, index) =>
                    {
                        var findingIndex = index - 5;

                        var severityCode =
                            findingIndex >= 0 &&
                            findingIndex <
                            evidence.Findings.Count
                                ? evidence.Findings[
                                    findingIndex].Severity
                                : "Info";

                        var severity = arabic
                            ? severityCode.ToLowerInvariant()
                                switch
                                {
                                    "critical" =>
                                        "\u062d\u0631\u062c\u0629",
                                    "high" =>
                                        "\u0639\u0627\u0644\u064a\u0629",
                                    "medium" =>
                                        "\u0645\u062a\u0648\u0633\u0637\u0629",
                                    "low" =>
                                        "\u0645\u0646\u062e\u0641\u0636\u0629",
                                    _ =>
                                        "\u0645\u0639\u0644\u0648\u0645\u0627\u062a\u064a\u0629"
                                }
                            : severityCode;

                        var title = arabic
                            ? index switch
                            {
                                0 =>
                                    "\u0627\u0644\u062d\u0627\u0644\u0629 \u0627\u0644\u0639\u0627\u0645\u0629 \u0644\u0644\u0645\u062e\u0627\u0637\u0631",
                                1 =>
                                    "\u0627\u0644\u062a\u0646\u0628\u064a\u0647\u0627\u062a \u0648\u0627\u0644\u0623\u062d\u062f\u0627\u062b \u0627\u0644\u0623\u0645\u0646\u064a\u0629",
                                2 =>
                                    "Microsoft Defender \u0648\u0627\u0644\u062d\u0645\u0627\u064a\u0629 \u0627\u0644\u0641\u0648\u0631\u064a\u0629",
                                3 =>
                                    "Domain / Private / Public Firewall",
                                4 =>
                                    "\u0627\u0644\u0639\u0645\u0644\u064a\u0627\u062a \u0648\u0627\u062a\u0635\u0627\u0644\u0627\u062a TCP",
                                _ =>
                                    findingIndex >= 0 &&
                                    findingIndex <
                                    evidence.Findings.Count
                                        ? $"\u0627\u0644\u0645\u0634\u0643\u0644\u0629 {findingIndex + 1}: " +
                                          LocalizeCategory(
                                              evidence.Findings[
                                                  findingIndex]
                                                  .Category,
                                              true)
                                        : "\u0645\u0644\u0627\u062d\u0638\u0629 \u0625\u0636\u0627\u0641\u064a\u0629"
                            }
                            : index switch
                            {
                                0 => "Overall risk",
                                1 => "Alerts and security events",
                                2 => "Defender and real-time protection",
                                3 => "Domain / Private / Public Firewall",
                                4 => "Processes and TCP connections",
                                _ =>
                                    findingIndex >= 0 &&
                                    findingIndex <
                                    evidence.Findings.Count
                                        ? $"Issue {findingIndex + 1}"
                                        : "Additional observation"
                            };

                        return new
                        {
                            severity,
                            title,
                            evidence = text,
                            description = text,
                            details = text
                        };
                    })
                    .ToArray(),
                priorityActions = actions.Select(
                    (text, index) =>
                    {
                        var reason = arabic
                            ? "\u0647\u0630\u0627 \u0627\u0644\u0625\u062c\u0631\u0627\u0621 \u0645\u0631\u062a\u0628\u0637 \u0645\u0628\u0627\u0634\u0631\u0629 \u0628\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u062c\u0647\u0627\u0632 \u0627\u0644\u062d\u0627\u0644\u064a\u0629 \u0648\u0627\u0644\u0645\u0634\u0643\u0644\u0629 \u0627\u0644\u0645\u0643\u062a\u0634\u0641\u0629."
                            : "This action is directly related to the current endpoint evidence and detected issue.";

                        return new
                        {
                            priority = index + 1,
                            title = arabic
                                ? $"\u0627\u0644\u0625\u062c\u0631\u0627\u0621 {index + 1}"
                                : $"Action {index + 1}",
                            action = text,
                            reason,
                            description = text,
                            details = reason
                        };
                    })
                    .ToArray()
            }
        });
    }

    private async Task<AiEnrichment?>
        TryGetAiEnrichmentAsync(
            EvidenceSnapshot evidence,
            string? question,
            bool arabic,
            CancellationToken cancellationToken)
    {
        var cacheMaterial = string.Join(
            "|",
            arabic,
            question?.Trim(),
            evidence.RiskScore,
            evidence.Findings.Count,
            evidence.ProcessCount,
            evidence.ActiveTcpConnections,
            evidence.EventsLast24Hours,
            evidence.HighOrCriticalEvents,
            evidence.FailedSignIns,
            string.Join(
                ";",
                evidence.Findings.Select(x =>
                    $"{x.Title}:{x.Severity}:{x.FilePath}")));

        var cacheKey = Convert.ToHexString(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(cacheMaterial)));

        if (AiCache.TryGetValue(cacheKey, out var cached) &&
            DateTime.UtcNow - cached.CreatedAtUtc <
            TimeSpan.FromMinutes(10))
        {
            return cached.Value;
        }

        try
        {
            using var timeout =
                CancellationTokenSource.CreateLinkedTokenSource(
                    cancellationToken);

            timeout.CancelAfter(TimeSpan.FromSeconds(15));

            var prompt = BuildCompactPrompt(
                evidence,
                question,
                arabic);

            var body = JsonSerializer.Serialize(new
            {
                model = ModelName,
                prompt,
                stream = false,
                format = "json",
                keep_alive = "30m",
                options = new
                {
                    temperature = 0,
                    num_ctx = 1024,
                    num_predict = 80,
                    top_p = 0.8
                }
            });

            using var content = new StringContent(
                body,
                Encoding.UTF8,
                "application/json");

            using var response = await OllamaClient.PostAsync(
                "/api/generate",
                content,
                timeout.Token);

            if (!response.IsSuccessStatusCode)
                return null;

            var responseBody = await response.Content
                .ReadAsStringAsync(timeout.Token);

            using var envelope = JsonDocument.Parse(responseBody);

            if (!TryGetProperty(
                    envelope.RootElement,
                    "response",
                    out var responseValue))
            {
                return null;
            }

            var responseJson = responseValue.GetString();

            if (string.IsNullOrWhiteSpace(responseJson))
                return null;

            using var resultDocument =
                JsonDocument.Parse(responseJson);

            var extraObservation = ReadString(
                resultDocument.RootElement,
                "extraObservation");

            var extraAction = ReadString(
                resultDocument.RootElement,
                "extraAction");

            extraObservation = ValidateAiText(
                extraObservation,
                arabic);

            extraAction = ValidateAiText(
                extraAction,
                arabic);

            if (extraObservation is null && extraAction is null)
                return null;

            var result = new AiEnrichment(
                extraObservation,
                extraAction);

            AiCache[cacheKey] = new AiCacheEntry(
                result,
                DateTime.UtcNow);

            return result;
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation(
                "Local AI enrichment exceeded its time limit. " +
                "Verified analysis was returned without delay.");

            return null;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(
                exception,
                "Local AI enrichment was unavailable. " +
                "Verified analysis was returned.");

            return null;
        }
    }

    private static GroundedAnalysis BuildGroundedAnalysis(
        EvidenceSnapshot evidence,
        bool arabic)
    {
        // Keep the API value in English because the dashboard uses it
        // to select the correct badge color. The visible text remains
        // fully localized below.
        var riskCode = GetRiskLabel(
            evidence.RiskScore,
            false);

        var riskLabel = GetRiskLabel(
            evidence.RiskScore,
            arabic);

        var controlIssueCount = CountControlIssues(evidence);

        if (!arabic)
        {
            return BuildEnglishAnalysis(
                evidence,
                riskLabel,
                controlIssueCount);
        }

        var alertCount = evidence.Findings.Count;
        var firewallState = BuildFirewallState(
            evidence,
            true);

        var headline = evidence.RiskScore == 0 &&
                       alertCount == 0 &&
                       controlIssueCount == 0
            ? "الجهاز بحالة أمنية جيدة حاليًا"
            : $"تم اكتشاف {alertCount + controlIssueCount} " +
              "مشكلة أو تنبيه يحتاج المراجعة";

        var summary =
            $"درجة الخطر الحالية {evidence.RiskScore}/100 " +
            $"({riskLabel}). عدد التنبيهات الأمنية النشطة: " +
            $"{alertCount}، ومشكلات إعدادات الحماية: " +
            $"{controlIssueCount}. يوجد حاليًا " +
            $"{evidence.ProcessCount} عملية و" +
            $"{evidence.ActiveTcpConnections} اتصال TCP نشط. " +
            $"حالة الجدار الناري: {firewallState}.";

        var observations = new List<string>
        {
            $"الخطر العام: {evidence.RiskScore}/100 — " +
            $"{riskLabel}.",

            $"التنبيهات: {alertCount} تنبيه نشط. " +
            $"أحداث Windows الأمنية خلال 24 ساعة: " +
            $"{evidence.EventsLast24Hours}، منها " +
            $"{evidence.HighOrCriticalEvents} عالي أو حرج، " +
            $"ومحاولات تسجيل الدخول الفاشلة: " +
            $"{evidence.FailedSignIns}.",

            $"الحماية: Microsoft Defender " +
            $"{EnabledText(evidence.DefenderEnabled, true)}، " +
            $"والحماية الفورية " +
            $"{EnabledText(
                evidence.RealTimeProtectionEnabled,
                true)}. عمر توقيعات الحماية: " +
            $"{NullableNumber(
                evidence.AntivirusSignatureAgeDays,
                true)} يوم.",

            $"الجدار الناري: {firewallState}.",

            $"العمليات والاتصالات: {evidence.ProcessCount} " +
            $"عملية قيد التشغيل و" +
            $"{evidence.ActiveTcpConnections} اتصال TCP نشط. " +
            "هذه الأعداد للمراقبة ولا تعني وحدها أن الجهاز مخترق."
        };

        for (var index = 0;
             index < evidence.Findings.Count;
             index++)
        {
            var finding = evidence.Findings[index];
            var evidenceText = BuildFindingEvidence(
                finding,
                true);

            observations.Add(
                $"المشكلة {index + 1} — النوع: " +
                $"{LocalizeCategory(finding.Category, true)}، " +
                $"الخطورة: " +
                $"{LocalizeSeverity(finding.Severity, true)}. " +
                $"{finding.Title}. {evidenceText}");
        }

        var actions = BuildControlActions(evidence, true);

        for (var index = 0;
             index < evidence.Findings.Count;
             index++)
        {
            actions.Add(
                $"حل المشكلة {index + 1}: " +
                BuildFindingSolution(
                    evidence.Findings[index],
                    true));
        }

        if (evidence.HighOrCriticalEvents > 0)
        {
            actions.Add(
                "راجع صفحة Activity وابدأ بالأحداث العالية " +
                "والحرجة، وتأكد أن مصدرها إجراء معروف. " +
                "إذا كان الحدث غير متوقع افصل الجهاز عن الشبكة " +
                "وافحص العملية والحساب المرتبطين به.");
        }

        if (evidence.FailedSignIns >= 5)
        {
            actions.Add(
                "توجد محاولات دخول فاشلة متعددة: راجع الحساب " +
                "المستهدف، غيّر كلمة مروره، فعّل MFA إن أمكن، " +
                "وراجع مصدر المحاولات في صفحة Activity.");
        }

        if (actions.Count == 0)
        {
            actions.Add(
                "لا توجد مشكلة نشطة تحتاج علاجًا الآن. أبقِ " +
                "Defender والجدار الناري مفعّلين، وحدّث النظام، " +
                "وشغّل Quick Scan دوريًا.");
        }

        return new GroundedAnalysis(
            riskCode,
            headline,
            summary,
            observations,
            actions);
    }

    private static GroundedAnalysis BuildEnglishAnalysis(
        EvidenceSnapshot evidence,
        string riskLabel,
        int controlIssueCount)
    {
        var alertCount = evidence.Findings.Count;
        var firewallState = BuildFirewallState(
            evidence,
            false);

        var headline = evidence.RiskScore == 0 &&
                       alertCount == 0 &&
                       controlIssueCount == 0
            ? "The endpoint is currently in good security condition"
            : $"{alertCount + controlIssueCount} issue(s) " +
              "require review";

        var summary =
            $"Current risk is {evidence.RiskScore}/100 " +
            $"({riskLabel}). There are {alertCount} active " +
            $"security alerts and {controlIssueCount} protection " +
            $"configuration issues. The endpoint has " +
            $"{evidence.ProcessCount} running processes and " +
            $"{evidence.ActiveTcpConnections} active TCP " +
            $"connections. Firewall state: {firewallState}.";

        var observations = new List<string>
        {
            $"Overall risk: {evidence.RiskScore}/100 — " +
            $"{riskLabel}.",
            $"Alerts: {alertCount} active. Windows security " +
            $"events in 24 hours: {evidence.EventsLast24Hours}; " +
            $"high or critical: " +
            $"{evidence.HighOrCriticalEvents}; failed sign-ins: " +
            $"{evidence.FailedSignIns}.",
            $"Protection: Defender is " +
            $"{EnabledText(evidence.DefenderEnabled, false)}; " +
            $"real-time protection is " +
            $"{EnabledText(
                evidence.RealTimeProtectionEnabled,
                false)}.",
            $"Firewall: {firewallState}.",
            $"Runtime: {evidence.ProcessCount} processes and " +
            $"{evidence.ActiveTcpConnections} active TCP " +
            $"connections."
        };

        for (var index = 0;
             index < evidence.Findings.Count;
             index++)
        {
            var finding = evidence.Findings[index];

            observations.Add(
                $"Issue {index + 1} — type: " +
                $"{finding.Category}; severity: " +
                $"{finding.Severity}. {finding.Title}. " +
                BuildFindingEvidence(finding, false));
        }

        var actions = BuildControlActions(evidence, false);

        for (var index = 0;
             index < evidence.Findings.Count;
             index++)
        {
            actions.Add(
                $"Solution for issue {index + 1}: " +
                BuildFindingSolution(
                    evidence.Findings[index],
                    false));
        }

        if (evidence.HighOrCriticalEvents > 0)
        {
            actions.Add(
                "Review high and critical events in Activity. " +
                "If an event is unexpected, isolate the endpoint " +
                "and investigate its process and account.");
        }

        if (actions.Count == 0)
        {
            actions.Add(
                "No active issue currently requires remediation. " +
                "Keep Defender and firewall enabled, install " +
                "updates, and run periodic quick scans.");
        }

        return new GroundedAnalysis(
            riskLabel,
            headline,
            summary,
            observations,
            actions);
    }

    private static List<string> BuildControlActions(
        EvidenceSnapshot evidence,
        bool arabic)
    {
        var actions = new List<string>();

        if (evidence.DefenderEnabled == false)
        {
            actions.Add(arabic
                ? "حل مشكلة Defender: افتح Windows Security ثم " +
                  "Virus & threat protection وفعّل Microsoft " +
                  "Defender، وبعدها حدّث التوقيعات وشغّل فحصًا."
                : "Enable Microsoft Defender in Windows Security, " +
                  "update signatures, and run a scan.");
        }

        if (evidence.RealTimeProtectionEnabled == false)
        {
            actions.Add(arabic
                ? "حل مشكلة الحماية الفورية: من Windows Security " +
                  "افتح Manage settings وفعّل Real-time " +
                  "protection."
                : "Enable Real-time protection under Windows " +
                  "Security > Manage settings.");
        }

        AddFirewallAction(
            actions,
            evidence.FirewallDomainEnabled,
            "Domain",
            arabic);

        AddFirewallAction(
            actions,
            evidence.FirewallPrivateEnabled,
            "Private",
            arabic);

        AddFirewallAction(
            actions,
            evidence.FirewallPublicEnabled,
            "Public",
            arabic);

        if (evidence.RebootRequired == true)
        {
            actions.Add(arabic
                ? "يوجد إعادة تشغيل أمنية معلّقة: احفظ عملك ثم " +
                  "أعد تشغيل الجهاز لإكمال التحديثات."
                : "Save your work and restart the endpoint to " +
                  "complete pending security updates.");
        }

        if (evidence.AntivirusSignatureAgeDays is > 3)
        {
            actions.Add(arabic
                ? "توقيعات Defender قديمة: افتح صفحة Remediation " +
                  "واضغط Update Now ثم أعد الفحص."
                : "Defender signatures are stale. Use " +
                  "Remediation > Update Now, then scan again.");
        }

        return actions;
    }

    private static void AddFirewallAction(
        ICollection<string> actions,
        bool? enabled,
        string profile,
        bool arabic)
    {
        if (enabled != false)
            return;

        actions.Add(arabic
            ? $"حل مشكلة جدار {profile}: افتح Windows Security " +
              $"ثم Firewall & network protection وفعّل ملف " +
              $"{profile}. لا تسمح بتطبيق غير موثوق عبر الجدار."
            : $"Enable the {profile} firewall profile in Windows " +
              "Security > Firewall & network protection.");
    }

    private static string BuildFindingSolution(
        FindingInfo finding,
        bool arabic)
    {
        var searchable = string.Join(
            " ",
            finding.Title,
            finding.Description,
            finding.Category,
            finding.FilePath)
            .ToLowerInvariant();

        if (searchable.Contains("malware") ||
            searchable.Contains("virus") ||
            searchable.Contains("trojan"))
        {
            return arabic
                ? "افصل الجهاز عن الشبكة إذا كان التهديد نشطًا، " +
                  "ثم من Windows Security اعزل أو أزل التهديد، " +
                  "حدّث التوقيعات، وشغّل Full Scan وتأكد أن " +
                  "التنبيه اختفى قبل إعادة الاتصال."
                : "Isolate the endpoint if the threat is active, " +
                  "quarantine or remove it in Windows Security, " +
                  "update signatures, and run a full scan.";
        }

        if (searchable.Contains("risky location") ||
            searchable.Contains("\\temp\\") ||
            searchable.Contains("\\downloads\\"))
        {
            var fileName = string.IsNullOrWhiteSpace(
                finding.FilePath)
                ? finding.ProcessName ?? "الملف"
                : Path.GetFileName(finding.FilePath);

            return arabic
                ? $"تحقق من {fileName}: إذا لم تكن أنت من شغّله " +
                  "أوقف العملية فورًا وافحص الملف بـDefender. " +
                  "إذا كان ملف تثبيت معروفًا، افتح Properties ثم " +
                  "Digital Signatures وتأكد من الناشر، وبعد انتهاء " +
                  "التثبيت احذف الملف المؤقت. صنّفه False Positive " +
                  "فقط بعد التأكد من التوقيع والمصدر."
                : $"Verify {fileName}. If you did not start it, " +
                  "stop the process and scan the file. For a known " +
                  "installer, verify its publisher and digital " +
                  "signature, then remove the temporary file.";
        }

        if (searchable.Contains("powershell") ||
            searchable.Contains("command") ||
            searchable.Contains("encoded"))
        {
            return arabic
                ? "راجع سطر الأوامر والعملية الأب. إذا لم يكن " +
                  "الأمر متوقعًا، أوقف العملية وافصل الشبكة، ثم " +
                  "افحص الملف والحساب الذي شغّله وراجع أحداث " +
                  "Windows في صفحة Activity."
                : "Review the command line and parent process. If " +
                  "unexpected, stop it, isolate the endpoint, and " +
                  "investigate the file and account.";
        }

        if (searchable.Contains("unsigned") ||
            searchable.Contains("signature"))
        {
            return arabic
                ? "تحقق من التوقيع الرقمي والناشر وHash الملف. " +
                  "إذا كان غير موقّع أو مصدره غير معروف، لا تشغّله " +
                  "وافحصه ثم احذفه أو اعزله."
                : "Verify the digital signature, publisher, and " +
                  "file hash. Do not run an unknown unsigned file; " +
                  "scan and quarantine or remove it.";
        }

        return arabic
            ? "راجع اسم العملية ومسار الملف وسطر الأوامر، وتأكد " +
              "أنها مرتبطة ببرنامج تعرفه. إن لم تكن متوقعة، أوقف " +
              "العملية وافحص الملف واعزله قبل اعتباره آمنًا."
            : "Review the process, file path, and command line. If " +
              "unexpected, stop it, scan the file, and quarantine " +
              "it until verified.";
    }

    private static string BuildFindingEvidence(
        FindingInfo finding,
        bool arabic)
    {
        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(finding.Description))
        {
            parts.Add(arabic
                ? $"التفاصيل: {Limit(finding.Description, 220)}"
                : $"Details: {Limit(finding.Description, 220)}");
        }

        if (!string.IsNullOrWhiteSpace(finding.ProcessName))
        {
            parts.Add(arabic
                ? $"العملية: {finding.ProcessName}"
                : $"Process: {finding.ProcessName}");
        }

        if (finding.ProcessId is not null)
        {
            parts.Add(arabic
                ? $"المعرّف: {finding.ProcessId}"
                : $"PID: {finding.ProcessId}");
        }

        if (!string.IsNullOrWhiteSpace(finding.FilePath))
        {
            parts.Add(arabic
                ? $"المسار: {Limit(finding.FilePath, 180)}"
                : $"Path: {Limit(finding.FilePath, 180)}");
        }

        if (parts.Count == 0)
        {
            return arabic
                ? "لا يتوفر مسار ملف إضافي لهذا التنبيه."
                : "No additional file evidence is available.";
        }

        return string.Join("، ", parts) + ".";
    }

    private static string BuildFirewallState(
        EvidenceSnapshot evidence,
        bool arabic)
    {
        if (arabic)
        {
            return
                $"Domain {EnabledText(
                    evidence.FirewallDomainEnabled,
                    true)}، " +
                $"Private {EnabledText(
                    evidence.FirewallPrivateEnabled,
                    true)}، " +
                $"Public {EnabledText(
                    evidence.FirewallPublicEnabled,
                    true)}";
        }

        return
            $"Domain {EnabledText(
                evidence.FirewallDomainEnabled,
                false)}, " +
            $"Private {EnabledText(
                evidence.FirewallPrivateEnabled,
                false)}, " +
            $"Public {EnabledText(
                evidence.FirewallPublicEnabled,
                false)}";
    }

    private static string BuildCompactPrompt(
        EvidenceSnapshot evidence,
        string? question,
        bool arabic)
    {
        var languageInstruction = arabic
            ? "Write both values in clear Arabic only."
            : "Write both values in clear English only.";

        var findingSummary = evidence.Findings.Count == 0
            ? "none"
            : string.Join(
                "; ",
                evidence.Findings.Take(3).Select(x =>
                    $"{x.Severity}/{x.Category}: {x.Title}"));

        return
            "You are a local endpoint security analyst. " +
            "The application has already produced a verified, " +
            "complete analysis. Add only one useful observation " +
            "and one safe action based strictly on these facts. " +
            "Do not invent threats. " + languageInstruction + " " +
            "Return JSON only: " +
            "{\"extraObservation\":\"...\"," +
            "\"extraAction\":\"...\"}. " +
            $"Question: {Limit(question, 180) ?? "general status"}. " +
            $"Risk={evidence.RiskScore}/100; " +
            $"alerts={evidence.Findings.Count}; " +
            $"processes={evidence.ProcessCount}; " +
            $"tcp={evidence.ActiveTcpConnections}; " +
            $"events24h={evidence.EventsLast24Hours}; " +
            $"highCritical={evidence.HighOrCriticalEvents}; " +
            $"failedSignIns={evidence.FailedSignIns}; " +
            $"firewall={BuildFirewallState(evidence, false)}; " +
            $"findings={findingSummary}.";
    }

    private static int CountControlIssues(
        EvidenceSnapshot evidence)
    {
        var count = 0;

        if (evidence.DefenderEnabled == false)
            count++;

        if (evidence.RealTimeProtectionEnabled == false)
            count++;

        if (evidence.FirewallDomainEnabled == false)
            count++;

        if (evidence.FirewallPrivateEnabled == false)
            count++;

        if (evidence.FirewallPublicEnabled == false)
            count++;

        if (evidence.RebootRequired == true)
            count++;

        if (evidence.AntivirusSignatureAgeDays is > 3)
            count++;

        return count;
    }

    private static void AddUnique(
        ICollection<string> target,
        string? value,
        bool arabic)
    {
        value = ValidateAiText(value, arabic);

        if (value is null)
            return;

        if (target.Any(x => string.Equals(
                x,
                value,
                StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        target.Add(value);
    }

    private static string? ValidateAiText(
        string? value,
        bool arabic)
    {
        value = Limit(value, 360);

        if (string.IsNullOrWhiteSpace(value))
            return null;

        if (value.Contains('{') || value.Contains('['))
            return null;

        if (arabic && !ContainsArabic(value))
            return null;

        if (!arabic && ContainsArabic(value))
            return null;

        return value;
    }

    private static bool IsArabicRequest(
        string? language,
        string? question)
    {
        return language?.Contains(
                   "arab",
                   StringComparison.OrdinalIgnoreCase) == true ||
               ContainsArabic(question);
    }

    private static bool ContainsArabic(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        return value.Any(character =>
            character is >= '\u0600' and <= '\u06FF' or
            >= '\u0750' and <= '\u077F' or
            >= '\u08A0' and <= '\u08FF');
    }

    private static string GetRiskLabel(
        int score,
        bool arabic)
    {
        if (arabic)
        {
            return score switch
            {
                0 => "آمن",
                < 30 => "منخفض",
                < 60 => "متوسط",
                < 80 => "مرتفع",
                _ => "حرج"
            };
        }

        return score switch
        {
            0 => "Secure",
            < 30 => "Low",
            < 60 => "Medium",
            < 80 => "High",
            _ => "Critical"
        };
    }

    private static string EnabledText(
        bool? value,
        bool arabic)
    {
        if (arabic)
        {
            return value switch
            {
                true => "مفعّل",
                false => "متوقف",
                null => "غير متوفر"
            };
        }

        return value switch
        {
            true => "enabled",
            false => "disabled",
            null => "unavailable"
        };
    }

    private static string NullableNumber(
        int? value,
        bool arabic)
    {
        return value?.ToString() ??
               (arabic ? "غير معروف" : "unknown");
    }

    private static string LocalizeSeverity(
        string severity,
        bool arabic)
    {
        if (!arabic)
            return severity;

        return severity.ToLowerInvariant() switch
        {
            "critical" => "حرجة",
            "high" => "عالية",
            "medium" => "متوسطة",
            "low" => "منخفضة",
            _ => severity
        };
    }

    private static string LocalizeCategory(
        string category,
        bool arabic)
    {
        if (!arabic)
            return category;

        var normalized = category.ToLowerInvariant();

        if (normalized.Contains("malware"))
            return "برمجية خبيثة";

        if (normalized.Contains("process") ||
            normalized.Contains("behavior"))
            return "سلوك عملية مشبوه";

        if (normalized.Contains("network"))
            return "نشاط شبكة";

        if (normalized.Contains("file"))
            return "ملف مشبوه";

        if (normalized.Contains("configuration"))
            return "إعداد أمني";

        return category;
    }

    private static string? Limit(
        string? value,
        int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        value = value.Trim();

        return value.Length <= maxLength
            ? value
            : value[..maxLength] + "…";
    }

    private static bool TryGetProperty(
        JsonElement element,
        string name,
        out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(
                        property.Name,
                        name,
                        StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private static JsonElement GetChild(
        JsonElement element,
        string name)
    {
        return TryGetProperty(element, name, out var value)
            ? value
            : default;
    }

    private static string? ReadString(
        JsonElement element,
        params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetProperty(element, name, out var value))
                continue;

            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number => value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            };
        }

        return null;
    }

    private static int? ReadInt(
        JsonElement element,
        params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetProperty(element, name, out var value))
                continue;

            var result = ConvertToInt(value);

            if (result is not null)
                return result;
        }

        return null;
    }

    private static int? ReadIntDeep(
        JsonElement element,
        params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryFindFirst(element, name, out var value))
                continue;

            var result = ConvertToInt(value);

            if (result is not null)
                return result;
        }

        return null;
    }

    private static int? ConvertToInt(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Number)
        {
            if (value.TryGetInt32(out var integer))
                return integer;

            if (value.TryGetDouble(out var number))
                return Convert.ToInt32(number);
        }

        if (value.ValueKind == JsonValueKind.String &&
            int.TryParse(value.GetString(), out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static bool? ReadBool(
        JsonElement element,
        params string[] names)
    {
        foreach (var name in names)
        {
            if (!TryGetProperty(element, name, out var value))
                continue;

            if (value.ValueKind == JsonValueKind.True)
                return true;

            if (value.ValueKind == JsonValueKind.False)
                return false;

            if (value.ValueKind == JsonValueKind.Number &&
                value.TryGetInt32(out var number))
            {
                return number != 0;
            }

            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();

                if (bool.TryParse(text, out var parsed))
                    return parsed;

                if (string.Equals(
                        text,
                        "enabled",
                        StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(
                        text,
                        "on",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (string.Equals(
                        text,
                        "disabled",
                        StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(
                        text,
                        "off",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }
        }

        return null;
    }

    private static bool TryFindFirst(
        JsonElement element,
        string name,
        out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (TryGetProperty(element, name, out value))
                return true;

            foreach (var property in element.EnumerateObject())
            {
                if (TryFindFirst(
                        property.Value,
                        name,
                        out value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (TryFindFirst(item, name, out value))
                    return true;
            }
        }

        value = default;
        return false;
    }

    private static List<FindingInfo> ReadFindings(
        JsonElement context)
    {
        var items = new List<JsonElement>();
        CollectArraysByName(context, "findings", items);

        return items
            .Where(x => x.ValueKind == JsonValueKind.Object)
            .Select(x => new FindingInfo(
                NormalizeCategory(
                    ReadString(x, "category") ?? "Behavior"),
                NormalizeSeverity(
                    ReadString(x, "severity") ?? "Low"),
                ReadString(x, "title") ??
                    "Security finding requires review",
                ReadString(x, "description") ?? string.Empty,
                ReadString(x, "processName"),
                ReadInt(x, "processId"),
                ReadString(x, "filePath", "path"),
                ReadString(x, "commandLine")))
            .GroupBy(
                x => string.Join(
                    "|",
                    x.Title,
                    x.ProcessName,
                    x.FilePath),
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .Take(20)
            .ToList();
    }

    private static void CollectArraysByName(
        JsonElement element,
        string name,
        ICollection<JsonElement> result)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(
                        property.Name,
                        name,
                        StringComparison.OrdinalIgnoreCase) &&
                    property.Value.ValueKind ==
                    JsonValueKind.Array)
                {
                    foreach (var item in
                             property.Value.EnumerateArray())
                    {
                        result.Add(item);
                    }

                    continue;
                }

                CollectArraysByName(
                    property.Value,
                    name,
                    result);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                CollectArraysByName(item, name, result);
            }
        }
    }

    private static string NormalizeSeverity(string value)
    {
        return value.Trim().ToLowerInvariant() switch
        {
            "4" or "critical" => "Critical",
            "3" or "high" => "High",
            "2" or "medium" or "moderate" => "Medium",
            "1" or "low" => "Low",
            _ => value.Trim()
        };
    }

    private static string NormalizeCategory(string value)
    {
        return value.Trim().ToLowerInvariant() switch
        {
            "0" => "Malware",
            "1" => "SuspiciousProcess",
            "2" => "SuspiciousCommand",
            "3" => "RiskyFileLocation",
            "4" => "Network",
            _ => value.Trim()
        };
    }

    public sealed record AnalyzeSecurityRequest(
        string? Language,
        string? Question,
        JsonElement Context);

    private sealed record AiEnrichment(
        string? ExtraObservation,
        string? ExtraAction);

    private sealed record AiCacheEntry(
        AiEnrichment Value,
        DateTime CreatedAtUtc);

    private sealed record GroundedAnalysis(
        string OverallRisk,
        string Headline,
        string Summary,
        IReadOnlyList<string> Observations,
        IReadOnlyList<string> PriorityActions);

    private sealed record FindingInfo(
        string Category,
        string Severity,
        string Title,
        string Description,
        string? ProcessName,
        int? ProcessId,
        string? FilePath,
        string? CommandLine);

    private sealed record EvidenceSnapshot(
        int RiskScore,
        int ProcessCount,
        int ActiveTcpConnections,
        int EventsLast24Hours,
        int HighOrCriticalEvents,
        int FailedSignIns,
        bool? DefenderEnabled,
        bool? RealTimeProtectionEnabled,
        bool? FirewallDomainEnabled,
        bool? FirewallPrivateEnabled,
        bool? FirewallPublicEnabled,
        bool? RebootRequired,
        int? AntivirusSignatureAgeDays,
        IReadOnlyList<FindingInfo> Findings)
    {
        public static EvidenceSnapshot Read(
            JsonElement context)
        {
            var posture = GetChild(context, "posture");
            var telemetry = GetChild(context, "telemetry");
            var eventSummary = GetChild(
                context,
                "securityEventSummary");

            if (eventSummary.ValueKind is
                JsonValueKind.Undefined or
                JsonValueKind.Null)
            {
                eventSummary = GetChild(
                    context,
                    "eventSummary");
            }

            var findings = ReadFindings(context);

            var riskValues = new List<int>();
            CollectIntegersByName(
                context,
                "riskScore",
                riskValues);

            var reportedRisk = riskValues.Count == 0
                ? 0
                : riskValues.Max();

            var calculatedRisk = CalculateMinimumRisk(
                findings,
                ReadBool(posture, "defenderEnabled"),
                ReadBool(
                    posture,
                    "realTimeProtectionEnabled"),
                ReadBool(
                    posture,
                    "firewallDomainEnabled"),
                ReadBool(
                    posture,
                    "firewallPrivateEnabled"),
                ReadBool(
                    posture,
                    "firewallPublicEnabled"));

            var eventsLast24Hours = ReadIntDeep(
                    eventSummary,
                    "eventsLast24Hours",
                    "eventsIn24Hours",
                    "eventsInLast24Hours",
                    "totalLast24Hours",
                    "totalEventsLast24Hours",
                    "eventCount",
                    "totalEvents",
                    "totalCount",
                    "total") ?? 0;

            var highOrCriticalCombined = ReadIntDeep(
                    eventSummary,
                    "highOrCriticalCount",
                    "highCriticalCount",
                    "highOrCriticalLast24Hours",
                    "highCriticalEvents");

            var highOrCritical = highOrCriticalCombined ??
                ((ReadIntDeep(
                      eventSummary,
                      "highCount",
                      "highEvents") ?? 0) +
                 (ReadIntDeep(
                      eventSummary,
                      "criticalCount",
                      "criticalEvents") ?? 0));

            var failedSignIns = ReadIntDeep(
                    eventSummary,
                    "failedSignInCount",
                    "failedSignIns",
                    "failedSignInsLast24Hours",
                    "failedAuthenticationCount") ?? 0;

            return new EvidenceSnapshot(
                Math.Clamp(
                    Math.Max(reportedRisk, calculatedRisk),
                    0,
                    100),
                ReadInt(telemetry, "processCount") ?? 0,
                ReadInt(
                    telemetry,
                    "activeTcpConnectionCount") ?? 0,
                eventsLast24Hours,
                highOrCritical,
                failedSignIns,
                ReadBool(posture, "defenderEnabled"),
                ReadBool(
                    posture,
                    "realTimeProtectionEnabled"),
                ReadBool(
                    posture,
                    "firewallDomainEnabled"),
                ReadBool(
                    posture,
                    "firewallPrivateEnabled"),
                ReadBool(
                    posture,
                    "firewallPublicEnabled"),
                ReadBool(posture, "rebootRequired"),
                ReadInt(
                    posture,
                    "antivirusSignatureAgeDays"),
                findings);
        }

        private static int CalculateMinimumRisk(
            IReadOnlyList<FindingInfo> findings,
            bool? defender,
            bool? realTime,
            bool? domainFirewall,
            bool? privateFirewall,
            bool? publicFirewall)
        {
            var score = findings.Sum(finding =>
                finding.Severity.ToLowerInvariant() switch
                {
                    "critical" => 50,
                    "high" => 30,
                    "medium" => 15,
                    _ => 5
                });

            if (defender == false)
                score += 30;

            if (realTime == false)
                score += 25;

            if (domainFirewall == false)
                score += 10;

            if (privateFirewall == false)
                score += 10;

            if (publicFirewall == false)
                score += 15;

            return Math.Clamp(score, 0, 100);
        }

        private static void CollectIntegersByName(
            JsonElement element,
            string name,
            ICollection<int> result)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in
                         element.EnumerateObject())
                {
                    if (string.Equals(
                            property.Name,
                            name,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        var value = ConvertToInt(property.Value);

                        if (value is not null)
                            result.Add(value.Value);
                    }

                    CollectIntegersByName(
                        property.Value,
                        name,
                        result);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    CollectIntegersByName(
                        item,
                        name,
                        result);
                }
            }
        }
    }
}

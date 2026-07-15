import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Cpu,
  Download,
  FileText,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  XCircle
} from 'lucide-react'
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type CSSProperties
} from 'react'
import './security-report.css'

type ReportDevice = {
  id: string
  hostName: string
  operatingSystem: string
  operatingSystemVersion: string
  architecture: string
  agentVersion: string
  status: string
  lastSeenUtc: string
}

type ReportCounts = {
  openFindings: number
  reviewedFindings: number
  totalFindings: number
  processes: number
  tcpConnections: number
  securityEvents: number
  highCriticalEvents: number
  failedLogons: number
  defenderEvents: number
  scans: number
  remediationActions: number
  failedActions: number
}

type ReportProtection = {
  defenderEnabled: boolean | null
  realTimeProtectionEnabled: boolean | null
  antivirusSignatureAgeDays: number | null
  firewallDomainEnabled: boolean | null
  firewallPrivateEnabled: boolean | null
  firewallPublicEnabled: boolean | null
  rebootRequired: boolean | null
  collectedAtUtc: string | null
}

type ReportIssue = {
  severity: string
  type: string
  title: string
  evidence: string
  status: string
  recommendedAction: string
}

type ReportPreview = {
  generatedAtUtc: string
  windowHours: number
  overallRisk: number
  riskLevel: string
  assessmentStatus: string
  executiveSummary: string
  device: ReportDevice
  counts: ReportCounts
  protection: ReportProtection
  issues: ReportIssue[]
  recommendations: string[]
  dataFreshness: {
    telemetryAtUtc: string | null
    postureAtUtc: string | null
    latestEventAtUtc: string | null
  }
}

type Props = {
  deviceId?: string
  online: boolean
}

function parseApiDate(value: string): Date {
  const includesTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  return new Date(
    includesTimeZone ? value : `${value}Z`
  )
}

function formatDate(value?: string | null): string {
  if (!value) {
    return 'Not available'
  }

  const date = parseApiDate(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date)
}

function protectionState(
  value: boolean | null
): {
  label: string
  className: string
} {
  if (value === true) {
    return {
      label: 'Enabled',
      className: 'healthy'
    }
  }

  if (value === false) {
    return {
      label: 'Disabled',
      className: 'danger'
    }
  }

  return {
    label: 'Unavailable',
    className: 'unknown'
  }
}

function safeFileName(value: string): string {
  return value.replace(/[^a-z0-9_.-]+/gi, '-')
}

export function SecurityReport({
  deviceId,
  online
}: Props) {
  const [hours, setHours] = useState(24)
  const [report, setReport] =
    useState<ReportPreview | null>(null)
  const [loading, setLoading] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState('')

  const loadReport = useCallback(async () => {
    if (!deviceId) {
      setReport(null)
      setError('No registered endpoint is available for reporting.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await fetch(
        `/api/security-reports/devices/${deviceId}?hours=${hours}`,
        {
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        const message = await response.text()
        throw new Error(
          message ||
          `Report preview failed with HTTP ${response.status}.`
        )
      }

      const payload =
        await response.json() as ReportPreview

      setReport(payload)
    } catch (requestError) {
      setReport(null)
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'The report preview could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId, hours])

  useEffect(() => {
    void loadReport()
  }, [loadReport])

  const downloadReport = useCallback(async () => {
    if (!deviceId || !report) {
      return
    }

    setDownloading(true)
    setError('')

    try {
      const response = await fetch(
        `/api/security-reports/devices/${deviceId}/pdf?hours=${hours}`,
        {
          headers: {
            Accept: 'application/pdf'
          }
        }
      )

      if (!response.ok) {
        const message = await response.text()
        throw new Error(
          message ||
          `PDF generation failed with HTTP ${response.status}.`
        )
      }

      const contentType =
        response.headers.get('content-type') ?? ''

      if (!contentType.toLowerCase().includes('application/pdf')) {
        throw new Error('The API did not return a PDF document.')
      }

      const blob = await response.blob()

      if (blob.size < 1000) {
        throw new Error('The generated PDF document is incomplete.')
      }

      const objectUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      const date = new Date().toISOString().slice(0, 10)

      link.href = objectUrl
      link.download =
        `Endpoint-Security-Report-${safeFileName(report.device.hostName)}-${date}.pdf`
      document.body.appendChild(link)
      link.click()
      link.remove()

      window.setTimeout(() => {
        URL.revokeObjectURL(objectUrl)
      }, 1000)
    } catch (downloadError) {
      setError(
        downloadError instanceof Error
          ? downloadError.message
          : 'The PDF document could not be downloaded.'
      )
    } finally {
      setDownloading(false)
    }
  }, [deviceId, hours, report])

  const protectionChecks = useMemo(() => {
    if (!report) {
      return []
    }

    return [
      {
        name: 'Microsoft Defender',
        value: report.protection.defenderEnabled
      },
      {
        name: 'Real-time Protection',
        value: report.protection.realTimeProtectionEnabled
      },
      {
        name: 'Domain Firewall',
        value: report.protection.firewallDomainEnabled
      },
      {
        name: 'Private Firewall',
        value: report.protection.firewallPrivateEnabled
      },
      {
        name: 'Public Firewall',
        value: report.protection.firewallPublicEnabled
      }
    ]
  }, [report])

  const riskStyle = {
    '--report-risk-angle':
      `${Math.min(100, Math.max(0, report?.overallRisk ?? 0)) * 3.6}deg`
  } as CSSProperties

  if (!deviceId) {
    return (
      <section className="panel report-empty-state">
        <FileText size={30} />
        <h2>No endpoint available</h2>
        <p>
          Register an endpoint before generating a security report.
        </p>
      </section>
    )
  }

  return (
    <div className="security-report-page">
      <section className="panel report-command-bar">
        <div className="report-command-copy">
          <div className="report-command-icon">
            <FileText size={25} />
          </div>

          <div>
            <span className="section-label">
              PROFESSIONAL SECURITY ASSESSMENT
            </span>
            <h2>Endpoint Security PDF Report</h2>
            <p>
              Generated locally from the latest endpoint, Defender,
              firewall, finding, event, scan, and network data.
            </p>
          </div>
        </div>

        <div className="report-command-actions">
          <label>
            REPORT WINDOW
            <select
              value={hours}
              onChange={(event) =>
                setHours(Number(event.target.value))
              }
              disabled={loading || downloading}
            >
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 3 days</option>
              <option value={168}>Last 7 days</option>
            </select>
          </label>

          <button
            className="report-refresh-button"
            onClick={() => void loadReport()}
            disabled={loading || downloading}
          >
            <RefreshCw
              size={17}
              className={loading ? 'spinning' : ''}
            />
            Refresh
          </button>

          <button
            className="report-download-button"
            onClick={() => void downloadReport()}
            disabled={!report || loading || downloading}
          >
            {downloading ? (
              <RefreshCw size={18} className="spinning" />
            ) : (
              <Download size={18} />
            )}
            {downloading ? 'Generating PDF...' : 'Download PDF'}
          </button>
        </div>
      </section>

      {error && (
        <div className="report-error-banner">
          <XCircle size={19} />
          <span>{error}</span>
        </div>
      )}

      {loading && !report ? (
        <section className="panel report-loading-state">
          <RefreshCw size={28} className="spinning" />
          <strong>Building report preview...</strong>
          <span>Loading current security data from this endpoint.</span>
        </section>
      ) : report ? (
        <>
          <section className="panel report-overview-card">
            <div className="report-overview-main">
              <div
                className={`report-risk-ring risk-${report.riskLevel.toLowerCase()}`}
                style={riskStyle}
              >
                <div>
                  <strong>{report.overallRisk}</strong>
                  <span>/100</span>
                </div>
              </div>

              <div className="report-overview-copy">
                <div className="report-status-row">
                  <span className="report-risk-level">
                    {report.riskLevel} risk
                  </span>
                  <span className={`report-online-state ${online ? 'online' : 'offline'}`}>
                    <span />
                    {online ? 'Endpoint online' : 'Endpoint offline'}
                  </span>
                </div>

                <h2>{report.assessmentStatus}</h2>
                <p>{report.executiveSummary}</p>

                <div className="report-device-line">
                  <Server size={17} />
                  <strong>{report.device.hostName}</strong>
                  <span>{report.device.operatingSystem}</span>
                  <span>Agent {report.device.agentVersion}</span>
                </div>
              </div>
            </div>

            <div className="report-generated-at">
              <Clock3 size={16} />
              Generated {formatDate(report.generatedAtUtc)}
            </div>
          </section>

          <section className="report-metric-grid">
            <article className="panel report-metric">
              <AlertTriangle size={21} />
              <span>Open findings</span>
              <strong>{report.counts.openFindings}</strong>
              <small>
                {report.counts.reviewedFindings} reviewed in latest snapshot
              </small>
            </article>

            <article className="panel report-metric">
              <Shield size={21} />
              <span>Windows events</span>
              <strong>{report.counts.securityEvents}</strong>
              <small>
                {report.counts.highCriticalEvents} high or critical
              </small>
            </article>

            <article className="panel report-metric">
              <Cpu size={21} />
              <span>Processes</span>
              <strong>{report.counts.processes}</strong>
              <small>Latest telemetry snapshot</small>
            </article>

            <article className="panel report-metric">
              <Network size={21} />
              <span>TCP connections</span>
              <strong>{report.counts.tcpConnections}</strong>
              <small>Current active sessions</small>
            </article>

            <article className="panel report-metric">
              <Activity size={21} />
              <span>Failed logons</span>
              <strong>{report.counts.failedLogons}</strong>
              <small>Inside the selected window</small>
            </article>

            <article className="panel report-metric">
              <CheckCircle2 size={21} />
              <span>Security actions</span>
              <strong>
                {report.counts.scans + report.counts.remediationActions}
              </strong>
              <small>
                {report.counts.failedActions} failed actions
              </small>
            </article>
          </section>

          <section className="report-content-grid">
            <article className="panel report-protection-panel">
              <div className="report-section-heading">
                <div>
                  <span className="section-label">PROTECTION CONTROLS</span>
                  <h2>Defender and Firewall</h2>
                </div>
                <ShieldCheck size={22} />
              </div>

              <div className="report-protection-list">
                {protectionChecks.map((check) => {
                  const state = protectionState(check.value)

                  return (
                    <div className="report-protection-row" key={check.name}>
                      <div className={`report-control-icon ${state.className}`}>
                        {check.value === true ? (
                          <CheckCircle2 size={18} />
                        ) : (
                          <AlertTriangle size={18} />
                        )}
                      </div>
                      <strong>{check.name}</strong>
                      <span className={`report-control-state ${state.className}`}>
                        {state.label}
                      </span>
                    </div>
                  )
                })}

                <div className="report-protection-row">
                  <div className="report-control-icon healthy">
                    <Clock3 size={18} />
                  </div>
                  <strong>Defender signature age</strong>
                  <span className="report-control-value">
                    {report.protection.antivirusSignatureAgeDays == null
                      ? 'Unavailable'
                      : `${report.protection.antivirusSignatureAgeDays} day(s)`}
                  </span>
                </div>
              </div>
            </article>

            <article className="panel report-contents-panel">
              <div className="report-section-heading">
                <div>
                  <span className="section-label">PDF CONTENTS</span>
                  <h2>Evidence included</h2>
                </div>
                <FileText size={22} />
              </div>

              <ul className="report-contents-list">
                <li>Executive risk summary and endpoint identity</li>
                <li>Microsoft Defender and each firewall profile</li>
                <li>Current findings with severity, evidence, and status</li>
                <li>Windows events, failed logons, and Defender activity</li>
                <li>Process, TCP, remote endpoint, and secure-port totals</li>
                <li>Scan, remediation, and prioritized action history</li>
              </ul>

              <div className="report-local-note">
                <ShieldCheck size={18} />
                <div>
                  <strong>Generated locally</strong>
                  <span>No report data is sent to a cloud service.</span>
                </div>
              </div>
            </article>
          </section>

          <section className="panel report-issues-panel">
            <div className="report-section-heading">
              <div>
                <span className="section-label">EVIDENCE-BASED ASSESSMENT</span>
                <h2>Issues requiring attention</h2>
              </div>
              <span className="report-count-pill">
                {report.issues.length} item(s)
              </span>
            </div>

            {report.issues.length === 0 ? (
              <div className="report-no-issues">
                <CheckCircle2 size={24} />
                <div>
                  <strong>No current security issue was detected.</strong>
                  <span>
                    The report does not invent risk when device data is healthy.
                  </span>
                </div>
              </div>
            ) : (
              <div className="report-issue-list">
                {report.issues.map((issue, index) => (
                  <article className="report-issue" key={`${issue.type}-${issue.title}-${index}`}>
                    <span className={`report-severity severity-${issue.severity.toLowerCase()}`}>
                      {issue.severity}
                    </span>
                    <div className="report-issue-copy">
                      <div>
                        <span>{issue.type}</span>
                        <strong>{issue.title}</strong>
                      </div>
                      <p>{issue.evidence}</p>
                      <small>
                        <b>Action:</b> {issue.recommendedAction}
                      </small>
                    </div>
                    <span className="report-issue-status">
                      {issue.status}
                    </span>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="panel report-recommendations-panel">
            <div className="report-section-heading">
              <div>
                <span className="section-label">PRIORITY PLAN</span>
                <h2>Recommended actions</h2>
              </div>
              <Activity size={22} />
            </div>

            <ol className="report-recommendation-list">
              {report.recommendations.map((recommendation, index) => (
                <li key={`${recommendation}-${index}`}>
                  <span>{index + 1}</span>
                  <p>{recommendation}</p>
                </li>
              ))}
            </ol>
          </section>

          <footer className="report-data-footer">
            <span>
              Telemetry: {formatDate(report.dataFreshness.telemetryAtUtc)}
            </span>
            <span>
              Posture: {formatDate(report.dataFreshness.postureAtUtc)}
            </span>
            <span>
              Latest event: {formatDate(report.dataFreshness.latestEventAtUtc)}
            </span>
          </footer>
        </>
      ) : null}
    </div>
  )
}

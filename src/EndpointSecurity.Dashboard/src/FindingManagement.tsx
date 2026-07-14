import {
  useCallback,
  useEffect,
  useMemo,
  useState
} from 'react'
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock3,
  EyeOff,
  FileCheck2,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck
} from 'lucide-react'
import './finding-management.css'

type Finding = {
  id: string
  category: string
  severity: string
  title: string
  description: string
  processName?: string | null
  processId?: number | null
  filePath?: string | null
  commandLine?: string | null
  fingerprint: string
  status: string
  analystNote?: string | null
  analystName?: string | null
  reviewedAtUtc?: string | null
  detectedAtUtc: string
}

type Telemetry = {
  deviceId: string
  riskScore: number
  collectedAtUtc: string
  findings: Finding[]
}

type FindingReview = {
  id: string
  findingId: string
  fingerprint: string
  status: string
  analystNote?: string | null
  analystName: string
  reviewedAtUtc: string
}

type Props = {
  deviceId?: string
}

function formatDate(value?: string | null): string {
  if (!value) {
    return '—'
  }

  const includesTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  const date = new Date(
    includesTimeZone ? value : `${value}Z`
  )

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).format(date)
}

function isOpen(status?: string): boolean {
  return !status || status.toLowerCase() === 'open'
}

function statusLabel(status: string): string {
  switch (status.toLowerCase()) {
    case 'falsepositive':
      return 'False Positive'

    case 'resolved':
      return 'Resolved'

    case 'ignored':
      return 'Ignored'

    default:
      return 'Open'
  }
}

export function FindingManagement({
  deviceId
}: Props) {
  const [telemetry, setTelemetry] =
    useState<Telemetry | null>(null)
  const [history, setHistory] =
    useState<FindingReview[]>([])
  const [loading, setLoading] = useState(true)
  const [reviewing, setReviewing] =
    useState<string | null>(null)
  const [error, setError] = useState('')

  const loadData = useCallback(async () => {
    if (!deviceId) {
      setTelemetry(null)
      setHistory([])
      setLoading(false)
      return
    }

    try {
      const [telemetryResponse, historyResponse] =
        await Promise.all([
          fetch(
            `/api/telemetry/${deviceId}/latest`
          ),
          fetch(
            `/api/findings/devices/${deviceId}/reviews`
          )
        ])

      if (!telemetryResponse.ok) {
        throw new Error(
          `Telemetry request failed: ` +
          `${telemetryResponse.status}`
        )
      }

      if (!historyResponse.ok) {
        throw new Error(
          `Review history request failed: ` +
          `${historyResponse.status}`
        )
      }

      setTelemetry(
        (await telemetryResponse.json()) as Telemetry
      )

      setHistory(
        (await historyResponse.json()) as FindingReview[]
      )

      setError('')
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Finding data could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadData()

    const timer = window.setInterval(() => {
      void loadData()
    }, 10_000)

    return () => window.clearInterval(timer)
  }, [loadData])

  const findings = telemetry?.findings ?? []

  const activeFindings = useMemo(
    () =>
      findings.filter((finding) =>
        isOpen(finding.status)
      ),
    [findings]
  )

  const reviewedFindings = useMemo(
    () =>
      findings.filter(
        (finding) => !isOpen(finding.status)
      ),
    [findings]
  )

  const falsePositiveCount = history.filter(
    (review) =>
      review.status.toLowerCase() ===
      'falsepositive'
  ).length

  async function reviewFinding(
    finding: Finding,
    status:
      | 'Open'
      | 'Resolved'
      | 'FalsePositive'
      | 'Ignored'
  ) {
    let defaultNote = ''

    if (status === 'FalsePositive') {
      defaultNote =
        'Verified as expected or trusted software.'
    } else if (status === 'Resolved') {
      defaultNote =
        'Finding investigated and resolved.'
    } else if (status === 'Ignored') {
      defaultNote =
        'Accepted risk or temporarily ignored.'
    } else {
      defaultNote =
        'Finding reopened for further investigation.'
    }

    const note = window.prompt(
      `Analyst note for ${statusLabel(status)}:`,
      defaultNote
    )

    if (note === null) {
      return
    }

    setReviewing(finding.id)
    setError('')

    try {
      const response = await fetch(
        `/api/findings/${finding.id}/review`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            status,
            analystNote: note,
            analystName: 'Osama Alsmadi'
          })
        }
      )

      if (!response.ok) {
        const body = await response.text()

        throw new Error(
          body ||
            `Review request failed: ` +
            `${response.status}`
        )
      }

      await loadData()
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Finding review failed.'
      )
    } finally {
      setReviewing(null)
    }
  }

  return (
    <div className="finding-management">
      {error && (
        <div className="finding-management-error">
          <AlertTriangle size={18} />
          {error}
        </div>
      )}

      <section className="finding-management-metrics">
        <article>
          <ShieldAlert size={24} />
          <span>Open findings</span>
          <strong>{activeFindings.length}</strong>
        </article>

        <article className="good">
          <CheckCircle2 size={24} />
          <span>Reviewed snapshot</span>
          <strong>{reviewedFindings.length}</strong>
        </article>

        <article>
          <FileCheck2 size={24} />
          <span>False positives</span>
          <strong>{falsePositiveCount}</strong>
        </article>

        <article>
          <Clock3 size={24} />
          <span>Audit decisions</span>
          <strong>{history.length}</strong>
        </article>
      </section>

      <section className="finding-management-panel">
        <div className="finding-management-heading">
          <div>
            <span>SECURITY INVESTIGATION</span>
            <h2>Open Findings</h2>
            <p>
              Review evidence, digital signatures,
              and analyst disposition.
            </p>
          </div>

          <button
            onClick={() => void loadData()}
            disabled={loading}
          >
            <RefreshCw size={17} />
            Refresh
          </button>
        </div>

        {activeFindings.length === 0 ? (
          <div className="finding-management-empty">
            <ShieldCheck size={45} />
            <strong>No open findings</strong>
            <span>
              All current findings have been reviewed
              or no suspicious activity is active.
            </span>
          </div>
        ) : (
          <div className="finding-management-list">
            {activeFindings.map((finding) => (
              <article key={finding.id}>
                <div className="finding-management-topline">
                  <span
                    className={`finding-management-severity ${finding.severity.toLowerCase()}`}
                  >
                    {finding.severity}
                  </span>

                  <span className="finding-management-status open">
                    Open
                  </span>
                </div>

                <h3>{finding.title}</h3>
                <p>{finding.description}</p>

                <dl>
                  <div>
                    <dt>Process</dt>
                    <dd>
                      {finding.processName ?? '—'}
                      {finding.processId
                        ? ` (${finding.processId})`
                        : ''}
                    </dd>
                  </div>

                  <div>
                    <dt>File</dt>
                    <dd>{finding.filePath ?? '—'}</dd>
                  </div>

                  <div>
                    <dt>Detected</dt>
                    <dd>
                      {formatDate(
                        finding.detectedAtUtc
                      )}
                    </dd>
                  </div>
                </dl>

                <div className="finding-management-actions">
                  <button
                    className="resolve"
                    disabled={reviewing === finding.id}
                    onClick={() =>
                      void reviewFinding(
                        finding,
                        'Resolved'
                      )
                    }
                  >
                    <CheckCircle2 size={16} />
                    Resolve
                  </button>

                  <button
                    className="false-positive"
                    disabled={reviewing === finding.id}
                    onClick={() =>
                      void reviewFinding(
                        finding,
                        'FalsePositive'
                      )
                    }
                  >
                    <FileCheck2 size={16} />
                    False Positive
                  </button>

                  <button
                    className="ignore"
                    disabled={reviewing === finding.id}
                    onClick={() =>
                      void reviewFinding(
                        finding,
                        'Ignored'
                      )
                    }
                  >
                    <EyeOff size={16} />
                    Ignore
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {reviewedFindings.length > 0 && (
        <section className="finding-management-panel">
          <div className="finding-management-heading">
            <div>
              <span>CURRENT SNAPSHOT</span>
              <h2>Reviewed Findings</h2>
            </div>
          </div>

          <div className="finding-management-reviewed">
            {reviewedFindings.map((finding) => (
              <article key={finding.id}>
                <div>
                  <strong>{finding.title}</strong>
                  <span>
                    {statusLabel(finding.status)}
                    {' · '}
                    {finding.analystName ??
                      'Local Analyst'}
                  </span>
                  <p>
                    {finding.analystNote ??
                      'No analyst note.'}
                  </p>
                </div>

                <button
                  onClick={() =>
                    void reviewFinding(
                      finding,
                      'Open'
                    )
                  }
                >
                  <RotateCcw size={15} />
                  Reopen
                </button>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="finding-management-panel">
        <div className="finding-management-heading">
          <div>
            <span>ANALYST AUDIT LOG</span>
            <h2>Review History</h2>
          </div>
        </div>

        <div className="finding-management-table">
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Analyst</th>
                <th>Note</th>
                <th>Reviewed</th>
              </tr>
            </thead>

            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td colSpan={4}>
                    No analyst decisions recorded.
                  </td>
                </tr>
              ) : (
                history.map((review) => (
                  <tr key={review.id}>
                    <td>
                      <span
                        className={`finding-management-status ${review.status.toLowerCase()}`}
                      >
                        {statusLabel(review.status)}
                      </span>
                    </td>
                    <td>{review.analystName}</td>
                    <td>
                      {review.analystNote ?? '—'}
                    </td>
                    <td>
                      {formatDate(
                        review.reviewedAtUtc
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

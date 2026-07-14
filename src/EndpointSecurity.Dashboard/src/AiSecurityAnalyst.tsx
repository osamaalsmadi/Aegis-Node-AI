import {
  Bot,
  BrainCircuit,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Cpu,
  Languages,
  LoaderCircle,
  Play,
  ShieldAlert,
  Sparkles,
  Terminal
} from 'lucide-react'
import {
  useEffect,
  useState
} from 'react'
import './ai-security-analyst.css'

type Props = {
  deviceId?: string
}

type AiStatus = {
  available: boolean
  model: string
  version?: string
  privacy?: string
  message?: string
}

type AiObservation = {
  severity?: string
  title?: string
  evidence?: string
}

type AiAction = {
  priority?: number
  action?: string
  reason?: string
  command?: string
}

type AiAnalysis = {
  overallRisk?: string
  headline?: string
  executiveSummary?: string
  observations?: AiObservation[]
  priorityActions?: AiAction[]
}

type AiEnvelope = {
  model: string
  language: string
  generatedAtUtc: string
  analysis: AiAnalysis
}

async function safeJson(
  url: string
): Promise<unknown> {
  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'application/json'
      }
    })

    if (!response.ok) {
      return {
        unavailable: `HTTP ${response.status}`
      }
    }

    return response.json() as Promise<unknown>
  } catch {
    return {
      unavailable: 'Request failed'
    }
  }
}

function compactTelemetry(
  payload: unknown
): unknown {
  if (
    !payload ||
    typeof payload !== 'object' ||
    Array.isArray(payload)
  ) {
    return payload
  }

  const record =
    payload as Record<string, unknown>

  return {
    ...record,
    connections:
      Array.isArray(record.connections)
        ? record.connections.slice(0, 25)
        : record.connections,
    findings:
      Array.isArray(record.findings)
        ? record.findings.slice(0, 25)
        : record.findings
  }
}

function compactEvents(
  payload: unknown
): unknown {
  if (Array.isArray(payload)) {
    return payload.slice(0, 40)
  }

  if (
    payload &&
    typeof payload === 'object'
  ) {
    const record =
      payload as Record<string, unknown>

    if (Array.isArray(record.items)) {
      return {
        ...record,
        items: record.items.slice(0, 40)
      }
    }
  }

  return payload
}

function riskClass(
  risk?: string
): string {
  const value = risk?.toLowerCase() ?? ''

  if (
    value === 'critical' ||
    value === 'high'
  ) {
    return 'danger'
  }

  if (value === 'medium') {
    return 'warning'
  }

  return 'safe'
}

export function AiSecurityAnalyst({
  deviceId
}: Props) {
  const [status, setStatus] =
    useState<AiStatus | null>(null)

  const [analysis, setAnalysis] =
    useState<AiEnvelope | null>(null)

  const [language, setLanguage] =
    useState<'Arabic' | 'English'>('Arabic')

  const [question, setQuestion] =
    useState(
      'Analyze the endpoint and explain the most important risks and next actions.'
    )

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState('')

  useEffect(() => {
    void safeJson('/api/ai-security/status')
      .then((payload) => {
        setStatus(payload as AiStatus)
      })
  }, [])

  async function runAnalysis(): Promise<void> {
    if (!deviceId) {
      setError(
        'No managed endpoint is available.'
      )
      return
    }

    setLoading(true)
    setError('')

    try {
      const [
        devices,
        posture,
        telemetry,
        eventSummary,
        events
      ] = await Promise.all([
        safeJson('/api/devices'),
        safeJson(
          `/api/security-posture/${deviceId}/latest`
        ),
        safeJson(
          `/api/telemetry/${deviceId}/latest`
        ),
        safeJson(
          `/api/security-events/devices/${deviceId}/summary`
        ),
        safeJson(
          `/api/security-events/devices/${deviceId}?limit=40`
        )
      ])

      const context = {
        analyzedAtUtc:
          new Date().toISOString(),
        selectedDeviceId: deviceId,
        devices,
        posture,
        telemetry:
          compactTelemetry(telemetry),
        securityEventSummary:
          eventSummary,
        recentSecurityEvents:
          compactEvents(events)
      }

      const response = await fetch(
        '/api/ai-security/analyze',
        {
          method: 'POST',
          headers: {
            'Content-Type':
              'application/json',
            Accept: 'application/json'
          },
          body: JSON.stringify({
            context,
            question,
            language
          })
        }
      )

      const payload =
        await response.json() as
          AiEnvelope & {
            error?: string
          }

      if (!response.ok) {
        throw new Error(
          payload.error ??
          `AI request failed: ${response.status}`
        )
      }

      setAnalysis(payload)
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'AI analysis failed.'
      )
    } finally {
      setLoading(false)
    }
  }

  const observations =
    analysis?.analysis.observations ?? []

  const actions =
    analysis?.analysis.priorityActions ?? []

  const directionClass =
    analysis?.language === 'Arabic'
      ? 'rtl'
      : ''

  return (
    <section className="ai-analyst">
      <div className="ai-control-grid">
        <article className="ai-status-card">
          <div className="ai-card-icon">
            <BrainCircuit size={28} />
          </div>

          <div>
            <span>Local AI engine</span>
            <strong>
              {status?.available
                ? 'Operational'
                : 'Unavailable'}
            </strong>
            <small>
              {status?.model ??
                'Checking local model...'}
            </small>
          </div>

          <span
            className={
              status?.available
                ? 'ai-status good'
                : 'ai-status bad'
            }
          >
            {status?.available
              ? 'LOCAL'
              : 'OFFLINE'}
          </span>
        </article>

        <article className="ai-status-card">
          <div className="ai-card-icon">
            <Cpu size={28} />
          </div>

          <div>
            <span>Processing</span>
            <strong>On this device</strong>
            <small>
              No paid cloud API required
            </small>
          </div>

          <CheckCircle2
            className="ai-good-icon"
            size={24}
          />
        </article>

        <article className="ai-status-card">
          <div className="ai-card-icon">
            <ShieldAlert size={28} />
          </div>

          <div>
            <span>Evidence sources</span>
            <strong>
              Posture + Events
            </strong>
            <small>
              Telemetry and findings included
            </small>
          </div>

          <Sparkles
            className="ai-spark-icon"
            size={24}
          />
        </article>
      </div>

      <article className="ai-workspace">
        <header className="ai-workspace-header">
          <div>
            <span className="eyebrow">
              LOCAL SECURITY INTELLIGENCE
            </span>
            <h2>
              <Bot size={28} />
              AI Security Analyst
            </h2>
            <p>
              Analyze the endpoint using its
              latest real security evidence.
            </p>
          </div>

          <div className="ai-language">
            <Languages size={18} />

            <select
              value={language}
              onChange={(event) =>
                setLanguage(
                  event.target.value as
                    'Arabic' | 'English'
                )
              }
            >
              <option value="Arabic">
                Arabic
              </option>
              <option value="English">
                English
              </option>
            </select>
          </div>
        </header>

        <div className="ai-question">
          <label htmlFor="ai-question">
            Analyst question
          </label>

          <textarea
            id="ai-question"
            value={question}
            maxLength={1000}
            onChange={(event) =>
              setQuestion(event.target.value)
            }
          />

          <div className="ai-question-footer">
            <span>
              The model can take up to a minute
              on the first analysis.
            </span>

            <button
              type="button"
              onClick={() =>
                void runAnalysis()
              }
              disabled={
                loading ||
                !status?.available
              }
            >
              {loading ? (
                <LoaderCircle
                  className="spinning"
                  size={20}
                />
              ) : (
                <Play size={20} />
              )}

              {loading
                ? 'Analyzing evidence...'
                : 'Analyze Endpoint'}
            </button>
          </div>
        </div>

        {error && (
          <div className="ai-error">
            <CircleAlert size={20} />
            {error}
          </div>
        )}
      </article>

      {!analysis && !loading && (
        <article className="ai-empty">
          <BrainCircuit size={48} />

          <h3>
            Ready for local AI analysis
          </h3>

          <p>
            Press Analyze Endpoint to generate
            an evidence-based SOC assessment.
          </p>
        </article>
      )}

      {analysis && (
        <div
          className={`ai-result ${directionClass}`}
        >
          <article className="ai-summary-card">
            <header>
              <div>
                <span className="eyebrow">
                  AI ASSESSMENT
                </span>
                <h2>
                  {analysis.analysis.headline ??
                    'Security analysis'}
                </h2>
              </div>

              <span
                className={`ai-risk ${riskClass(
                  analysis.analysis.overallRisk
                )}`}
              >
                {analysis.analysis.overallRisk ??
                  'Unknown'}
              </span>
            </header>

            <p>
              {analysis.analysis
                .executiveSummary ??
                'No executive summary returned.'}
            </p>

            <footer>
              <span>
                <Bot size={16} />
                {analysis.model}
              </span>

              <span>
                <Clock3 size={16} />
                {new Date(
                  analysis.generatedAtUtc
                ).toLocaleString()}
              </span>
            </footer>
          </article>

          <div className="ai-result-grid">
            <article className="ai-list-card">
              <header>
                <ShieldAlert size={23} />
                <div>
                  <span className="eyebrow">
                    EVIDENCE
                  </span>
                  <h3>Security Observations</h3>
                </div>
              </header>

              {observations.length === 0 ? (
                <p className="ai-muted">
                  No observations returned.
                </p>
              ) : (
                <div className="ai-list">
                  {observations.map(
                    (item, index) => (
                      <div
                        className="ai-list-item"
                        key={`${item.title}-${index}`}
                      >
                        <span
                          className={`ai-severity ${riskClass(
                            item.severity
                          )}`}
                        >
                          {item.severity ??
                            'Info'}
                        </span>

                        <div>
                          <strong>
                            {item.title ??
                              'Observation'}
                          </strong>
                          <p>
                            {item.evidence ??
                              'No evidence supplied.'}
                          </p>
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </article>

            <article className="ai-list-card">
              <header>
                <Sparkles size={23} />
                <div>
                  <span className="eyebrow">
                    RESPONSE PLAN
                  </span>
                  <h3>Priority Actions</h3>
                </div>
              </header>

              {actions.length === 0 ? (
                <p className="ai-muted">
                  No actions returned.
                </p>
              ) : (
                <div className="ai-list">
                  {actions.map(
                    (item, index) => (
                      <div
                        className="ai-action-item"
                        key={`${item.action}-${index}`}
                      >
                        <span className="ai-priority">
                          {item.priority ??
                            index + 1}
                        </span>

                        <div>
                          <strong>
                            {item.action ??
                              'Recommended action'}
                          </strong>
                          <p>
                            {item.reason ??
                              'No reason supplied.'}
                          </p>

                          {item.command && (
                            <code>
                              <Terminal size={15} />
                              {item.command}
                            </code>
                          )}
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </article>
          </div>
        </div>
      )}
    </section>
  )
}

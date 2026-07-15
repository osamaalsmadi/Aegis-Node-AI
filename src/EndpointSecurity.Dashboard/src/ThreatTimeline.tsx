import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FileSearch,
  History,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Wifi,
  XCircle
} from 'lucide-react'
import './threat-timeline.css'

type TimelineItem = {
  id: string
  type: string
  severity: string
  title: string
  description: string
  status: string
  category: string
  evidence: string
  recommendedAction: string
  occurredAtUtc: string
}

type TimelineSummary = {
  totalItems: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  informationalCount: number
  actionRequiredCount: number
  securityEventCount: number
  findingCount: number
  remediationCount: number
  scanCount: number
  telemetryCount: number
  postureCount: number
  currentRiskScore: number
  latestActivityAtUtc?: string
}

type TimelineResponse = {
  deviceId: string
  hostName: string
  generatedAtUtc: string
  windowHours: number
  returnedItems: number
  summary: TimelineSummary
  items: TimelineItem[]
}

type Props = {
  deviceId?: string
  online: boolean
}

const timelineTypes = [
  'All',
  'SecurityEvent',
  'Finding',
  'Remediation',
  'Scan',
  'Posture',
  'Telemetry',
  'Agent'
]

const severityTypes = [
  'All',
  'Critical',
  'High',
  'Medium',
  'Low',
  'Informational'
]

function parseApiDate(value: string): Date {
  const includesTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  return new Date(
    includesTimeZone ? value : `${value}Z`
  )
}

function formatDate(value?: string): string {
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
    minute: '2-digit',
    second: '2-digit'
  }).format(date)
}

function relativeTime(value: string): string {
  const time = parseApiDate(value).getTime()

  if (Number.isNaN(time)) {
    return 'Unknown time'
  }

  const differenceSeconds = Math.max(
    0,
    Math.floor((Date.now() - time) / 1000)
  )

  if (differenceSeconds < 60) {
    return `${differenceSeconds}s ago`
  }

  const minutes = Math.floor(
    differenceSeconds / 60
  )

  if (minutes < 60) {
    return `${minutes}m ago`
  }

  const hours = Math.floor(minutes / 60)

  if (hours < 24) {
    return `${hours}h ago`
  }

  return `${Math.floor(hours / 24)}d ago`
}

function typeLabel(type: string): string {
  return type === 'SecurityEvent'
    ? 'Windows Event'
    : type
}

function sourceIcon(type: string): ReactNode {
  switch (type) {
    case 'SecurityEvent':
      return <TerminalSquare size={19} />
    case 'Finding':
      return <ShieldAlert size={19} />
    case 'Remediation':
      return <ShieldCheck size={19} />
    case 'Scan':
      return <FileSearch size={19} />
    case 'Posture':
      return <CheckCircle2 size={19} />
    case 'Telemetry':
      return <Activity size={19} />
    case 'Agent':
      return <Wifi size={19} />
    default:
      return <History size={19} />
  }
}

export function ThreatTimeline({
  deviceId,
  online
}: Props) {
  const [timeline, setTimeline] =
    useState<TimelineResponse | null>(null)
  const [windowHours, setWindowHours] =
    useState(24)
  const [typeFilter, setTypeFilter] =
    useState('All')
  const [severityFilter, setSeverityFilter] =
    useState('All')
  const [searchText, setSearchText] =
    useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadTimeline = useCallback(async () => {
    if (!deviceId) {
      setTimeline(null)
      setError('No endpoint is available for timeline analysis.')
      return
    }

    setLoading(true)

    try {
      const response = await fetch(
        `/api/threat-timeline/devices/${deviceId}?hours=${windowHours}&limit=500`,
        {
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        throw new Error(
          `Timeline request failed: ${response.status} ${response.statusText}`
        )
      }

      const payload =
        (await response.json()) as TimelineResponse

      setTimeline({
        ...payload,
        items: Array.isArray(payload.items)
          ? payload.items
          : []
      })
      setError('')
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Threat Timeline could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId, windowHours])

  useEffect(() => {
    void loadTimeline()

    const timer = window.setInterval(() => {
      void loadTimeline()
    }, 30_000)

    return () => window.clearInterval(timer)
  }, [loadTimeline])

  const filteredItems = useMemo(() => {
    const query = searchText
      .trim()
      .toLowerCase()

    return (timeline?.items ?? []).filter((item) => {
      const matchesType =
        typeFilter === 'All' ||
        item.type === typeFilter

      const matchesSeverity =
        severityFilter === 'All' ||
        item.severity === severityFilter

      const searchable = [
        item.title,
        item.description,
        item.evidence,
        item.category,
        item.status,
        item.type
      ]
        .join(' ')
        .toLowerCase()

      return (
        matchesType &&
        matchesSeverity &&
        (query.length === 0 || searchable.includes(query))
      )
    })
  }, [
    timeline,
    typeFilter,
    severityFilter,
    searchText
  ])

  const summary = timeline?.summary

  if (!deviceId) {
    return (
      <section className="panel timeline-unavailable">
        <History size={34} />
        <h2>Threat Timeline unavailable</h2>
        <p>
          Register an endpoint before opening the unified
          security timeline.
        </p>
      </section>
    )
  }

  return (
    <div className="threat-timeline-page">
      <section className="timeline-summary-grid">
        <article className="panel timeline-summary-card">
          <div className="timeline-summary-icon cyan">
            <History size={21} />
          </div>
          <span>Total activity</span>
          <strong>{summary?.totalItems ?? 0}</strong>
          <small>
            Last {timeline?.windowHours ?? windowHours} hours
          </small>
        </article>

        <article className="panel timeline-summary-card attention">
          <div className="timeline-summary-icon orange">
            <AlertTriangle size={21} />
          </div>
          <span>Action required</span>
          <strong>{summary?.actionRequiredCount ?? 0}</strong>
          <small>
            High, critical, or open findings
          </small>
        </article>

        <article className="panel timeline-summary-card">
          <div className="timeline-summary-icon purple">
            <TerminalSquare size={21} />
          </div>
          <span>Windows events</span>
          <strong>{summary?.securityEventCount ?? 0}</strong>
          <small>
            Security records in this window
          </small>
        </article>

        <article className="panel timeline-summary-card good">
          <div className="timeline-summary-icon green">
            <ShieldCheck size={21} />
          </div>
          <span>Security actions</span>
          <strong>
            {(summary?.remediationCount ?? 0) +
              (summary?.scanCount ?? 0)}
          </strong>
          <small>Scans and remediation operations</small>
        </article>
      </section>

      <section className="panel timeline-workspace">
        <div className="timeline-heading">
          <div>
            <span className="section-label">
              UNIFIED SECURITY HISTORY
            </span>
            <h2>
              {timeline?.hostName ?? 'Endpoint'} Threat Timeline
            </h2>
            <p>
              Findings, Windows events, scans, remediation,
              protection posture, and telemetry ordered by time.
            </p>
          </div>

          <div className="timeline-heading-status">
            <span
              className={`timeline-live-state ${online ? 'online' : 'offline'}`}
            >
              <span />
              {online ? 'Endpoint online' : 'Endpoint offline'}
            </span>

            <button
              className="timeline-refresh-button"
              onClick={() => void loadTimeline()}
              disabled={loading}
            >
              <RefreshCw
                size={17}
                className={loading ? 'spinning' : ''}
              />
              Refresh
            </button>
          </div>
        </div>

        <div className="timeline-risk-strip">
          <span>Current risk</span>
          <strong>{summary?.currentRiskScore ?? 0}/100</strong>
          <div>
            <span>Critical {summary?.criticalCount ?? 0}</span>
            <span>High {summary?.highCount ?? 0}</span>
            <span>Medium {summary?.mediumCount ?? 0}</span>
            <span>Low {summary?.lowCount ?? 0}</span>
          </div>
          <time>
            Latest: {formatDate(summary?.latestActivityAtUtc)}
          </time>
        </div>

        <div className="timeline-toolbar">
          <label className="timeline-search-box">
            <Search size={17} />
            <input
              value={searchText}
              onChange={(event) =>
                setSearchText(event.target.value)
              }
              placeholder="Search title, evidence, category, or status"
            />
          </label>

          <label>
            <span>Time range</span>
            <select
              value={windowHours}
              onChange={(event) =>
                setWindowHours(Number(event.target.value))
              }
            >
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 3 days</option>
              <option value={168}>Last 7 days</option>
            </select>
          </label>

          <label>
            <span>Source</span>
            <select
              value={typeFilter}
              onChange={(event) =>
                setTypeFilter(event.target.value)
              }
            >
              {timelineTypes.map((type) => (
                <option value={type} key={type}>
                  {type === 'All' ? 'All sources' : typeLabel(type)}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>Severity</span>
            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(event.target.value)
              }
            >
              {severityTypes.map((severity) => (
                <option value={severity} key={severity}>
                  {severity === 'All'
                    ? 'All severities'
                    : severity}
                </option>
              ))}
            </select>
          </label>
        </div>

        {error && (
          <div className="timeline-error">
            <XCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {loading && !timeline ? (
          <div className="timeline-loading">
            <RefreshCw size={25} className="spinning" />
            <strong>Building unified timeline...</strong>
            <span>Correlating endpoint security records</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="timeline-empty">
            <CheckCircle2 size={31} />
            <strong>No matching activity</strong>
            <span>
              No timeline records match the selected filters.
            </span>
          </div>
        ) : (
          <div className="timeline-feed">
            {filteredItems.map((item) => (
              <article
                className={`timeline-entry ${item.severity.toLowerCase()}`}
                key={`${item.type}-${item.id}`}
              >
                <div className="timeline-rail">
                  <div className="timeline-source-icon">
                    {sourceIcon(item.type)}
                  </div>
                  <span />
                </div>

                <div className="timeline-entry-content">
                  <div className="timeline-entry-topline">
                    <div>
                      <span className="timeline-type-badge">
                        {typeLabel(item.type)}
                      </span>
                      <span
                        className={`timeline-severity-badge ${item.severity.toLowerCase()}`}
                      >
                        {item.severity}
                      </span>
                      <span className="timeline-status-badge">
                        {item.status}
                      </span>
                    </div>

                    <time title={formatDate(item.occurredAtUtc)}>
                      <Clock3 size={14} />
                      {relativeTime(item.occurredAtUtc)}
                    </time>
                  </div>

                  <h3>{item.title}</h3>
                  <p>{item.description}</p>

                  <div className="timeline-details-grid">
                    <div>
                      <span>Evidence</span>
                      <strong>{item.evidence}</strong>
                    </div>

                    <div>
                      <span>Recommended action</span>
                      <strong>{item.recommendedAction}</strong>
                    </div>
                  </div>

                  <footer>
                    <span>{item.category}</span>
                    <span>{formatDate(item.occurredAtUtc)}</span>
                  </footer>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

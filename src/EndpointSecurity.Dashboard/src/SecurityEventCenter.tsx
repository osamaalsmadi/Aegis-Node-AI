import {
  AlertTriangle,
  Clock3,
  Filter,
  KeyRound,
  RefreshCw,
  Search,
  ServerCog,
  ShieldAlert,
  ShieldCheck
} from 'lucide-react'
import {
  useCallback,
  useEffect,
  useMemo,
  useState
} from 'react'
import './security-event-center.css'

type WindowsSecurityEvent = {
  id: string
  deviceId: string
  eventKey: string
  providerName: string
  logName: string
  eventId: number
  level: string
  severity: string
  category: string
  title: string
  message: string
  recordId: number
  occurredAtUtc: string
  collectedAtUtc: string
}

type EventSummary = {
  deviceId: string
  totalEvents: number
  criticalCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  failedLogonCount: number
  defenderEventCount: number
  riskScore: number
  lastEventAtUtc?: string
}

type Props = {
  deviceId?: string
  online: boolean
}

function parseApiDate(value: string): Date {
  const hasTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  return new Date(
    hasTimeZone ? value : `${value}Z`
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

function severityClass(value: string): string {
  return value.toLowerCase()
}

const emptySummary: EventSummary = {
  deviceId: '',
  totalEvents: 0,
  criticalCount: 0,
  highCount: 0,
  mediumCount: 0,
  lowCount: 0,
  failedLogonCount: 0,
  defenderEventCount: 0,
  riskScore: 0
}

export function SecurityEventCenter({
  deviceId,
  online
}: Props) {
  const [events, setEvents] =
    useState<WindowsSecurityEvent[]>([])

  const [summary, setSummary] =
    useState<EventSummary>(emptySummary)

  const [filter, setFilter] =
    useState('All')

  const [searchText, setSearchText] =
    useState('')

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState('')

  const loadEvents = useCallback(async () => {
    if (!deviceId) {
      setEvents([])
      setSummary(emptySummary)
      setLoading(false)
      return
    }

    setLoading(true)

    try {
      const [eventsResponse, summaryResponse] =
        await Promise.all([
          fetch(
            `/api/security-events/devices/${deviceId}?limit=200`
          ),
          fetch(
            `/api/security-events/devices/${deviceId}/summary`
          )
        ])

      if (
        !eventsResponse.ok ||
        !summaryResponse.ok
      ) {
        throw new Error(
          'Windows security events could not be loaded.'
        )
      }

      const eventPayload =
        await eventsResponse.json() as
          WindowsSecurityEvent[]

      const summaryPayload =
        await summaryResponse.json() as
          EventSummary

      setEvents(
        Array.isArray(eventPayload)
          ? eventPayload
          : []
      )

      setSummary(summaryPayload)
      setError('')
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Security events could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadEvents()

    const timer = window.setInterval(() => {
      void loadEvents()
    }, 30_000)

    return () =>
      window.clearInterval(timer)
  }, [loadEvents])

  const visibleEvents = useMemo(() => {
    const query =
      searchText.trim().toLowerCase()

    return events.filter((securityEvent) => {
      const matchesFilter =
        filter === 'All' ||
        securityEvent.severity === filter

      const matchesSearch =
        query.length === 0 ||
        securityEvent.title
          .toLowerCase()
          .includes(query) ||
        securityEvent.message
          .toLowerCase()
          .includes(query) ||
        securityEvent.category
          .toLowerCase()
          .includes(query) ||
        securityEvent.eventId
          .toString()
          .includes(query)

      return matchesFilter && matchesSearch
    })
  }, [events, filter, searchText])

  const importantCount =
    summary.criticalCount +
    summary.highCount

  return (
    <div className="security-event-center">
      {error && (
        <div className="event-error">
          <AlertTriangle size={18} />
          {error}
        </div>
      )}

      <section className="event-metrics">
        <article className="event-metric">
          <ShieldAlert size={25} />
          <span>Events in 24 hours</span>
          <strong>{summary.totalEvents}</strong>
        </article>

        <article className="event-metric danger">
          <AlertTriangle size={25} />
          <span>High / Critical</span>
          <strong>{importantCount}</strong>
        </article>

        <article className="event-metric warning">
          <KeyRound size={25} />
          <span>Failed sign-ins</span>
          <strong>
            {summary.failedLogonCount}
          </strong>
        </article>

        <article className="event-metric">
          <ShieldCheck size={25} />
          <span>Event risk contribution</span>
          <strong>{summary.riskScore}</strong>
        </article>
      </section>

      <section className="event-panel">
        <div className="event-panel-heading">
          <div>
            <span>WINDOWS EVENT MONITOR</span>
            <h2>Security Event Timeline</h2>
            <p>
              Authentication, Defender, service,
              account, and protection-change events.
            </p>
          </div>

          <div className="event-heading-actions">
            <span
              className={
                online
                  ? 'event-agent online'
                  : 'event-agent offline'
              }
            >
              <span />
              Agent {online ? 'online' : 'offline'}
            </span>

            <button
              type="button"
              onClick={() => void loadEvents()}
              disabled={loading}
            >
              <RefreshCw
                size={18}
                className={
                  loading ? 'event-spin' : ''
                }
              />
              Refresh
            </button>
          </div>
        </div>

        <div className="event-toolbar">
          <label className="event-search">
            <Search size={18} />

            <input
              value={searchText}
              onChange={(event) =>
                setSearchText(event.target.value)
              }
              placeholder="Search title, event ID, category..."
            />
          </label>

          <div className="event-filters">
            <Filter size={18} />

            {[
              'All',
              'Critical',
              'High',
              'Medium',
              'Low'
            ].map((item) => (
              <button
                type="button"
                key={item}
                className={
                  filter === item ? 'active' : ''
                }
                onClick={() => setFilter(item)}
              >
                {item}
              </button>
            ))}
          </div>
        </div>

        {loading && events.length === 0 ? (
          <div className="event-empty">
            Loading Windows security events…
          </div>
        ) : visibleEvents.length === 0 ? (
          <div className="event-empty">
            <ShieldCheck size={42} />
            <h3>No matching security events</h3>
            <p>
              No monitored Windows events matched
              the selected filter.
            </p>
          </div>
        ) : (
          <div className="event-list">
            {visibleEvents.map((securityEvent) => (
              <article
                className="event-row"
                key={securityEvent.id}
              >
                <div
                  className={
                    `event-severity ${severityClass(
                      securityEvent.severity
                    )}`
                  }
                >
                  {securityEvent.severity}
                </div>

                <div className="event-content">
                  <div className="event-title">
                    <div>
                      <strong>
                        {securityEvent.title}
                      </strong>

                      <span>
                        Event ID {securityEvent.eventId}
                        {' · '}
                        {securityEvent.category}
                      </span>
                    </div>

                    <time>
                      <Clock3 size={15} />
                      {formatDate(
                        securityEvent.occurredAtUtc
                      )}
                    </time>
                  </div>

                  <p>{securityEvent.message}</p>

                  <div className="event-source">
                    <ServerCog size={15} />
                    {securityEvent.providerName}
                    {' · '}
                    {securityEvent.logName}
                    {' · Record '}
                    {securityEvent.recordId}
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

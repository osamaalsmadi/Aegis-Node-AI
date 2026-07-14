import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type CSSProperties
} from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleGauge,
  Clock3,
  Cpu,
  Database,
  HardDrive,
  LayoutDashboard,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  TerminalSquare,
  Wifi,
  XCircle
} from 'lucide-react'
import {
  AdditionalPages,
  type DashboardPage
} from './AdditionalPages'
import './App.css'
import './pages.css'

type Device = {
  id: string
  hostName: string
  operatingSystem: string
  operatingSystemVersion: string
  architecture: string
  agentVersion: string
  status: string | number
  riskScore: number
  firstSeenUtc: string
  lastSeenUtc: string
}

type SecurityPosture = {
  id: string
  deviceId: string
  defenderEnabled: boolean
  realTimeProtectionEnabled: boolean
  antivirusSignatureAgeDays: number
  firewallDomainEnabled: boolean
  firewallPrivateEnabled: boolean
  firewallPublicEnabled: boolean
  rebootRequired: boolean
  riskScore: number
  collectedAtUtc: string
}

type SecurityFinding = {
  id?: string
  title?: string
  description?: string
  severity?: string | number
}

type Telemetry = {
  id?: string
  deviceId?: string
  processCount: number
  activeTcpConnectionCount: number
  riskScore: number
  collectedAtUtc: string
  findings?: SecurityFinding[]
}

type ApiHealth = {
  service: string
  status: string
  version: string
  utcTime: string
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: {
      Accept: 'application/json'
    }
  })

  if (!response.ok) {
    throw new Error(
      `Request failed: ${response.status} ${response.statusText}`
    )
  }

  return response.json() as Promise<T>
}

function extractDevices(payload: unknown): Device[] {
  if (Array.isArray(payload)) {
    return payload as Device[]
  }

  if (payload && typeof payload === 'object') {
    const wrapped = payload as {
      items?: unknown
      $values?: unknown
    }

    if (Array.isArray(wrapped.items)) {
      return wrapped.items as Device[]
    }

    if (Array.isArray(wrapped.$values)) {
      return wrapped.$values as Device[]
    }
  }

  return []
}

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

function isRecentlyOnline(value?: string): boolean {
  if (!value) {
    return false
  }

  const time = parseApiDate(value).getTime()

  if (Number.isNaN(time)) {
    return false
  }

  return Date.now() - time < 180_000
}

function App() {
  const [devices, setDevices] = useState<Device[]>([])
  const [posture, setPosture] =
    useState<SecurityPosture | null>(null)
  const [telemetry, setTelemetry] =
    useState<Telemetry | null>(null)
  const [health, setHealth] =
    useState<ApiHealth | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [lastRefresh, setLastRefresh] =
    useState<Date | null>(null)
  const [activePage, setActivePage] =
    useState<DashboardPage>('overview')

  const loadDashboard = useCallback(async () => {
    setLoading(true)

    try {
      const [healthResult, devicePayload] =
        await Promise.all([
          getJson<ApiHealth>('/api/health'),
          getJson<unknown>('/api/devices')
        ])

      const deviceList = extractDevices(devicePayload)
        .sort(
          (first, second) =>
            parseApiDate(second.lastSeenUtc).getTime() -
            parseApiDate(first.lastSeenUtc).getTime()
        )

      setHealth(healthResult)
      setDevices(deviceList)

      const currentDevice = deviceList[0]

      if (!currentDevice) {
        setPosture(null)
        setTelemetry(null)
        setError('No registered endpoint was returned by the API.')
        return
      }

      const [postureResult, telemetryResult] =
        await Promise.all([
          getJson<SecurityPosture>(
            `/api/security-posture/${currentDevice.id}/latest`
          ),
          getJson<Telemetry>(
            `/api/telemetry/${currentDevice.id}/latest`
          )
        ])

      setPosture(postureResult)
      setTelemetry(telemetryResult)
      setError('')
      setLastRefresh(new Date())
    } catch (requestError) {
      const message =
        requestError instanceof Error
          ? requestError.message
          : 'Dashboard data could not be loaded.'

      setError(message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadDashboard()

    const timer = window.setInterval(() => {
      void loadDashboard()
    }, 30_000)

    return () => window.clearInterval(timer)
  }, [loadDashboard])

  const device = devices[0] ?? null
  const online = isRecentlyOnline(device?.lastSeenUtc)
  const apiHealthy =
    health?.status?.toLowerCase() === 'healthy'

  const riskScore =
    telemetry?.riskScore ??
    posture?.riskScore ??
    device?.riskScore ??
    0

  const riskLabel =
    riskScore === 0
      ? 'Secure'
      : riskScore < 30
        ? 'Low Risk'
        : riskScore < 60
          ? 'Medium Risk'
          : 'High Risk'

  const riskColor =
    riskScore === 0
      ? '#38e8a3'
      : riskScore < 30
        ? '#71e177'
        : riskScore < 60
          ? '#ffbd5a'
          : '#ff6377'

  const riskStyle = {
    '--risk-angle': `${Math.min(100, Math.max(0, riskScore)) * 3.6}deg`,
    '--risk-color': riskColor
  } as CSSProperties

  const securityChecks = useMemo(
    () => [
      {
        name: 'Microsoft Defender',
        description: 'Antivirus engine',
        healthy: posture?.defenderEnabled ?? false
      },
      {
        name: 'Real-time Protection',
        description: 'Live threat monitoring',
        healthy:
          posture?.realTimeProtectionEnabled ?? false
      },
      {
        name: 'Domain Firewall',
        description: 'Enterprise network profile',
        healthy:
          posture?.firewallDomainEnabled ?? false
      },
      {
        name: 'Private Firewall',
        description: 'Trusted network profile',
        healthy:
          posture?.firewallPrivateEnabled ?? false
      },
      {
        name: 'Public Firewall',
        description: 'Untrusted network profile',
        healthy:
          posture?.firewallPublicEnabled ?? false
      },
      {
        name: 'Reboot State',
        description: 'No pending security reboot',
        healthy: posture ? !posture.rebootRequired : false
      }
    ],
    [posture]
  )

  const healthyChecks =
    securityChecks.filter((check) => check.healthy).length

  const findingsCount =
    telemetry?.findings?.length ?? 0

  const processPercent = Math.min(
    100,
    ((telemetry?.processCount ?? 0) / 400) * 100
  )

  const connectionPercent = Math.min(
    100,
    ((telemetry?.activeTcpConnectionCount ?? 0) / 100) *
      100
  )

  const pageHeadings = {
    overview: {
      title: 'Endpoint Overview',
      description:
        'Live security posture and endpoint telemetry'
    },
    endpoints: {
      title: 'Managed Endpoints',
      description:
        'Device inventory, health, versions, and connectivity'
    },
    findings: {
      title: 'Security Findings',
      description:
        'Detected threats, suspicious behavior, and remediation'
    },
    network: {
      title: 'Network Activity',
      description:
        'Live process-to-network connection telemetry'
    },
    activity: {
      title: 'Security Activity',
      description:
        'Recent agent, posture, telemetry, and detection events'
    }
  }

  const currentHeading =
    pageHeadings[activePage]

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>

          <div>
            <strong>Endpoint Security</strong>
            <span>Operations Platform</span>
          </div>
        </div>

        <nav className="navigation">
          <button
            className={`nav-item ${activePage === 'overview' ? 'active' : ''}`}
            onClick={() => setActivePage('overview')}
          >
            <LayoutDashboard size={19} />
            Overview
          </button>

          <button
            className={`nav-item ${activePage === 'endpoints' ? 'active' : ''}`}
            onClick={() => setActivePage('endpoints')}
          >
            <Server size={19} />
            Endpoints
          </button>

          <button
            className={`nav-item ${activePage === 'findings' ? 'active' : ''}`}
            onClick={() => setActivePage('findings')}
          >
            <AlertTriangle size={19} />
            Findings
          </button>

          <button
            className={`nav-item ${activePage === 'network' ? 'active' : ''}`}
            onClick={() => setActivePage('network')}
          >
            <Network size={19} />
            Network
          </button>

          <button
            className={`nav-item ${activePage === 'activity' ? 'active' : ''}`}
            onClick={() => setActivePage('activity')}
          >
            <TerminalSquare size={19} />
            Activity
          </button>
        </nav>

        <div className="sidebar-status">
          <span className={`pulse ${apiHealthy ? 'good' : 'bad'}`} />

          <div>
            <strong>
              {apiHealthy ? 'API Operational' : 'API Offline'}
            </strong>
            <span>Version {health?.version ?? '—'}</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">SECURITY OPERATIONS</span>
            <h1>{currentHeading.title}</h1>
            <p>{currentHeading.description}</p>
          </div>

          <div className="topbar-actions">
            <div className="live-badge">
              <span className="pulse good" />
              Live monitoring
            </div>

            <button
              className="refresh-button"
              onClick={() => void loadDashboard()}
              disabled={loading}
            >
              <RefreshCw
                size={18}
                className={loading ? 'spinning' : ''}
              />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <XCircle size={19} />
            <span>{error}</span>
          </div>
        )}

        {activePage === 'overview' ? (
          <>
        <section className="summary-grid">
          <article className="risk-card panel">
            <div className="panel-heading">
              <div>
                <span className="section-label">
                  CURRENT EXPOSURE
                </span>
                <h2>Security Risk Score</h2>
              </div>

              <CircleGauge size={22} />
            </div>

            <div className="risk-content">
              <div
                className="risk-orbit"
                style={riskStyle}
              >
                <div className="risk-center">
                  <strong>{riskScore}</strong>
                  <span>/ 100</span>
                </div>
              </div>

              <div className="risk-details">
                <span
                  className="risk-label"
                  style={{ color: riskColor }}
                >
                  {riskLabel}
                </span>

                <p>
                  Calculated from Defender, firewall,
                  processes, findings, and network activity.
                </p>

                <div className="risk-foot">
                  <CheckCircle2 size={17} />
                  {findingsCount === 0
                    ? 'No active findings detected'
                    : `${findingsCount} findings require review`}
                </div>
              </div>
            </div>
          </article>

          <article className="metric-card panel">
            <div className="metric-icon cyan">
              <HardDrive size={22} />
            </div>

            <span>Managed Endpoints</span>
            <strong>{devices.length}</strong>

            <div className="metric-footer">
              <span className={`status-dot ${online ? 'online' : 'offline'}`} />
              {online ? 'Endpoint online' : 'Endpoint offline'}
            </div>
          </article>

          <article className="metric-card panel">
            <div className="metric-icon purple">
              <Cpu size={22} />
            </div>

            <span>Running Processes</span>
            <strong>{telemetry?.processCount ?? '—'}</strong>

            <div className="metric-footer">
              Latest endpoint snapshot
            </div>
          </article>

          <article className="metric-card panel">
            <div className="metric-icon orange">
              <Wifi size={22} />
            </div>

            <span>TCP Connections</span>
            <strong>
              {telemetry?.activeTcpConnectionCount ?? '—'}
            </strong>

            <div className="metric-footer">
              Active established sessions
            </div>
          </article>
        </section>

        <section className="content-grid">
          <article className="panel security-panel">
            <div className="panel-heading">
              <div>
                <span className="section-label">
                  PROTECTION STATUS
                </span>
                <h2>Security Controls</h2>
              </div>

              <span className="check-score">
                {healthyChecks}/{securityChecks.length} healthy
              </span>
            </div>

            <div className="checks-list">
              {securityChecks.map((check) => (
                <div className="security-check" key={check.name}>
                  <div
                    className={
                      check.healthy
                        ? 'check-icon healthy'
                        : 'check-icon unhealthy'
                    }
                  >
                    {check.healthy ? (
                      <CheckCircle2 size={19} />
                    ) : (
                      <AlertTriangle size={19} />
                    )}
                  </div>

                  <div>
                    <strong>{check.name}</strong>
                    <span>{check.description}</span>
                  </div>

                  <span
                    className={
                      check.healthy
                        ? 'control-state enabled'
                        : 'control-state disabled'
                    }
                  >
                    {check.healthy ? 'Enabled' : 'Attention'}
                  </span>
                </div>
              ))}
            </div>
          </article>

          <article className="panel telemetry-panel">
            <div className="panel-heading">
              <div>
                <span className="section-label">
                  LIVE TELEMETRY
                </span>
                <h2>Endpoint Activity</h2>
              </div>

              <Activity size={22} />
            </div>

            <div className="telemetry-item">
              <div className="telemetry-title">
                <span>Processes</span>
                <strong>
                  {telemetry?.processCount ?? 0}
                </strong>
              </div>

              <div className="progress-track">
                <div
                  className="progress-fill cyan-fill"
                  style={{ width: `${processPercent}%` }}
                />
              </div>
            </div>

            <div className="telemetry-item">
              <div className="telemetry-title">
                <span>Network connections</span>
                <strong>
                  {telemetry?.activeTcpConnectionCount ?? 0}
                </strong>
              </div>

              <div className="progress-track">
                <div
                  className="progress-fill purple-fill"
                  style={{ width: `${connectionPercent}%` }}
                />
              </div>
            </div>

            <div className="telemetry-info">
              <Database size={19} />

              <div>
                <strong>SQL persistence active</strong>
                <span>
                  Security snapshots are stored automatically
                </span>
              </div>
            </div>

            <div className="telemetry-info">
              <Search size={19} />

              <div>
                <strong>Behavior rules active</strong>
                <span>
                  Suspicious commands and paths are monitored
                </span>
              </div>
            </div>
          </article>
        </section>

        <section className="panel device-panel">
          <div className="panel-heading">
            <div>
              <span className="section-label">
                ASSET INVENTORY
              </span>
              <h2>Managed Devices</h2>
            </div>

            <Shield size={22} />
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Operating System</th>
                  <th>Architecture</th>
                  <th>Agent</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                </tr>
              </thead>

              <tbody>
                {devices.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-row">
                      No endpoints are currently registered.
                    </td>
                  </tr>
                ) : (
                  devices.map((item) => {
                    const itemOnline =
                      isRecentlyOnline(item.lastSeenUtc)

                    return (
                      <tr key={item.id}>
                        <td>
                          <div className="endpoint-name">
                            <div className="device-avatar">
                              <HardDrive size={18} />
                            </div>

                            <div>
                              <strong>{item.hostName}</strong>
                              <span>{item.id.slice(0, 13)}…</span>
                            </div>
                          </div>
                        </td>

                        <td>
                          <strong>{item.operatingSystem}</strong>
                          <span className="table-subtext">
                            {item.operatingSystemVersion}
                          </span>
                        </td>

                        <td>{item.architecture}</td>
                        <td>v{item.agentVersion}</td>
                        <td>
                          <span className="risk-pill">
                            {item.riskScore}
                          </span>
                        </td>

                        <td>
                          <span
                            className={
                              itemOnline
                                ? 'endpoint-status online'
                                : 'endpoint-status offline'
                            }
                          >
                            <span />
                            {itemOnline ? 'Online' : 'Offline'}
                          </span>
                        </td>

                        <td>{formatDate(item.lastSeenUtc)}</td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="dashboard-footer">
          <span>
            <Clock3 size={15} />
            Last refreshed:{' '}
            {lastRefresh
              ? lastRefresh.toLocaleTimeString()
              : 'Waiting for data'}
          </span>

          <span>
            Telemetry snapshot:{' '}
            {formatDate(telemetry?.collectedAtUtc)}
          </span>
        </footer>
          </>
        ) : (
          <AdditionalPages
            activePage={activePage}
            devices={devices}
            telemetry={telemetry}
            posture={posture}
          />
        )}
      </main>
    </div>
  )
}

export default App



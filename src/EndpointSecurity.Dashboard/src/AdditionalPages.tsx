import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Cpu,
  HardDrive,
  Network,
  Search,
  ShieldCheck,
  Wifi
} from 'lucide-react'
import { FindingManagement } from './FindingManagement'

export type DashboardPage =
  | 'overview'
  | 'endpoints'
  | 'findings'
  | 'network'
  | 'activity'
  | 'scans'
  | 'remediation'

type DeviceRecord = {
  id: string
  hostName: string
  operatingSystem: string
  operatingSystemVersion: string
  architecture: string
  agentVersion: string
  riskScore: number
  firstSeenUtc: string
  lastSeenUtc: string
}

type ConnectionRecord = {
  id?: string
  processName?: string
  processId?: number
  protocol?: string
  localAddress?: string
  localPort?: number
  remoteAddress?: string
  remotePort?: number
  state?: string
  collectedAtUtc?: string
}

type FindingRecord = {
  id?: string
  title?: string
  description?: string
  evidence?: string
  recommendation?: string
  severity?: string | number
  category?: string | number
  detectedAtUtc?: string
}

type TelemetryRecord = {
  scanId?: string
  deviceId?: string
  processCount: number
  activeTcpConnectionCount: number
  riskScore: number
  collectedAtUtc: string
  connections?: ConnectionRecord[]
  findings?: FindingRecord[]
}

type PostureRecord = {
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

type Props = {
  activePage: Exclude<DashboardPage, 'overview'>
  devices: DeviceRecord[]
  telemetry: TelemetryRecord | null
  posture: PostureRecord | null
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

function isOnline(value?: string): boolean {
  if (!value) {
    return false
  }

  const time = parseApiDate(value).getTime()

  return (
    !Number.isNaN(time) &&
    Date.now() - time < 180_000
  )
}

function severityName(
  severity?: string | number
): string {
  if (typeof severity === 'string') {
    return severity
  }

  const levels: Record<number, string> = {
    0: 'Informational',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
  }

  return levels[severity ?? 0] ?? 'Unknown'
}

export function AdditionalPages({
  activePage,
  devices,
  telemetry,
  posture
}: Props) {
  const connections = telemetry?.connections ?? []
  const findings = telemetry?.findings ?? []

  if (activePage === 'findings') {
    return (
      <FindingManagement
        deviceId={telemetry?.deviceId}
      />
    )
  }

  if (activePage === 'endpoints') {
    const onlineDevices = devices.filter((device) =>
      isOnline(device.lastSeenUtc)
    ).length

    const averageRisk =
      devices.length === 0
        ? 0
        : Math.round(
            devices.reduce(
              (total, device) =>
                total + device.riskScore,
              0
            ) / devices.length
          )

    return (
      <div className="page-content">
        <section className="page-metrics">
          <article className="page-metric panel">
            <HardDrive size={23} />
            <span>Total endpoints</span>
            <strong>{devices.length}</strong>
          </article>

          <article className="page-metric panel good">
            <Wifi size={23} />
            <span>Online endpoints</span>
            <strong>{onlineDevices}</strong>
          </article>

          <article className="page-metric panel">
            <Activity size={23} />
            <span>Offline endpoints</span>
            <strong>
              {devices.length - onlineDevices}
            </strong>
          </article>

          <article className="page-metric panel">
            <ShieldCheck size={23} />
            <span>Average risk</span>
            <strong>{averageRisk}</strong>
          </article>
        </section>

        <section className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <span className="section-label">
                DEVICE INVENTORY
              </span>
              <h2>Registered Endpoints</h2>
            </div>

            <HardDrive size={22} />
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Operating System</th>
                  <th>Architecture</th>
                  <th>Agent</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                </tr>
              </thead>

              <tbody>
                {devices.map((device) => {
                  const online =
                    isOnline(device.lastSeenUtc)

                  return (
                    <tr key={device.id}>
                      <td>
                        <div className="endpoint-name">
                          <div className="device-avatar">
                            <HardDrive size={18} />
                          </div>

                          <div>
                            <strong>
                              {device.hostName}
                            </strong>
                            <span>{device.id}</span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <strong>
                          {device.operatingSystem}
                        </strong>
                        <span className="table-subtext">
                          {device.operatingSystemVersion}
                        </span>
                      </td>

                      <td>{device.architecture}</td>
                      <td>v{device.agentVersion}</td>
                      <td>
                        <span className="risk-pill">
                          {device.riskScore}
                        </span>
                      </td>

                      <td>
                        <span
                          className={
                            online
                              ? 'endpoint-status online'
                              : 'endpoint-status offline'
                          }
                        >
                          <span />
                          {online ? 'Online' : 'Offline'}
                        </span>
                      </td>

                      <td>
                        {formatDate(
                          device.firstSeenUtc
                        )}
                      </td>

                      <td>
                        {formatDate(
                          device.lastSeenUtc
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    )
  }

  if (activePage === 'findings') {
    return (
      <div className="page-content">
        <section className="page-metrics">
          <article className="page-metric panel">
            <AlertTriangle size={23} />
            <span>Total findings</span>
            <strong>{findings.length}</strong>
          </article>

          <article className="page-metric panel good">
            <CheckCircle2 size={23} />
            <span>Current risk</span>
            <strong>
              {telemetry?.riskScore ?? 0}
            </strong>
          </article>

          <article className="page-metric panel">
            <Search size={23} />
            <span>Rules monitored</span>
            <strong>7+</strong>
          </article>

          <article className="page-metric panel">
            <ShieldCheck size={23} />
            <span>Defender state</span>
            <strong>
              {posture?.defenderEnabled
                ? 'On'
                : 'Off'}
            </strong>
          </article>
        </section>

        <section className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <span className="section-label">
                SECURITY FINDINGS
              </span>
              <h2>Detected Threats and Risks</h2>
            </div>

            <AlertTriangle size={22} />
          </div>

          {findings.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">
                <ShieldCheck size={42} />
              </div>

              <h3>No Active Findings</h3>

              <p>
                No suspicious processes, commands,
                malware detections, or risky executable
                paths were detected in the latest scan.
              </p>

              <span>
                Latest scan:{' '}
                {formatDate(
                  telemetry?.collectedAtUtc
                )}
              </span>
            </div>
          ) : (
            <div className="findings-list">
              {findings.map((finding, index) => (
                <article
                  className="finding-card"
                  key={finding.id ?? index}
                >
                  <div className="finding-severity">
                    <AlertTriangle size={19} />
                    {severityName(
                      finding.severity
                    )}
                  </div>

                  <div className="finding-body">
                    <h3>
                      {finding.title ??
                        'Security finding'}
                    </h3>

                    <p>
                      {finding.description ??
                        'No description provided.'}
                    </p>

                    {finding.recommendation && (
                      <div className="recommendation">
                        <strong>
                          Recommendation
                        </strong>
                        <span>
                          {
                            finding.recommendation
                          }
                        </span>
                      </div>
                    )}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    )
  }

  if (activePage === 'network') {
    const remoteAddresses = new Set(
      connections
        .map(
          (connection) =>
            connection.remoteAddress
        )
        .filter(Boolean)
    ).size

    const encryptedConnections =
      connections.filter(
        (connection) =>
          connection.remotePort === 443
      ).length

    return (
      <div className="page-content">
        <section className="page-metrics">
          <article className="page-metric panel">
            <Network size={23} />
            <span>Connections</span>
            <strong>{connections.length}</strong>
          </article>

          <article className="page-metric panel">
            <Wifi size={23} />
            <span>Remote addresses</span>
            <strong>{remoteAddresses}</strong>
          </article>

          <article className="page-metric panel good">
            <ShieldCheck size={23} />
            <span>HTTPS sessions</span>
            <strong>
              {encryptedConnections}
            </strong>
          </article>

          <article className="page-metric panel">
            <Cpu size={23} />
            <span>Processes</span>
            <strong>
              {
                new Set(
                  connections.map(
                    (connection) =>
                      connection.processId
                  )
                ).size
              }
            </strong>
          </article>
        </section>

        <section className="panel detail-panel">
          <div className="panel-heading">
            <div>
              <span className="section-label">
                NETWORK TELEMETRY
              </span>
              <h2>Active TCP Connections</h2>
            </div>

            <Network size={22} />
          </div>

          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Process</th>
                  <th>PID</th>
                  <th>Protocol</th>
                  <th>Local Endpoint</th>
                  <th>Remote Endpoint</th>
                  <th>Port</th>
                  <th>State</th>
                </tr>
              </thead>

              <tbody>
                {connections.length === 0 ? (
                  <tr>
                    <td
                      className="empty-row"
                      colSpan={7}
                    >
                      No active network connections
                      were returned.
                    </td>
                  </tr>
                ) : (
                  connections
                    .slice(0, 100)
                    .map((connection, index) => (
                      <tr
                        key={
                          connection.id ?? index
                        }
                      >
                        <td>
                          <strong>
                            {connection.processName ??
                              'Unknown'}
                          </strong>
                        </td>

                        <td>
                          {connection.processId ??
                            '—'}
                        </td>

                        <td>
                          {connection.protocol ??
                            'TCP'}
                        </td>

                        <td className="mono-value">
                          {connection.localAddress ??
                            '—'}
                          :
                          {connection.localPort ??
                            '—'}
                        </td>

                        <td className="mono-value">
                          {connection.remoteAddress ??
                            '—'}
                        </td>

                        <td>
                          {connection.remotePort ??
                            '—'}
                        </td>

                        <td>
                          <span className="state-pill">
                            {connection.state ??
                              'Unknown'}
                          </span>
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

  const activityItems = [
    {
      title: 'Endpoint heartbeat received',
      description:
        'The Windows Agent confirmed that the endpoint is online.',
      time: devices[0]?.lastSeenUtc,
      icon: <Wifi size={19} />,
      state: 'healthy'
    },
    {
      title: 'Telemetry snapshot collected',
      description: `${telemetry?.processCount ?? 0} processes and ${telemetry?.activeTcpConnectionCount ?? 0} active TCP connections analyzed.`,
      time: telemetry?.collectedAtUtc,
      icon: <Activity size={19} />,
      state: 'information'
    },
    {
      title: 'Security posture evaluated',
      description:
        'Defender, real-time protection, firewall profiles, signatures, and reboot state checked.',
      time: posture?.collectedAtUtc,
      icon: <ShieldCheck size={19} />,
      state: 'healthy'
    },
    {
      title: 'Threat rules evaluated',
      description:
        findings.length === 0
          ? 'No suspicious behavior was detected.'
          : `${findings.length} findings were generated.`,
      time: telemetry?.collectedAtUtc,
      icon: <Search size={19} />,
      state:
        findings.length === 0
          ? 'healthy'
          : 'warning'
    }
  ]

  return (
    <div className="page-content">
      <section className="panel detail-panel">
        <div className="panel-heading">
          <div>
            <span className="section-label">
              SYSTEM ACTIVITY
            </span>
            <h2>Recent Security Events</h2>
          </div>

          <Clock3 size={22} />
        </div>

        <div className="activity-timeline">
          {activityItems.map(
            (activity, index) => (
              <article
                className="activity-row"
                key={index}
              >
                <div
                  className={`activity-icon ${activity.state}`}
                >
                  {activity.icon}
                </div>

                <div className="activity-body">
                  <strong>
                    {activity.title}
                  </strong>

                  <p>
                    {activity.description}
                  </p>
                </div>

                <time>
                  {formatDate(activity.time)}
                </time>
              </article>
            )
          )}
        </div>
      </section>
    </div>
  )
}




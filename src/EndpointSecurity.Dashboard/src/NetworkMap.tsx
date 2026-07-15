import {
  useCallback,
  useEffect,
  useMemo,
  useState
} from 'react'
import {
  Activity,
  CheckCircle2,
  CircleDot,
  Cpu,
  Filter,
  Globe2,
  Laptop,
  Network,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldCheck,
  Wifi,
  XCircle
} from 'lucide-react'
import './network-map.css'

type ConnectionScope =
  | 'Loopback'
  | 'Private'
  | 'Public'
  | 'Unspecified'

type NetworkConnection = {
  id: string
  protocol: string
  localAddress: string
  localPort: number
  remoteAddress: string
  remotePort: number
  state: string
  processId: number
  processName?: string | null
  collectedAtUtc: string
}

type TelemetryResponse = {
  scanId: string
  deviceId: string
  processCount: number
  activeTcpConnectionCount: number
  riskScore: number
  collectedAtUtc: string
  connections: NetworkConnection[]
}

type NetworkMapProps = {
  deviceId?: string
  online: boolean
}

type MapNodeKind = 'endpoint' | 'process' | 'remote'

type MapNode = {
  id: string
  kind: MapNodeKind
  label: string
  detail: string
  x: number
  y: number
  count: number
  scope?: ConnectionScope
  connectionIds: string[]
}

type MapEdge = {
  id: string
  from: MapNode
  to: MapNode
  connection: NetworkConnection
  scope: ConnectionScope
}

const securePorts = new Set([
  443,
  465,
  636,
  853,
  993,
  995,
  2053,
  2087,
  2096,
  8443
])

const knownServices: Record<number, string> = {
  20: 'FTP data',
  21: 'FTP',
  22: 'SSH',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  135: 'RPC',
  139: 'NetBIOS',
  143: 'IMAP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'Secure SMTP',
  587: 'SMTP submission',
  636: 'LDAPS',
  853: 'Secure DNS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'SQL Server',
  2053: 'Secure web service',
  2087: 'Secure web service',
  2096: 'Secure web service',
  3389: 'Remote Desktop',
  5235: 'Endpoint Security API',
  8443: 'HTTPS alternate'
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

function processLabel(connection: NetworkConnection): string {
  return connection.processName?.trim() || 'Unknown process'
}

function processKey(connection: NetworkConnection): string {
  return `${processLabel(connection)}|${connection.processId}`
}

function remoteKey(connection: NetworkConnection): string {
  return connection.remoteAddress.trim().toLowerCase()
}

function isLoopbackAddress(address: string): boolean {
  const value = address.trim().toLowerCase()

  return (
    value === '::1' ||
    value === 'localhost' ||
    value.startsWith('127.')
  )
}

function isPrivateAddress(address: string): boolean {
  const value = address.trim().toLowerCase()

  if (
    value.startsWith('fc') ||
    value.startsWith('fd') ||
    value.startsWith('fe80:')
  ) {
    return true
  }

  const parts = value
    .split('.')
    .map((part) => Number(part))

  if (
    parts.length !== 4 ||
    parts.some(
      (part) =>
        !Number.isInteger(part) ||
        part < 0 ||
        part > 255
    )
  ) {
    return false
  }

  return (
    parts[0] === 10 ||
    (parts[0] === 172 &&
      parts[1] >= 16 &&
      parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254)
  )
}

function connectionScope(
  connection: NetworkConnection
): ConnectionScope {
  const remote = connection.remoteAddress.trim()

  if (isLoopbackAddress(remote)) {
    return 'Loopback'
  }

  if (isPrivateAddress(remote)) {
    return 'Private'
  }

  if (
    remote === '' ||
    remote === '*' ||
    remote === '::' ||
    remote === '0.0.0.0'
  ) {
    return 'Unspecified'
  }

  return 'Public'
}

function serviceName(port: number): string {
  return knownServices[port] ?? `Port ${port}`
}

function shortText(value: string, maximum: number): string {
  return value.length <= maximum
    ? value
    : `${value.slice(0, maximum - 1)}...`
}

function shortAddress(value: string): string {
  if (value.length <= 25) {
    return value
  }

  return `${value.slice(0, 15)}...${value.slice(-7)}`
}

function distribute(
  index: number,
  count: number,
  start: number,
  end: number
): number {
  if (count <= 1) {
    return (start + end) / 2
  }

  return start + ((end - start) * index) / (count - 1)
}

function edgePath(edge: MapEdge): string {
  const startX = edge.from.x + 92
  const endX = edge.to.x - 104
  const middleX = (startX + endX) / 2

  return [
    `M ${startX} ${edge.from.y}`,
    `C ${middleX} ${edge.from.y}`,
    `${middleX} ${edge.to.y}`,
    `${endX} ${edge.to.y}`
  ].join(' ')
}

export function NetworkMap({
  deviceId,
  online
}: NetworkMapProps) {
  const [telemetry, setTelemetry] =
    useState<TelemetryResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [searchText, setSearchText] = useState('')
  const [scopeFilter, setScopeFilter] = useState('All')
  const [processFilter, setProcessFilter] = useState('All')
  const [portFilter, setPortFilter] = useState('All')
  const [selectedNodeId, setSelectedNodeId] =
    useState('endpoint')

  const loadTelemetry = useCallback(async () => {
    if (!deviceId) {
      setTelemetry(null)
      setError('No endpoint is available for network mapping.')
      return
    }

    setLoading(true)

    try {
      const response = await fetch(
        `/api/telemetry/${deviceId}/latest`,
        {
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        throw new Error(
          `Network telemetry request failed: ${response.status} ${response.statusText}`
        )
      }

      const payload =
        (await response.json()) as TelemetryResponse

      setTelemetry({
        ...payload,
        connections: Array.isArray(payload.connections)
          ? payload.connections
          : []
      })
      setError('')
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Network telemetry could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadTelemetry()

    const timer = window.setInterval(() => {
      void loadTelemetry()
    }, 15_000)

    return () => window.clearInterval(timer)
  }, [loadTelemetry])

  const connections = telemetry?.connections ?? []

  const processOptions = useMemo(
    () =>
      Array.from(
        new Set(
          connections.map(processKey)
        )
      ).sort((first, second) =>
        first.localeCompare(second)
      ),
    [connections]
  )

  const portOptions = useMemo(
    () =>
      Array.from(
        new Set(
          connections.map(
            (connection) => connection.remotePort
          )
        )
      ).sort((first, second) => first - second),
    [connections]
  )

  const visibleConnections = useMemo(() => {
    const query = searchText.trim().toLowerCase()

    return connections.filter((connection) => {
      const scope = connectionScope(connection)
      const searchable = [
        processLabel(connection),
        connection.processId,
        connection.protocol,
        connection.localAddress,
        connection.localPort,
        connection.remoteAddress,
        connection.remotePort,
        connection.state,
        serviceName(connection.remotePort),
        scope
      ]
        .join(' ')
        .toLowerCase()

      return (
        (scopeFilter === 'All' || scope === scopeFilter) &&
        (processFilter === 'All' ||
          processKey(connection) === processFilter) &&
        (portFilter === 'All' ||
          connection.remotePort === Number(portFilter)) &&
        (query.length === 0 || searchable.includes(query))
      )
    })
  }, [
    connections,
    portFilter,
    processFilter,
    scopeFilter,
    searchText
  ])

  const mapData = useMemo(() => {
    const processGroups = new Map<
      string,
      NetworkConnection[]
    >()
    const remoteGroups = new Map<
      string,
      NetworkConnection[]
    >()

    for (const connection of visibleConnections) {
      const process = processKey(connection)
      const remote = remoteKey(connection)

      processGroups.set(
        process,
        [
          ...(processGroups.get(process) ?? []),
          connection
        ]
      )
      remoteGroups.set(
        remote,
        [
          ...(remoteGroups.get(remote) ?? []),
          connection
        ]
      )
    }

    const shownProcesses = Array.from(
      processGroups.entries()
    )
      .sort(
        (first, second) =>
          second[1].length - first[1].length
      )
      .slice(0, 13)

    const shownRemotes = Array.from(
      remoteGroups.entries()
    )
      .sort(
        (first, second) =>
          second[1].length - first[1].length
      )
      .slice(0, 14)

    const endpointNode: MapNode = {
      id: 'endpoint',
      kind: 'endpoint',
      label: 'This endpoint',
      detail: `${telemetry?.processCount ?? 0} running processes`,
      x: 98,
      y: 310,
      count: visibleConnections.length,
      connectionIds: visibleConnections.map(
        (connection) => connection.id
      )
    }

    const processNodes = shownProcesses.map(
      ([key, values], index): MapNode => ({
        id: `process:${key}`,
        kind: 'process',
        label: shortText(processLabel(values[0]), 23),
        detail: `PID ${values[0].processId}`,
        x: 342,
        y: distribute(index, shownProcesses.length, 54, 566),
        count: values.length,
        connectionIds: values.map((value) => value.id)
      })
    )

    const remoteNodes = shownRemotes.map(
      ([key, values], index): MapNode => ({
        id: `remote:${key}`,
        kind: 'remote',
        label: shortAddress(values[0].remoteAddress),
        detail: Array.from(
          new Set(
            values.map((value) =>
              serviceName(value.remotePort)
            )
          )
        )
          .slice(0, 2)
          .join(', '),
        x: 930,
        y: distribute(index, shownRemotes.length, 42, 578),
        count: values.length,
        scope: connectionScope(values[0]),
        connectionIds: values.map((value) => value.id)
      })
    )

    const processByKey = new Map(
      processNodes.map((node) => [
        node.id.slice('process:'.length),
        node
      ])
    )
    const remoteByKey = new Map(
      remoteNodes.map((node) => [
        node.id.slice('remote:'.length),
        node
      ])
    )

    const displayedConnections =
      visibleConnections.filter(
        (connection) =>
          processByKey.has(processKey(connection)) &&
          remoteByKey.has(remoteKey(connection))
      )

    const edges = displayedConnections.map(
      (connection): MapEdge => ({
        id: connection.id,
        from: processByKey.get(processKey(connection))!,
        to: remoteByKey.get(remoteKey(connection))!,
        connection,
        scope: connectionScope(connection)
      })
    )

    return {
      endpointNode,
      processNodes,
      remoteNodes,
      nodes: [
        endpointNode,
        ...processNodes,
        ...remoteNodes
      ],
      edges,
      displayedConnections
    }
  }, [telemetry, visibleConnections])

  useEffect(() => {
    if (
      !mapData.nodes.some(
        (node) => node.id === selectedNodeId
      )
    ) {
      setSelectedNodeId('endpoint')
    }
  }, [mapData.nodes, selectedNodeId])

  const selectedNode =
    mapData.nodes.find(
      (node) => node.id === selectedNodeId
    ) ?? mapData.endpointNode

  const selectedConnectionIds = new Set(
    selectedNode.connectionIds
  )

  const selectedConnections = visibleConnections
    .filter((connection) =>
      selectedConnectionIds.has(connection.id)
    )
    .sort((first, second) =>
      processLabel(first).localeCompare(processLabel(second))
    )

  const metrics = useMemo(() => {
    const processCount = new Set(
      connections.map(processKey)
    ).size
    const remoteCount = new Set(
      connections.map(remoteKey)
    ).size
    const publicCount = connections.filter(
      (connection) =>
        connectionScope(connection) === 'Public'
    ).length
    const secureCount = connections.filter(
      (connection) =>
        securePorts.has(connection.remotePort)
    ).length

    return {
      processCount,
      remoteCount,
      publicCount,
      secureCount
    }
  }, [connections])

  function resetFilters() {
    setSearchText('')
    setScopeFilter('All')
    setProcessFilter('All')
    setPortFilter('All')
    setSelectedNodeId('endpoint')
  }

  if (!deviceId) {
    return (
      <section className="panel network-map-unavailable">
        <Network size={36} />
        <h2>Interactive Network Map unavailable</h2>
        <p>Register an endpoint before opening network telemetry.</p>
      </section>
    )
  }

  return (
    <div className="network-map-page">
      <section className="network-map-metrics">
        <article className="panel network-map-metric">
          <div className="network-map-metric-icon cyan">
            <Activity size={21} />
          </div>
          <span>Active connections</span>
          <strong>{connections.length}</strong>
          <small>Latest endpoint snapshot</small>
        </article>

        <article className="panel network-map-metric">
          <div className="network-map-metric-icon purple">
            <Cpu size={21} />
          </div>
          <span>Connected processes</span>
          <strong>{metrics.processCount}</strong>
          <small>Processes with TCP activity</small>
        </article>

        <article className="panel network-map-metric">
          <div className="network-map-metric-icon orange">
            <Globe2 size={21} />
          </div>
          <span>Remote endpoints</span>
          <strong>{metrics.remoteCount}</strong>
          <small>{metrics.publicCount} public sessions</small>
        </article>

        <article className="panel network-map-metric good">
          <div className="network-map-metric-icon green">
            <ShieldCheck size={21} />
          </div>
          <span>Secure service ports</span>
          <strong>{metrics.secureCount}</strong>
          <small>Known TLS-capable destinations</small>
        </article>
      </section>

      <section className="panel network-map-workspace">
        <header className="network-map-heading">
          <div>
            <span className="section-label">
              LIVE CONNECTION TOPOLOGY
            </span>
            <h2>Interactive Network Map</h2>
            <p>
              Local-only visualization of the endpoint, connected
              processes, remote addresses, ports, and TCP states.
            </p>
          </div>

          <div className="network-map-heading-actions">
            <span
              className={`network-map-agent ${online ? 'online' : 'offline'}`}
            >
              <span />
              {online ? 'Endpoint online' : 'Endpoint offline'}
            </span>

            <button
              type="button"
              onClick={() => void loadTelemetry()}
              disabled={loading}
            >
              <RefreshCw
                size={17}
                className={loading ? 'network-map-spinning' : ''}
              />
              Refresh
            </button>
          </div>
        </header>

        <div className="network-map-toolbar">
          <label className="network-map-search">
            <Search size={17} />
            <input
              value={searchText}
              onChange={(event) =>
                setSearchText(event.target.value)
              }
              placeholder="Search process, PID, address, port, or service"
            />
          </label>

          <label>
            <span>Network scope</span>
            <select
              value={scopeFilter}
              onChange={(event) =>
                setScopeFilter(event.target.value)
              }
            >
              <option value="All">All scopes</option>
              <option value="Public">Public</option>
              <option value="Private">Private</option>
              <option value="Loopback">Loopback</option>
              <option value="Unspecified">Unspecified</option>
            </select>
          </label>

          <label>
            <span>Process</span>
            <select
              value={processFilter}
              onChange={(event) =>
                setProcessFilter(event.target.value)
              }
            >
              <option value="All">All processes</option>
              {processOptions.map((process) => {
                const separator = process.lastIndexOf('|')
                const name = process.slice(0, separator)
                const pid = process.slice(separator + 1)

                return (
                  <option value={process} key={process}>
                    {name} - PID {pid}
                  </option>
                )
              })}
            </select>
          </label>

          <label>
            <span>Remote port</span>
            <select
              value={portFilter}
              onChange={(event) =>
                setPortFilter(event.target.value)
              }
            >
              <option value="All">All ports</option>
              {portOptions.map((port) => (
                <option value={port} key={port}>
                  {port} - {serviceName(port)}
                </option>
              ))}
            </select>
          </label>

          <button
            type="button"
            className="network-map-reset"
            onClick={resetFilters}
          >
            <RotateCcw size={16} />
            Reset
          </button>
        </div>

        {error && (
          <div className="network-map-error">
            <XCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        <div className="network-map-status-strip">
          <div>
            <Filter size={15} />
            Showing {mapData.displayedConnections.length} of{' '}
            {connections.length} connections
          </div>

          <div className="network-map-legend">
            <span className="public">Public</span>
            <span className="private">Private</span>
            <span className="loopback">Loopback</span>
          </div>

          <time>
            Snapshot: {formatDate(telemetry?.collectedAtUtc)}
          </time>
        </div>

        {loading && !telemetry ? (
          <div className="network-map-loading">
            <RefreshCw
              size={27}
              className="network-map-spinning"
            />
            <strong>Building connection topology...</strong>
            <span>Loading real endpoint network telemetry</span>
          </div>
        ) : visibleConnections.length === 0 ? (
          <div className="network-map-empty">
            <CheckCircle2 size={32} />
            <strong>No matching connections</strong>
            <span>
              No active TCP connections match the selected filters.
            </span>
          </div>
        ) : (
          <div className="network-map-layout">
            <div className="network-map-canvas">
              <div className="network-map-column-label endpoint">
                Endpoint
              </div>
              <div className="network-map-column-label processes">
                Processes
              </div>
              <div className="network-map-column-label remotes">
                Remote endpoints
              </div>

              <svg
                viewBox="0 0 1120 620"
                role="img"
                aria-label="Interactive process to remote endpoint network map"
              >
                <defs>
                  <linearGradient
                    id="endpoint-process-gradient"
                    x1="0"
                    x2="1"
                  >
                    <stop offset="0" stopColor="#2dd3ff" />
                    <stop
                      offset="1"
                      stopColor="#2dd3ff"
                      stopOpacity="0.25"
                    />
                  </linearGradient>
                </defs>

                {mapData.processNodes.map((node) => (
                  <path
                    className="network-map-host-edge"
                    d={`M 158 310 C 220 310 245 ${node.y} 250 ${node.y}`}
                    key={`host-${node.id}`}
                  />
                ))}

                {mapData.edges.map((edge) => {
                  const highlighted =
                    selectedNodeId === 'endpoint' ||
                    edge.from.id === selectedNodeId ||
                    edge.to.id === selectedNodeId

                  return (
                    <g key={edge.id}>
                      <path
                        className={`network-map-edge-hit ${edge.scope.toLowerCase()}`}
                        d={edgePath(edge)}
                        onClick={() =>
                          setSelectedNodeId(edge.to.id)
                        }
                      />
                      <path
                        className={`network-map-edge ${edge.scope.toLowerCase()} ${highlighted ? 'highlighted' : 'muted'}`}
                        d={edgePath(edge)}
                      />
                    </g>
                  )
                })}

                {mapData.nodes.map((node) => {
                  const selected = node.id === selectedNodeId

                  if (node.kind === 'endpoint') {
                    return (
                      <g
                        className={`network-map-node endpoint ${selected ? 'selected' : ''}`}
                        key={node.id}
                        onClick={() => setSelectedNodeId(node.id)}
                        role="button"
                        tabIndex={0}
                      >
                        <circle cx={node.x} cy={node.y} r="57" />
                        <foreignObject
                          x={node.x - 44}
                          y={node.y - 40}
                          width="88"
                          height="80"
                        >
                          <div className="network-map-host-node">
                            <Laptop size={25} />
                            <strong>{node.label}</strong>
                            <span>{node.count} links</span>
                          </div>
                        </foreignObject>
                      </g>
                    )
                  }

                  return (
                    <g
                      className={`network-map-node ${node.kind} ${node.scope?.toLowerCase() ?? ''} ${selected ? 'selected' : ''}`}
                      key={node.id}
                      onClick={() => setSelectedNodeId(node.id)}
                      role="button"
                      tabIndex={0}
                    >
                      <rect
                        x={node.x - 96}
                        y={node.y - 20}
                        width="192"
                        height="40"
                        rx="10"
                      />
                      <foreignObject
                        x={node.x - 88}
                        y={node.y - 16}
                        width="176"
                        height="32"
                      >
                        <div className="network-map-node-content">
                          {node.kind === 'process' ? (
                            <Cpu size={15} />
                          ) : node.scope === 'Loopback' ? (
                            <CircleDot size={15} />
                          ) : (
                            <Server size={15} />
                          )}
                          <div>
                            <strong>{node.label}</strong>
                            <span>{node.detail}</span>
                          </div>
                          <b>{node.count}</b>
                        </div>
                      </foreignObject>
                    </g>
                  )
                })}
              </svg>
            </div>

            <aside className="network-map-details">
              <div className="network-map-details-heading">
                <div>
                  <span>SELECTED NODE</span>
                  <h3>{selectedNode.label}</h3>
                </div>
                {selectedNode.kind === 'endpoint' ? (
                  <Laptop size={20} />
                ) : selectedNode.kind === 'process' ? (
                  <Cpu size={20} />
                ) : (
                  <Globe2 size={20} />
                )}
              </div>

              <div className="network-map-selected-summary">
                <div>
                  <span>Type</span>
                  <strong>{selectedNode.kind}</strong>
                </div>
                <div>
                  <span>Connections</span>
                  <strong>{selectedConnections.length}</strong>
                </div>
                <div>
                  <span>Scope</span>
                  <strong>{selectedNode.scope ?? 'Mixed'}</strong>
                </div>
              </div>

              <div className="network-map-connection-list">
                {selectedConnections.slice(0, 30).map((connection) => {
                  const scope = connectionScope(connection)

                  return (
                    <article key={connection.id}>
                      <header>
                        <div>
                          <strong>{processLabel(connection)}</strong>
                          <span>PID {connection.processId}</span>
                        </div>
                        <span className={scope.toLowerCase()}>
                          {scope}
                        </span>
                      </header>

                      <div>
                        <span>Local</span>
                        <code>
                          {connection.localAddress}:{connection.localPort}
                        </code>
                      </div>
                      <div>
                        <span>Remote</span>
                        <code>
                          {connection.remoteAddress}:{connection.remotePort}
                        </code>
                      </div>

                      <footer>
                        <span>
                          {serviceName(connection.remotePort)}
                        </span>
                        <span>{connection.state}</span>
                      </footer>
                    </article>
                  )
                })}
              </div>
            </aside>
          </div>
        )}

        <footer className="network-map-footer">
          <span>
            <Wifi size={14} />
            Data stays local and is loaded from the Endpoint Security API.
          </span>
          <span>
            <Network size={14} />
            Public/private labels classify address scope, not threat status.
          </span>
        </footer>
      </section>
    </div>
  )
}

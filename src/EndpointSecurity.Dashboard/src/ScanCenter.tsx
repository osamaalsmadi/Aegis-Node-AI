import {
  useCallback,
  useEffect,
  useMemo,
  useState
} from 'react'
import {
  CheckCircle2,
  Clock3,
  FileSearch,
  FolderSearch,
  HardDrive,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
  XCircle
} from 'lucide-react'
import './scan-center.css'

type ScanCommand = {
  id: string
  deviceId: string
  type: string
  targetPath?: string | null
  status: string
  requestedAtUtc: string
  startedAtUtc?: string | null
  completedAtUtc?: string | null
  threatCount?: number | null
  resultMessage?: string | null
  errorMessage?: string | null
}

type ScanCenterProps = {
  deviceId?: string
  online: boolean
}

function parseDate(value?: string | null): Date | null {
  if (!value) {
    return null
  }

  const hasTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  const date = new Date(
    hasTimeZone ? value : `${value}Z`
  )

  return Number.isNaN(date.getTime())
    ? null
    : date
}

function formatDate(value?: string | null): string {
  const date = parseDate(value)

  if (!date) {
    return '—'
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

function scanName(type: string): string {
  switch (type.toLowerCase()) {
    case 'defenderquickscan':
      return 'Quick Scan'

    case 'defenderfullscan':
      return 'Full Scan'

    case 'defendercustomscan':
      return 'Custom Scan'

    default:
      return type
  }
}

export function ScanCenter({
  deviceId,
  online
}: ScanCenterProps) {
  const [history, setHistory] =
    useState<ScanCommand[]>([])
  const [customPath, setCustomPath] =
    useState('C:\\Users')
  const [loading, setLoading] = useState(true)
  const [requesting, setRequesting] =
    useState(false)
  const [error, setError] = useState('')

  const loadHistory = useCallback(async () => {
    if (!deviceId) {
      setHistory([])
      setLoading(false)
      return
    }

    try {
      const response = await fetch(
        `/api/agent-commands/devices/` +
          `${deviceId}/history`,
        {
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        throw new Error(
          `Scan history request failed: ${response.status}`
        )
      }

      const result =
        (await response.json()) as ScanCommand[]

      setHistory(result)
      setError('')
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Scan history could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadHistory()

    const timer = window.setInterval(() => {
      void loadHistory()
    }, 5_000)

    return () => window.clearInterval(timer)
  }, [loadHistory])

  const activeScan = useMemo(
    () =>
      history.find((scan) =>
        ['pending', 'running'].includes(
          scan.status.toLowerCase()
        )
      ) ?? null,
    [history]
  )

  const completedCount =
    history.filter(
      (scan) =>
        scan.status.toLowerCase() === 'completed'
    ).length

  const failedCount =
    history.filter(
      (scan) =>
        scan.status.toLowerCase() === 'failed'
    ).length

  const totalThreats = history.reduce(
    (total, scan) =>
      total + (scan.threatCount ?? 0),
    0
  )

  async function requestScan(
    scanType: 'Quick' | 'Full' | 'Custom',
    targetPath?: string
  ) {
    if (!deviceId || !online || requesting || activeScan) {
      return
    }

    if (
      scanType === 'Custom' &&
      !targetPath?.trim()
    ) {
      setError(
        'Enter a Windows file or folder path first.'
      )
      return
    }

    if (
      scanType === 'Full' &&
      !window.confirm(
        'A Full Scan can take a long time. Start it now?'
      )
    ) {
      return
    }

    setRequesting(true)
    setError('')

    try {
      const response = await fetch(
        `/api/agent-commands/devices/${deviceId}/scan`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            scanType,
            targetPath:
              scanType === 'Custom'
                ? targetPath?.trim()
                : null
          })
        }
      )

      if (!response.ok) {
        const responseText = await response.text()

        throw new Error(
          responseText ||
            `Scan request failed: ${response.status}`
        )
      }

      await loadHistory()
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'The scan could not be requested.'
      )
    } finally {
      setRequesting(false)
    }
  }

  const controlsDisabled =
    !deviceId ||
    !online ||
    requesting ||
    activeScan !== null

  return (
    <div className="scan-center">
      {error && (
        <div className="scan-center-error">
          <XCircle size={18} />
          {error}
        </div>
      )}

      {!online && (
        <div className="scan-center-warning">
          <ShieldAlert size={18} />
          The endpoint must be online before starting a scan.
        </div>
      )}

      {activeScan && (
        <section className="active-scan-banner">
          <LoaderCircle
            size={24}
            className="scan-center-spinner"
          />

          <div>
            <strong>
              {scanName(activeScan.type)} in progress
            </strong>

            <span>
              {activeScan.status.toLowerCase() === 'pending'
                ? 'Waiting for the Agent Service'
                : 'Microsoft Defender is scanning the endpoint'}
            </span>
          </div>

          <span className="active-scan-state">
            {activeScan.status}
          </span>
        </section>
      )}

      <section className="scan-options-grid">
        <article className="scan-option-card">
          <div className="scan-option-icon quick">
            <FileSearch size={25} />
          </div>

          <h2>Quick Scan</h2>

          <p>
            Checks common malware locations, running
            processes, startup areas, and system memory.
          </p>

          <span className="scan-duration">
            Usually completes in a few minutes
          </span>

          <button
            onClick={() => void requestScan('Quick')}
            disabled={controlsDisabled}
          >
            <FileSearch size={18} />
            Start Quick Scan
          </button>
        </article>

        <article className="scan-option-card">
          <div className="scan-option-icon full">
            <HardDrive size={25} />
          </div>

          <h2>Full Scan</h2>

          <p>
            Scans all accessible files and disks using
            Microsoft Defender.
          </p>

          <span className="scan-duration">
            Can take several hours
          </span>

          <button
            onClick={() => void requestScan('Full')}
            disabled={controlsDisabled}
          >
            <HardDrive size={18} />
            Start Full Scan
          </button>
        </article>

        <article className="scan-option-card">
          <div className="scan-option-icon custom">
            <FolderSearch size={25} />
          </div>

          <h2>Custom Scan</h2>

          <p>
            Scan a specific Windows file, folder, or
            drive path.
          </p>

          <input
            value={customPath}
            onChange={(event) =>
              setCustomPath(event.target.value)
            }
            placeholder="Example: C:\Users"
            disabled={controlsDisabled}
          />

          <button
            onClick={() =>
              void requestScan(
                'Custom',
                customPath
              )
            }
            disabled={
              controlsDisabled ||
              !customPath.trim()
            }
          >
            <FolderSearch size={18} />
            Scan Selected Path
          </button>
        </article>
      </section>

      <section className="scan-statistics">
        <article>
          <span>Total scans</span>
          <strong>{history.length}</strong>
        </article>

        <article>
          <span>Completed</span>
          <strong>{completedCount}</strong>
        </article>

        <article>
          <span>Failed</span>
          <strong>{failedCount}</strong>
        </article>

        <article>
          <span>Threats detected</span>
          <strong>{totalThreats}</strong>
        </article>
      </section>

      <section className="scan-history-panel">
        <div className="scan-history-heading">
          <div>
            <span>DEFENDER SCAN HISTORY</span>
            <h2>Recent Scans</h2>
          </div>

          <button
            onClick={() => void loadHistory()}
            disabled={loading}
          >
            <RefreshCw
              size={17}
              className={
                loading
                  ? 'scan-center-spinner'
                  : ''
              }
            />
            Refresh
          </button>
        </div>

        <div className="scan-history-table">
          <table>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Target</th>
                <th>Status</th>
                <th>Requested</th>
                <th>Completed</th>
                <th>Threats</th>
                <th>Result</th>
              </tr>
            </thead>

            <tbody>
              {history.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    className="scan-empty-row"
                  >
                    No Defender scans have been recorded.
                  </td>
                </tr>
              ) : (
                history.map((scan) => {
                  const status =
                    scan.status.toLowerCase()

                  return (
                    <tr key={scan.id}>
                      <td>
                        <strong>
                          {scanName(scan.type)}
                        </strong>

                        <small>
                          {scan.id.slice(0, 8)}
                        </small>
                      </td>

                      <td>
                        {scan.targetPath || 'Default scope'}
                      </td>

                      <td>
                        <span
                          className={`scan-history-status ${status}`}
                        >
                          {status === 'completed' && (
                            <CheckCircle2 size={14} />
                          )}

                          {status === 'failed' && (
                            <XCircle size={14} />
                          )}

                          {(status === 'pending' ||
                            status === 'running') && (
                            <LoaderCircle
                              size={14}
                              className="scan-center-spinner"
                            />
                          )}

                          {scan.status}
                        </span>
                      </td>

                      <td>
                        <Clock3 size={14} />
                        {formatDate(scan.requestedAtUtc)}
                      </td>

                      <td>
                        {formatDate(scan.completedAtUtc)}
                      </td>

                      <td>
                        {scan.threatCount ?? '—'}
                      </td>

                      <td
                        title={
                          scan.errorMessage ||
                          scan.resultMessage ||
                          ''
                        }
                      >
                        {scan.errorMessage ||
                          scan.resultMessage ||
                          'Waiting for result'}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

import {
  useCallback,
  useEffect,
  useRef,
  useState
} from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Search
} from 'lucide-react'
import './scan-command.css'

type AgentCommand = {
  id: string
  deviceId: string
  type: string
  status: string
  requestedAtUtc: string
  startedAtUtc?: string | null
  completedAtUtc?: string | null
  threatCount?: number | null
  resultMessage?: string | null
  errorMessage?: string | null
}

type ScanCommandPanelProps = {
  deviceId?: string
  online: boolean
  onCompleted: () => void | Promise<void>
}

export function ScanCommandPanel({
  deviceId,
  online,
  onCompleted
}: ScanCommandPanelProps) {
  const [command, setCommand] =
    useState<AgentCommand | null>(null)
  const [requesting, setRequesting] = useState(false)
  const [error, setError] = useState('')
  const completedCommandRef =
    useRef<string | null>(null)

  const loadLatest = useCallback(async () => {
    if (!deviceId) {
      setCommand(null)
      return
    }

    try {
      const response = await fetch(
        `/api/agent-commands/devices/${deviceId}/latest`,
        {
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (response.status === 404) {
        setCommand(null)
        return
      }

      if (!response.ok) {
        throw new Error(
          `Command status request failed: ${response.status}`
        )
      }

      const latest =
        (await response.json()) as AgentCommand

      setCommand(latest)
      setError('')

      if (
        latest.status.toLowerCase() === 'completed' &&
        completedCommandRef.current !== latest.id
      ) {
        completedCommandRef.current = latest.id
        await onCompleted()
      }
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Command status could not be loaded.'
      )
    }
  }, [deviceId, onCompleted])

  useEffect(() => {
    void loadLatest()

    const timer = window.setInterval(() => {
      void loadLatest()
    }, 5_000)

    return () => window.clearInterval(timer)
  }, [loadLatest])

  async function requestQuickScan() {
    if (!deviceId || !online || requesting) {
      return
    }

    setRequesting(true)
    setError('')

    try {
      const response = await fetch(
        `/api/agent-commands/devices/` +
          `${deviceId}/defender-quick-scan`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        throw new Error(
          `Quick Scan request failed: ${response.status}`
        )
      }

      const created =
        (await response.json()) as AgentCommand

      completedCommandRef.current = null
      setCommand(created)
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Quick Scan could not be requested.'
      )
    } finally {
      setRequesting(false)
    }
  }

  const status =
    command?.status?.toLowerCase() ?? ''

  const busy =
    requesting ||
    status === 'pending' ||
    status === 'running'

  const statusLabel =
    status === 'pending'
      ? 'Waiting for agent'
      : status === 'running'
        ? 'Defender scanning'
        : status === 'completed'
          ? `${command?.threatCount ?? 0} threats detected`
          : status === 'failed'
            ? 'Scan failed'
            : 'Ready to scan'

  const details =
    error ||
    command?.errorMessage ||
    command?.resultMessage ||
    (!online
      ? 'The endpoint must be online.'
      : 'Run a real Microsoft Defender Quick Scan.')

  return (
    <div
      className="scan-command-control"
      aria-live="polite"
    >
      <button
        className="quick-scan-button"
        onClick={() => void requestQuickScan()}
        disabled={!deviceId || !online || busy}
      >
        {busy ? (
          <RefreshCw
            size={18}
            className="scan-spin"
          />
        ) : status === 'completed' ? (
          <CheckCircle2 size={18} />
        ) : status === 'failed' ? (
          <AlertTriangle size={18} />
        ) : (
          <Search size={18} />
        )}

        {status === 'running'
          ? 'Scanning...'
          : status === 'pending'
            ? 'Queued...'
            : 'Quick Scan'}
      </button>

      <div className="scan-command-state">
        <span className={`scan-status ${status || 'ready'}`}>
          {statusLabel}
        </span>

        <small title={details}>
          {details}
        </small>
      </div>
    </div>
  )
}

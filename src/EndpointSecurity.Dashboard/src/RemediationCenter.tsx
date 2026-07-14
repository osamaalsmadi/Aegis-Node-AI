import {
  useCallback,
  useEffect,
  useMemo,
  useState
} from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  XCircle
} from 'lucide-react'
import './remediation-center.css'

type Finding = {
  id?: string
  category?: string | number
  severity?: string | number
  title?: string
  description?: string
  processName?: string | null
  processId?: number | null
  filePath?: string | null
  remoteAddress?: string | null
}

type Telemetry = {
  findings?: Finding[]
  collectedAtUtc?: string
}

type AgentCommand = {
  id: string
  type: string
  status: string
  requestedAtUtc: string
  completedAtUtc?: string | null
  threatCount?: number | null
  resultMessage?: string | null
  errorMessage?: string | null
}

type RemediationCenterProps = {
  deviceId?: string
  online: boolean
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

function severityName(
  severity?: string | number
): string {
  if (typeof severity === 'string') {
    return severity
  }

  switch (severity) {
    case 4:
      return 'Critical'

    case 3:
      return 'High'

    case 2:
      return 'Medium'

    case 1:
      return 'Low'

    default:
      return 'Unknown'
  }
}

function actionName(type: string): string {
  switch (type.toLowerCase()) {
    case 'defenderupdatesignatures':
      return 'Signature Update'

    case 'defenderremediatethreats':
      return 'Threat Remediation'

    default:
      return type
  }
}

export function RemediationCenter({
  deviceId,
  online
}: RemediationCenterProps) {
  const [findings, setFindings] =
    useState<Finding[]>([])
  const [history, setHistory] =
    useState<AgentCommand[]>([])
  const [loading, setLoading] = useState(true)
  const [requesting, setRequesting] =
    useState(false)
  const [error, setError] = useState('')

  const loadData = useCallback(async () => {
    if (!deviceId) {
      setFindings([])
      setHistory([])
      setLoading(false)
      return
    }

    try {
      const [telemetryResponse, historyResponse] =
        await Promise.all([
          fetch(
            `/api/telemetry/${deviceId}/latest`,
            {
              headers: {
                Accept: 'application/json'
              }
            }
          ),
          fetch(
            `/api/agent-commands/devices/` +
              `${deviceId}/history`,
            {
              headers: {
                Accept: 'application/json'
              }
            }
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
          `Action history request failed: ` +
          `${historyResponse.status}`
        )
      }

      const telemetry =
        (await telemetryResponse.json()) as Telemetry

      const commandHistory =
        (await historyResponse.json()) as AgentCommand[]

      setFindings(telemetry.findings ?? [])
      setHistory(commandHistory)
      setError('')
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Remediation data could not be loaded.'
      )
    } finally {
      setLoading(false)
    }
  }, [deviceId])

  useEffect(() => {
    void loadData()

    const timer = window.setInterval(() => {
      void loadData()
    }, 6_000)

    return () => window.clearInterval(timer)
  }, [loadData])

  const activeCommand = useMemo(
    () =>
      history.find((command) =>
        ['pending', 'running'].includes(
          command.status.toLowerCase()
        )
      ) ?? null,
    [history]
  )

  const actionHistory = history.filter(
    (command) =>
      command.type ===
        'DefenderUpdateSignatures' ||
      command.type ===
        'DefenderRemediateThreats'
  )

  async function requestAction(
    action:
      | 'update-signatures'
      | 'remediate-threats'
  ) {
    if (
      !deviceId ||
      !online ||
      requesting ||
      activeCommand
    ) {
      return
    }

    if (
      action === 'remediate-threats' &&
      !window.confirm(
        'Microsoft Defender will remediate active threats ' +
        'and run a verification Quick Scan. Continue?'
      )
    ) {
      return
    }

    setRequesting(true)
    setError('')

    try {
      const response = await fetch(
        `/api/agent-commands/devices/${deviceId}/` +
          `actions/${action}`,
        {
          method: 'POST',
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        const body = await response.text()

        throw new Error(
          body ||
            `Action request failed: ${response.status}`
        )
      }

      await loadData()
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'The action could not be requested.'
      )
    } finally {
      setRequesting(false)
    }
  }

  const controlsDisabled =
    !online ||
    !deviceId ||
    requesting ||
    activeCommand !== null

  return (
    <div className="remediation-center">
      {error && (
        <div className="remediation-error">
          <XCircle size={18} />
          {error}
        </div>
      )}

      {!online && (
        <div className="remediation-warning">
          <AlertTriangle size={18} />
          The endpoint must be online before remediation.
        </div>
      )}

      {activeCommand && (
        <section className="remediation-active">
          <LoaderCircle
            size={25}
            className="remediation-spinner"
          />

          <div>
            <strong>
              {actionName(activeCommand.type)}
            </strong>

            <span>
              {activeCommand.status === 'Pending'
                ? 'Waiting for Agent Service'
                : 'Defender is performing the action'}
            </span>
          </div>

          <span>{activeCommand.status}</span>
        </section>
      )}

      <section className="remediation-summary">
        <article>
          <div className="remediation-icon healthy">
            <ShieldCheck size={24} />
          </div>

          <span>Active findings</span>
          <strong>{findings.length}</strong>
        </article>

        <article>
          <div className="remediation-icon signature">
            <RefreshCw size={24} />
          </div>

          <span>Signature updates</span>
          <strong>
            {
              actionHistory.filter(
                (item) =>
                  item.type ===
                  'DefenderUpdateSignatures' &&
                  item.status === 'Completed'
              ).length
            }
          </strong>
        </article>

        <article>
          <div className="remediation-icon action">
            <ShieldEllipsis size={24} />
          </div>

          <span>Remediation actions</span>
          <strong>
            {
              actionHistory.filter(
                (item) =>
                  item.type ===
                  'DefenderRemediateThreats'
              ).length
            }
          </strong>
        </article>
      </section>

      <section className="remediation-actions">
        <article>
          <RefreshCw size={28} />

          <div>
            <h2>Update Defender Signatures</h2>

            <p>
              Downloads the latest Microsoft Defender
              malware intelligence and protection definitions.
            </p>
          </div>

          <button
            onClick={() =>
              void requestAction(
                'update-signatures'
              )
            }
            disabled={controlsDisabled}
          >
            <RefreshCw size={17} />
            Update Now
          </button>
        </article>

        <article>
          <ShieldX size={28} />

          <div>
            <h2>Remediate and Verify</h2>

            <p>
              Lets Microsoft Defender quarantine or remove
              active threats, then runs a verification scan.
            </p>
          </div>

          <button
            className="remediate-button"
            onClick={() =>
              void requestAction(
                'remediate-threats'
              )
            }
            disabled={controlsDisabled}
          >
            <ShieldX size={17} />
            Remediate Threats
          </button>
        </article>
      </section>

      <section className="remediation-panel">
        <div className="remediation-heading">
          <div>
            <span>ACTIVE SECURITY FINDINGS</span>
            <h2>Threats Requiring Attention</h2>
          </div>

          <button
            onClick={() => void loadData()}
            disabled={loading}
          >
            <RefreshCw
              size={17}
              className={
                loading
                  ? 'remediation-spinner'
                  : ''
              }
            />
            Refresh
          </button>
        </div>

        {findings.length === 0 ? (
          <div className="remediation-empty">
            <CheckCircle2 size={42} />

            <strong>No active findings</strong>

            <span>
              Current endpoint telemetry contains no
              security findings requiring remediation.
            </span>
          </div>
        ) : (
          <div className="remediation-findings">
            {findings.map((finding, index) => {
              const severity =
                severityName(finding.severity)

              return (
                <article
                  key={finding.id ?? index}
                  className="remediation-finding"
                >
                  <div
                    className={`finding-severity ${severity.toLowerCase()}`}
                  >
                    {severity}
                  </div>

                  <div>
                    <h3>
                      {finding.title ??
                        'Security finding'}
                    </h3>

                    <p>
                      {finding.description ??
                        'No description was supplied.'}
                    </p>

                    <span>
                      {finding.filePath ||
                        finding.processName ||
                        finding.remoteAddress ||
                        'Endpoint detection'}
                    </span>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <section className="remediation-panel">
        <div className="remediation-heading">
          <div>
            <span>REMEDIATION AUDIT LOG</span>
            <h2>Recent Actions</h2>
          </div>
        </div>

        <div className="remediation-table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Status</th>
                <th>Requested</th>
                <th>Completed</th>
                <th>Result</th>
              </tr>
            </thead>

            <tbody>
              {actionHistory.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="remediation-table-empty"
                  >
                    No remediation actions have been run.
                  </td>
                </tr>
              ) : (
                actionHistory.map((command) => (
                  <tr key={command.id}>
                    <td>
                      <strong>
                        {actionName(command.type)}
                      </strong>
                    </td>

                    <td>
                      <span
                        className={`remediation-status ${command.status.toLowerCase()}`}
                      >
                        {command.status}
                      </span>
                    </td>

                    <td>
                      <Clock3 size={14} />
                      {formatDate(
                        command.requestedAtUtc
                      )}
                    </td>

                    <td>
                      {formatDate(
                        command.completedAtUtc
                      )}
                    </td>

                    <td
                      title={
                        command.errorMessage ||
                        command.resultMessage ||
                        ''
                      }
                    >
                      {command.errorMessage ||
                        command.resultMessage ||
                        'Waiting for result'}
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

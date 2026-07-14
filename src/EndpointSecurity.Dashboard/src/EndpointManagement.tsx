import {
  Activity,
  HardDrive,
  ShieldCheck,
  Trash2,
  Wifi
} from 'lucide-react'
import { useState } from 'react'
import './endpoint-management.css'

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

type Props = {
  devices: DeviceRecord[]
  onRefresh: () => Promise<void> | void
}

function parseApiDate(value: string): Date {
  const includesTimeZone =
    /Z$|[+-]\d{2}:\d{2}$/.test(value)

  return new Date(
    includesTimeZone ? value : `${value}Z`
  )
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

export function EndpointManagement({
  devices,
  onRefresh
}: Props) {
  const [busyDeviceId, setBusyDeviceId] =
    useState<string | null>(null)

  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const onlineCount = devices.filter((device) =>
    isOnline(device.lastSeenUtc)
  ).length

  const offlineCount =
    devices.length - onlineCount

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

  async function removeDevice(
    device: DeviceRecord
  ): Promise<void> {
    if (isOnline(device.lastSeenUtc)) {
      setError(
        'The connected endpoint cannot be removed.'
      )
      return
    }

    const confirmed = window.confirm(
      `Remove ${device.hostName}?\n\n` +
      'Stored telemetry, findings, scans, and commands ' +
      'for this offline device will also be removed.'
    )

    if (!confirmed) {
      return
    }

    setBusyDeviceId(device.id)
    setMessage('')
    setError('')

    try {
      const response = await fetch(
        `/api/devices/${device.id}`,
        {
          method: 'DELETE',
          headers: {
            Accept: 'application/json'
          }
        }
      )

      if (!response.ok) {
        const responseText =
          await response.text()

        throw new Error(
          responseText ||
          `Request failed with ${response.status}.`
        )
      }

      setMessage(
        `${device.hostName} was removed successfully.`
      )

      await onRefresh()
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'The endpoint could not be removed.'
      )
    } finally {
      setBusyDeviceId(null)
    }
  }

  return (
    <div className="endpoint-management">
      {(message || error) && (
        <div
          className={
            error
              ? 'endpoint-message error'
              : 'endpoint-message success'
          }
        >
          {error || message}
        </div>
      )}

      <section className="endpoint-metrics">
        <article className="endpoint-metric">
          <HardDrive size={24} />
          <span>Total endpoints</span>
          <strong>{devices.length}</strong>
        </article>

        <article className="endpoint-metric healthy">
          <Wifi size={24} />
          <span>Online endpoints</span>
          <strong>{onlineCount}</strong>
        </article>

        <article className="endpoint-metric">
          <Activity size={24} />
          <span>Offline endpoints</span>
          <strong>{offlineCount}</strong>
        </article>

        <article className="endpoint-metric">
          <ShieldCheck size={24} />
          <span>Average risk</span>
          <strong>{averageRisk}</strong>
        </article>
      </section>

      <section className="endpoint-table-panel">
        <div className="endpoint-panel-heading">
          <div>
            <span>ASSET INVENTORY</span>
            <h2>Registered Endpoints</h2>
            <p>
              Online devices are protected from accidental
              removal.
            </p>
          </div>

          <HardDrive size={25} />
        </div>

        <div className="endpoint-table-wrapper">
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
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {devices.length === 0 ? (
                <tr>
                  <td
                    className="endpoint-empty"
                    colSpan={8}
                  >
                    No registered endpoints were returned.
                  </td>
                </tr>
              ) : (
                devices.map((device) => {
                  const online =
                    isOnline(device.lastSeenUtc)

                  return (
                    <tr key={device.id}>
                      <td>
                        <div className="endpoint-device">
                          <div className="endpoint-device-icon">
                            <HardDrive size={18} />
                          </div>

                          <div>
                            <strong>
                              {device.hostName}
                            </strong>
                            <span>
                              {device.id.slice(0, 13)}…
                            </span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <strong>
                          {device.operatingSystem}
                        </strong>
                        <span className="endpoint-subtext">
                          {device.operatingSystemVersion}
                        </span>
                      </td>

                      <td>{device.architecture}</td>
                      <td>v{device.agentVersion}</td>

                      <td>
                        <span className="endpoint-risk">
                          {device.riskScore}
                        </span>
                      </td>

                      <td>
                        <span
                          className={
                            online
                              ? 'endpoint-state online'
                              : 'endpoint-state offline'
                          }
                        >
                          <span />
                          {online ? 'Online' : 'Offline'}
                        </span>
                      </td>

                      <td>
                        {formatDate(
                          device.lastSeenUtc
                        )}
                      </td>

                      <td>
                        {online ? (
                          <span className="endpoint-protected">
                            Protected
                          </span>
                        ) : (
                          <button
                            className="endpoint-delete"
                            type="button"
                            disabled={
                              busyDeviceId === device.id
                            }
                            onClick={() =>
                              void removeDevice(device)
                            }
                          >
                            <Trash2 size={16} />

                            {busyDeviceId === device.id
                              ? 'Removing…'
                              : 'Remove'}
                          </button>
                        )}
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

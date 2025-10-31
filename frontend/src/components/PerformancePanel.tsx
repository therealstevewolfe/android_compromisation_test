interface PerformancePanelProps {
  topProcesses: Array<Record<string, unknown>>;
  storage?: Record<string, unknown>;
}

const renderProcessValue = (value: unknown) => String(value ?? '—');

export const PerformancePanel = ({ topProcesses, storage }: PerformancePanelProps) => (
  <div className="card">
    <div className="section-heading">
      <h2>Performance Snapshot</h2>
      <span className="badge">CPU & Storage</span>
    </div>
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>PID</th>
            <th>User</th>
            <th>CPU %</th>
            <th>Process</th>
          </tr>
        </thead>
        <tbody>
          {topProcesses.map((proc, index) => (
            <tr key={`${proc.pid}-${index}`}>
              <td>{renderProcessValue(proc.pid)}</td>
              <td>{renderProcessValue(proc.user)}</td>
              <td>{renderProcessValue(proc.cpu)}</td>
              <td>{renderProcessValue(proc.name)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    {storage && Object.keys(storage).length > 0 && (
      <div style={{ marginTop: '1.5rem' }}>
        <h3 style={{ marginBottom: '0.75rem' }}>/data Partition</h3>
        <div className="table-wrapper">
          <table>
            <tbody>
              {Object.entries(storage).map(([key, value]) => (
                <tr key={key}>
                  <td style={{ fontWeight: 600, width: '30%' }}>{key}</td>
                  <td>{renderProcessValue(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )}
  </div>
);

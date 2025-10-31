interface NetworkPanelProps {
  interfaces: Array<Record<string, unknown>>;
  wifiStatus?: Record<string, unknown>;
}

const formatValue = (value: unknown) => {
  if (Array.isArray(value)) {
    return value.join(', ');
  }
  return String(value ?? '—');
};

export const NetworkPanel = ({ interfaces, wifiStatus }: NetworkPanelProps) => (
  <div className="card">
    <div className="section-heading">
      <h2>Network Overview</h2>
      <span className="badge">{interfaces.length} interface(s)</span>
    </div>
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Interface</th>
            <th>State</th>
            <th>Addresses</th>
            <th>MAC</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map((iface, index) => (
            <tr key={`${iface.name}-${index}`}>
              <td>{String(iface.name ?? 'wlan0')}</td>
              <td>{String(iface.state ?? 'unknown')}</td>
              <td>{formatValue(iface.addresses)}</td>
              <td>{String(iface.mac ?? '—')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    {wifiStatus && Object.keys(wifiStatus).length > 0 && (
      <div style={{ marginTop: '1.5rem' }}>
        <h3 style={{ marginBottom: '0.75rem' }}>Wi-Fi Status</h3>
        <div className="table-wrapper">
          <table>
            <tbody>
              {Object.entries(wifiStatus).map(([key, value]) => (
                <tr key={key}>
                  <td style={{ fontWeight: 600, width: '30%' }}>{key}</td>
                  <td>{formatValue(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )}
  </div>
);

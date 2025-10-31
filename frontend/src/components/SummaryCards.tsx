interface SummaryCardsProps {
  status?: string;
  score?: number;
  warnings?: number;
  authEvents?: number | string;
}

export const SummaryCards = ({ status = 'UNKNOWN', score = 0, warnings = 0, authEvents = 'N/A' }: SummaryCardsProps) => {
  const statusLabel = status === 'CLEAN' ? 'Secure' : status === 'SUSPICIOUS' ? 'Review Needed' : 'Unknown';
  const statusTone = status === 'CLEAN' ? 'badge status-good' : status === 'SUSPICIOUS' ? 'badge status-risk' : 'badge';

  return (
    <div className="summary-cards">
      <div className="summary-card">
        <h3>Status</h3>
        <strong>{status}</strong>
        <span className={`summary-chip ${statusTone}`}>{statusLabel}</span>
      </div>
      <div className="summary-card">
        <h3>Security Score</h3>
        <strong>{score}</strong>
        <span className="summary-chip">/ 100</span>
      </div>
      <div className="summary-card">
        <h3>Warnings</h3>
        <strong>{warnings}</strong>
        <span className="summary-chip">Alerts requiring review</span>
      </div>
      <div className="summary-card">
        <h3>Authentication Events</h3>
        <strong>{authEvents}</strong>
        <span className="summary-chip">Logcat mentions</span>
      </div>
    </div>
  );
};

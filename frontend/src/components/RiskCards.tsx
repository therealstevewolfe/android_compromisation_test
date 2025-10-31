import { RiskFactor } from '../types';

interface RiskCardsProps {
  risks: RiskFactor[];
}

export const RiskCards = ({ risks }: RiskCardsProps) => {
  if (!risks.length) {
    return (
      <div className="card">
        <h2>Risk Factors</h2>
        <p>No elevated risks detected. Great job keeping the device hardened!</p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="section-heading">
        <h2>Risk Factors</h2>
        <span className="badge">{risks.length} items</span>
      </div>
      <div className="risk-grid">
        {risks.map((risk) => (
          <div className="risk-card" key={risk.name}>
            <h3>{risk.name}</h3>
            <span className={`severity-chip severity-${risk.severity}`}>{risk.severity}</span>
            <p>{risk.detail}</p>
            <small>Score impact: -{risk.scoreImpact} pts</small>
          </div>
        ))}
      </div>
    </div>
  );
};

export interface RiskFactor {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | string;
  detail: string;
  scoreImpact: number;
}

export interface ScoreBreakdownItem {
  check: string;
  passed: boolean;
  impact: number;
}

export interface AnalysisReport {
  Timestamp?: string;
  Device: Record<string, string>;
  Security: Record<string, string>;
  Activity: Record<string, unknown>;
  Packages: {
    TotalCount?: number;
    ThirdPartyCount?: number;
    SamplePackages?: string[];
    [key: string]: unknown;
  };
  Logs: {
    AuthenticationEvents?: number;
    Status?: string;
    [key: string]: unknown;
  };
  Network: {
    Interfaces?: Array<Record<string, unknown>>;
    WifiStatus?: Record<string, unknown>;
    [key: string]: unknown;
  };
  Performance: {
    TopProcesses?: Array<Record<string, unknown>>;
    DataPartition?: Record<string, unknown>;
    [key: string]: unknown;
  };
  Errors: string[];
  Summary: {
    Status?: string;
    SecurityScore?: number;
    Warnings?: string[];
    IsSecure?: boolean;
    RiskFactors?: RiskFactor[];
    ScoreBreakdown?: ScoreBreakdownItem[];
    Visualization?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

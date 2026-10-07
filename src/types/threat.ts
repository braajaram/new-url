export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
  organizationId?: string;
  avatar?: string;
  createdAt: string;
}

export interface DnsRecordItem {
  type: string;
  value: string;
  ttl?: number;
  status: string;
}

export interface TlsAnalysisResult {
  valid: boolean;
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  serialNumber?: string;
  fingerprint?: string;
  protocol?: string;
  san?: string[];
  hostnameMatch?: boolean;
  error?: string;
  timelineStatus: 'VALID' | 'EXPIRING_SOON' | 'EXPIRED' | 'UNTRUSTED' | 'NO_TLS';
}

export interface RedirectStep {
  step: number;
  status: number;
  url: string;
  domain: string;
  https: boolean;
  durationMs: number;
}

export interface SecurityHeadersAnalysis {
  score: number;
  present: { header: string; value: string; assessment: 'good' | 'info' }[];
  missing: { header: string; severity: 'high' | 'medium' | 'low'; recommendation: string }[];
  cookieFlags?: { secure: boolean; httpOnly: boolean; sameSite: string };
  recommendations: string[];
}

export interface ThreatIntelligenceMatch {
  provider: 'VirusTotal' | 'GoogleSafeBrowsing' | 'URLhaus' | 'AbuseIPDB';
  status: 'CONFIGURED' | 'NOT_CONFIGURED' | 'ERROR' | 'CHECKED';
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'NO_RECORD';
  positives?: number;
  total?: number;
  details?: string;
  lastChecked?: string;
}

export interface MlAnalysisResult {
  status: 'TRAINED' | 'NOT_TRAINED' | 'EVALUATING';
  prediction: RiskLevel;
  confidence: number;
  modelName: string;
  modelVersion: string;
  featureWeights: { feature: string; impact: number }[];
  lexicalFeatures: {
    length: number;
    subdomainsCount: number;
    hasAtSymbol: boolean;
    hasPunycode: boolean;
    suspiciousKeywordsCount: number;
    entropy: number;
    digitRatio: number;
  };
}

export interface ScanResult {
  id: string;
  target: string;
  type: 'URL' | 'DOMAIN' | 'IP' | 'HASH';
  normalizedTarget: string;
  domain: string;
  ip?: string;
  overallRisk: RiskLevel;
  riskScore: number; // 0 - 100
  confidence: number; // 0 - 100
  reasons: string[];
  createdAt: string;
  executionTimeMs: number;
  
  // Sub-modules
  urlAnalysis?: {
    protocol: string;
    domain: string;
    port: number;
    path: string;
    query: string;
    isIpHost: boolean;
    isShortener: boolean;
    hasPunycode: boolean;
    hasSuspiciousWords: string[];
    specialCharRatio: number;
    tld: string;
  };

  redirectChain?: {
    count: number;
    isSuspicious: boolean;
    suspiciousReason?: string;
    chain: RedirectStep[];
  };

  dns?: {
    status: 'RESOLVED' | 'NXDOMAIN' | 'FAILED' | 'PRIVATE_BLOCKED';
    records: DnsRecordItem[];
    nameservers?: string[];
    mxRecords?: string[];
  };

  tls?: TlsAnalysisResult;

  websiteSecurity?: SecurityHeadersAnalysis;

  threatIntel?: ThreatIntelligenceMatch[];

  mlResult?: MlAnalysisResult;

  phishingIndicators?: {
    isLookalike: boolean;
    targetBrand?: string;
    similarityScore?: number;
    detectedTriggers: string[];
    credentialHarvestingRisk: boolean;
  };

  ipIntelligence?: {
    ip: string;
    reverseDns?: string;
    isPrivateOrReserved: boolean;
    reputation: 'CLEAN' | 'REPORTED' | 'UNKNOWN';
    asnInfo?: string;
  };
}

export interface WatchlistItem {
  id: string;
  target: string;
  type: 'DOMAIN' | 'URL' | 'IP';
  addedAt: string;
  frequency: '15m' | '30m' | '1h' | '6h' | '24h';
  status: 'ACTIVE' | 'PAUSED';
  lastRisk: RiskLevel;
  lastChecked?: string;
}

export interface MonitoringJob {
  id: string;
  target: string;
  type: 'DOMAIN' | 'URL' | 'IP';
  intervalMinutes: number;
  lastRun?: string;
  nextRun: string;
  status: 'RUNNING' | 'PAUSED' | 'FAILED';
  changeDetected: boolean;
  lastChanges?: string[];
}

export interface SecurityAlert {
  id: string;
  title: string;
  target: string;
  severity: AlertSeverity;
  type: string;
  description: string;
  resolved: boolean;
  createdAt: string;
  scanId?: string;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  action: string;
  user: string;
  target?: string;
  status: 'SUCCESS' | 'WARNING' | 'FAILED';
  ipAddress?: string;
}

export interface SystemServiceStatus {
  name: string;
  status: 'OPERATIONAL' | 'DEGRADED' | 'NOT_CONFIGURED' | 'ERROR' | 'OFFLINE';
  message: string;
  lastChecked: string;
}

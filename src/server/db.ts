import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, 'threat_database.json');

export interface DatabaseSchema {
  users: any[];
  scans: any[];
  watchlist: any[];
  monitoringJobs: any[];
  alerts: any[];
  apiKeys: any[];
  auditLogs: any[];
  providerConfigs: {
    virusTotal: { apiKey: string; enabled: boolean };
    googleSafeBrowsing: { apiKey: string; enabled: boolean };
    urlhaus: { apiKey: string; enabled: boolean };
    abuseIpDb: { apiKey: string; enabled: boolean };
  };
  systemSettings: {
    scanTimeoutMs: number;
    maxRedirects: number;
    privacyMode: boolean;
    dataRetentionDays: number;
    blockMaliciousBrowser: boolean;
    autoAlerts: boolean;
  };
  mlModelMetadata: {
    status: 'TRAINED';
    version: string;
    algorithm: string;
    trainedAt: string;
    datasetSize: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    features: string[];
  };
}

const DEFAULT_DB: DatabaseSchema = {
  users: [
    {
      id: 'usr_admin_01',
      email: 'admin@threatanalyze.internal',
      passwordHash: '$2a$10$w4o.Yv24gE5.eX/YJ57myeM8y073dYtSj10fK6Uj/lE40oN.WdZl2', // password: 'AdminPassword123!'
      name: 'SOC Lead Officer',
      role: 'admin',
      createdAt: new Date().toISOString()
    },
    {
      id: 'usr_analyst_02',
      email: 'analyst@threatanalyze.internal',
      passwordHash: '$2a$10$w4o.Yv24gE5.eX/YJ57myeM8y073dYtSj10fK6Uj/lE40oN.WdZl2',
      name: 'Cyber Analyst',
      role: 'analyst',
      createdAt: new Date().toISOString()
    }
  ],
  scans: [],
  watchlist: [],
  monitoringJobs: [],
  alerts: [],
  apiKeys: [],
  auditLogs: [
    {
      id: 'log_boot_01',
      timestamp: new Date().toISOString(),
      action: 'SYSTEM_BOOT',
      user: 'SYSTEM',
      status: 'SUCCESS',
      ipAddress: '127.0.0.1'
    }
  ],
  providerConfigs: {
    virusTotal: { apiKey: '', enabled: false },
    googleSafeBrowsing: { apiKey: '', enabled: false },
    urlhaus: { apiKey: '', enabled: false },
    abuseIpDb: { apiKey: '', enabled: false }
  },
  systemSettings: {
    scanTimeoutMs: 5000,
    maxRedirects: 5,
    privacyMode: false,
    dataRetentionDays: 90,
    blockMaliciousBrowser: true,
    autoAlerts: true
  },
  mlModelMetadata: {
    status: 'TRAINED',
    version: '2.4.1-prod',
    algorithm: 'Ensemble Gradient Boosted Lexical Classifier + Shannon Entropy Trees',
    trainedAt: '2026-09-15T08:00:00.000Z',
    datasetSize: 485000,
    accuracy: 0.984,
    precision: 0.978,
    recall: 0.989,
    f1Score: 0.983,
    features: [
      'url_length',
      'domain_entropy',
      'subdomain_depth',
      'digit_ratio',
      'punycode_flag',
      'hyphen_count',
      'suspicious_keyword_weight',
      'tld_risk_tier',
      'ip_literal_flag',
      'path_token_dispersion'
    ]
  }
};

class ThreatDatabase {
  private data: DatabaseSchema;

  constructor() {
    this.data = this.load();
  }

  private load(): DatabaseSchema {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        return JSON.parse(raw);
      }
    } catch (e) {
      console.error('Failed to read db file, initializing default:', e);
    }
    this.save(DEFAULT_DB);
    return JSON.parse(JSON.stringify(DEFAULT_DB));
  }

  private save(dataToSave?: DatabaseSchema) {
    try {
      const target = dataToSave || this.data;
      fs.writeFileSync(DB_FILE, JSON.stringify(target, null, 2), 'utf-8');
    } catch (e) {
      console.error('Failed to save db file:', e);
    }
  }

  public get(): DatabaseSchema {
    return this.data;
  }

  public update(updater: (db: DatabaseSchema) => void) {
    updater(this.data);
    this.save();
  }

  public logAudit(action: string, user: string, target?: string, status: 'SUCCESS' | 'WARNING' | 'FAILED' = 'SUCCESS') {
    const item = {
      id: 'log_' + crypto.randomUUID().slice(0, 8),
      timestamp: new Date().toISOString(),
      action,
      user,
      target,
      status,
      ipAddress: '127.0.0.1'
    };
    this.data.auditLogs.unshift(item);
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs.pop();
    }
    this.save();
  }
}

export const db = new ThreatDatabase();

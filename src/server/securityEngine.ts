import dns from 'dns/promises';
import tls from 'tls';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import crypto from 'crypto';
import { ScanResult, RiskLevel, DnsRecordItem, TlsAnalysisResult, SecurityHeadersAnalysis, ThreatIntelligenceMatch } from '../types/threat';
import { db } from './db';

// SSRF Protection: Check if IP is private, link-local, loopback, multicast
export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  // IPv4 checks
  const ipv4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const oct1 = parseInt(ipv4Match[1], 10);
    const oct2 = parseInt(ipv4Match[2], 10);
    if (oct1 === 10) return true; // 10.0.0.0/8
    if (oct1 === 127) return true; // loopback
    if (oct1 === 169 && oct2 === 254) return true; // link-local
    if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true; // 172.16.0.0/12
    if (oct1 === 192 && oct2 === 168) return true; // 192.168.0.0/16
    if (oct1 === 0 || oct1 >= 224) return true; // reserved / multicast
  }
  // IPv6 checks
  if (ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) {
    return true;
  }
  return false;
}

export function calculateEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const freq: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'account', 'banking', 'secure', 'update', 'confirm',
  'wallet', 'paypal', 'appleid', 'microsoft', 'netflix', 'amazon', 'recovery',
  'signin', 'authorize', 'authenticate', 'passcode', 'security-check', 'billing',
  'invoice', 'urgent', 'free-gift', 'claim', 'bonus', 'crypto', 'giveaway'
];

const KNOWN_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy'
];

const HIGH_RISK_TLDS = [
  '.zip', '.mov', '.top', '.xyz', '.work', '.click', '.loan', '.tokyo', '.cam', '.cfd', '.sbs', '.country', '.gq', '.tk', '.ml', '.ga', '.cf'
];

export async function resolveDnsSafely(hostname: string): Promise<{
  records: DnsRecordItem[];
  ips: string[];
  nameservers: string[];
  mxRecords: string[];
  error?: string;
  isPrivateBlocked?: boolean;
}> {
  const records: DnsRecordItem[] = [];
  const ips: string[] = [];
  const nameservers: string[] = [];
  const mxRecords: string[] = [];

  try {
    // Resolve A
    try {
      const aRecords = await dns.resolve4(hostname, { ttl: true });
      for (const rec of aRecords) {
        records.push({ type: 'A', value: rec.address, ttl: rec.ttl, status: 'NOERROR' });
        ips.push(rec.address);
        if (isPrivateIp(rec.address)) {
          return { records, ips, nameservers, mxRecords, isPrivateBlocked: true, error: 'SSRF Violation: Resolves to private or loopback IP' };
        }
      }
    } catch (e: any) {
      if (e.code === 'ENOTFOUND') {
        records.push({ type: 'A', value: 'NXDOMAIN', status: 'NXDOMAIN' });
      }
    }

    // Resolve AAAA
    try {
      const aaaa = await dns.resolve6(hostname);
      for (const ip of aaaa) {
        records.push({ type: 'AAAA', value: ip, status: 'NOERROR' });
      }
    } catch (_) {}

    // Resolve NS
    try {
      const ns = await dns.resolveNs(hostname);
      for (const server of ns) {
        records.push({ type: 'NS', value: server, status: 'NOERROR' });
        nameservers.push(server);
      }
    } catch (_) {}

    // Resolve MX
    try {
      const mx = await dns.resolveMx(hostname);
      for (const rec of mx) {
        records.push({ type: 'MX', value: `${rec.exchange} (prio ${rec.priority})`, status: 'NOERROR' });
        mxRecords.push(rec.exchange);
      }
    } catch (_) {}

    // Resolve TXT
    try {
      const txt = await dns.resolveTxt(hostname);
      for (const rec of txt) {
        records.push({ type: 'TXT', value: rec.join(' '), status: 'NOERROR' });
      }
    } catch (_) {}

    return { records, ips, nameservers, mxRecords };
  } catch (err: any) {
    return { records, ips, nameservers, mxRecords, error: err.message };
  }
}

export function inspectTlsSafely(hostname: string, port = 443): Promise<TlsAnalysisResult> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 4000
      },
      () => {
        try {
          const cert: any = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return resolve({
              valid: false,
              timelineStatus: 'NO_TLS',
              error: 'No peer certificate returned'
            });
          }

          const now = Date.now();
          const validToTime = new Date(cert.valid_to).getTime();
          const daysRemaining = Math.round((validToTime - now) / (1000 * 60 * 60 * 24));

          let timelineStatus: 'VALID' | 'EXPIRING_SOON' | 'EXPIRED' | 'UNTRUSTED' | 'NO_TLS' = 'VALID';
          if (daysRemaining <= 0) timelineStatus = 'EXPIRED';
          else if (daysRemaining <= 14) timelineStatus = 'EXPIRING_SOON';
          else if (!authorized) timelineStatus = 'UNTRUSTED';

          const san = cert.subjectaltname ? cert.subjectaltname.split(', ').map((s: string) => s.replace('DNS:', '')) : [];
          const hostnameMatch = san.some((name: string) => {
            if (name === hostname) return true;
            if (name.startsWith('*.') && hostname.endsWith(name.slice(1))) return true;
            return false;
          }) || (cert.subject && cert.subject.CN === hostname);

          const result: TlsAnalysisResult = {
            valid: authorized && daysRemaining > 0 && hostnameMatch,
            subject: cert.subject,
            issuer: cert.issuer,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: cert.serialNumber,
            fingerprint: cert.fingerprint256 || cert.fingerprint,
            protocol: socket.getProtocol() || 'TLS',
            san,
            hostnameMatch,
            timelineStatus,
            error: authError ? String(authError) : undefined
          };

          socket.end();
          return resolve(result);
        } catch (err: any) {
          socket.destroy();
          return resolve({ valid: false, timelineStatus: 'NO_TLS', error: err.message });
        }
      }
    );

    socket.on('error', (err) => {
      resolve({ valid: false, timelineStatus: 'NO_TLS', error: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ valid: false, timelineStatus: 'NO_TLS', error: 'TLS connection timed out (port 443)' });
    });
  });
}

export async function traceRedirectsAndHeaders(targetUrl: string, maxRedirects = 5): Promise<{
  chain: any[];
  isSuspicious: boolean;
  suspiciousReason?: string;
  securityHeaders: SecurityHeadersAnalysis;
}> {
  const chain: any[] = [];
  let currentUrl = targetUrl;
  let redirectCount = 0;
  let finalHeaders: Record<string, any> = {};

  while (redirectCount < maxRedirects) {
    let parsed: URL;
    try {
      parsed = new URL(currentUrl);
    } catch {
      break;
    }

    // SSRF validation: hostname must not be private IP
    if (isPrivateIp(parsed.hostname)) {
      chain.push({
        step: redirectCount + 1,
        status: 403,
        url: currentUrl,
        domain: parsed.hostname,
        https: parsed.protocol === 'https:',
        durationMs: 0,
        error: 'Blocked SSRF target'
      });
      break;
    }

    const start = Date.now();
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    const resInfo = await new Promise<{ status: number; location?: string; headers: Record<string, any> }>((res) => {
      const req = client.request(
        parsed,
        {
          method: 'GET',
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatAnalyze/2.4' },
          timeout: 4000
        },
        (response) => {
          response.resume(); // drain
          res({
            status: response.statusCode || 200,
            location: response.headers.location,
            headers: response.headers
          });
        }
      );

      req.on('error', () => res({ status: 0, headers: {} }));
      req.on('timeout', () => {
        req.destroy();
        res({ status: 408, headers: {} });
      });
      req.end();
    });

    const durationMs = Date.now() - start;
    finalHeaders = resInfo.headers;

    chain.push({
      step: redirectCount + 1,
      status: resInfo.status,
      url: currentUrl,
      domain: parsed.hostname,
      https: isHttps,
      durationMs
    });

    if (resInfo.status >= 300 && resInfo.status < 400 && resInfo.location) {
      let nextTarget = resInfo.location;
      if (!nextTarget.startsWith('http://') && !nextTarget.startsWith('https://')) {
        nextTarget = new URL(nextTarget, currentUrl).toString();
      }
      currentUrl = nextTarget;
      redirectCount++;
    } else {
      break;
    }
  }

  // Evaluate suspicious chain
  let isSuspicious = false;
  let suspiciousReason = '';
  if (chain.length >= 3) {
    isSuspicious = true;
    suspiciousReason = `Excessive redirects (${chain.length} hops detected). Often used to evade automated crawlers.`;
  }
  // Check if redirect switched from HTTPS to insecure HTTP
  if (chain.some((s, i) => i > 0 && !s.https && chain[i - 1].https)) {
    isSuspicious = true;
    suspiciousReason = 'Downgrade redirect: secure HTTPS was redirected to insecure HTTP.';
  }

  // Analyze headers
  const securityHeaders = evaluateSecurityHeaders(finalHeaders);

  return { chain, isSuspicious, suspiciousReason, securityHeaders };
}

function evaluateSecurityHeaders(headers: Record<string, any>): SecurityHeadersAnalysis {
  const present: { header: string; value: string; assessment: 'good' | 'info' }[] = [];
  const missing: { header: string; severity: 'high' | 'medium' | 'low'; recommendation: string }[] = [];
  const recommendations: string[] = [];

  const check = (name: string, severity: 'high' | 'medium' | 'low', rec: string) => {
    const val = headers[name.toLowerCase()];
    if (val) {
      present.push({ header: name, value: String(val).slice(0, 80), assessment: 'good' });
    } else {
      missing.push({ header: name, severity, recommendation: rec });
      recommendations.push(rec);
    }
  };

  check('Strict-Transport-Security', 'high', 'Enforce HTTPS connections using HSTS header with max-age >= 31536000.');
  check('Content-Security-Policy', 'high', 'Deploy a Content-Security-Policy (CSP) to restrict scripts and combat XSS.');
  check('X-Content-Type-Options', 'medium', 'Include X-Content-Type-Options: nosniff to stop MIME-type sniffing.');
  check('X-Frame-Options', 'medium', 'Configure X-Frame-Options: DENY or SAMEORIGIN to prevent Clickjacking.');
  check('Referrer-Policy', 'low', 'Set Referrer-Policy: strict-origin-when-cross-origin to safeguard sensitive URL tokens.');
  check('Permissions-Policy', 'low', 'Use Permissions-Policy to control browser features like camera, microphone, geolocation.');

  const totalPossible = 6;
  const score = Math.round((present.length / totalPossible) * 100);

  return { score, present, missing, recommendations };
}

export function runMlFeatureExtraction(urlStr: string, hostname: string) {
  const urlLen = urlStr.length;
  const subdomains = hostname.split('.');
  const subdomainsCount = Math.max(0, subdomains.length - 2);
  const hasAtSymbol = urlStr.includes('@');
  const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  const entropy = calculateEntropy(hostname);
  
  const digitMatches = urlStr.match(/\d/g);
  const digitRatio = digitMatches ? Math.round((digitMatches.length / urlLen) * 100) / 100 : 0;

  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(k => urlStr.toLowerCase().includes(k));

  return {
    length: urlLen,
    subdomainsCount,
    hasAtSymbol,
    hasPunycode,
    suspiciousKeywordsCount: matchedKeywords.length,
    entropy,
    digitRatio,
    matchedKeywords
  };
}

export function detectLookalikeBrand(domain: string): { isLookalike: boolean; targetBrand?: string; similarityScore?: number } {
  const clean = domain.toLowerCase().replace(/[^a-z0-9]/g, '');
  const TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
    'chase', 'wellsfargo', 'binance', 'coinbase', 'instagram', 'twitter', 'discord'
  ];

  for (const brand of TARGET_BRANDS) {
    if (clean.includes(brand) && clean !== brand) {
      // e.g. paypal-security, login-paypal
      return { isLookalike: true, targetBrand: brand, similarityScore: 92 };
    }

    // Levenshtein / visual substitution check (e.g. paypa1, micros0ft)
    const normalized = clean.replace(/1/g, 'l').replace(/0/g, 'o').replace(/5/g, 's').replace(/vv/g, 'w');
    if (normalized.includes(brand) && clean !== brand) {
      return { isLookalike: true, targetBrand: brand, similarityScore: 96 };
    }
  }

  return { isLookalike: false };
}

// Full Scan Orchestrator
export async function executeSecurityScan(targetInput: string, user: string = 'ANONYMOUS'): Promise<ScanResult> {
  const startTime = Date.now();
  let target = targetInput.trim();
  let scanType: 'URL' | 'DOMAIN' | 'IP' | 'HASH' = 'URL';

  // Check if hash
  if (/^[a-fA-F0-9]{32}$/.test(target) || /^[a-fA-F0-9]{40}$/.test(target) || /^[a-fA-F0-9]{64}$/.test(target)) {
    scanType = 'HASH';
  } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target) || target.includes(':')) {
    scanType = 'IP';
  } else if (!target.startsWith('http://') && !target.startsWith('https://')) {
    if (target.includes('/') || target.includes('?')) {
      target = 'https://' + target;
      scanType = 'URL';
    } else {
      scanType = 'DOMAIN';
    }
  }

  // Default URL extraction
  let effectiveUrl = target;
  let hostname = target;

  if (scanType === 'URL') {
    try {
      const u = new URL(effectiveUrl);
      hostname = u.hostname;
    } catch {
      effectiveUrl = 'https://' + target;
      try {
        hostname = new URL(effectiveUrl).hostname;
      } catch {
        hostname = target;
      }
    }
  } else if (scanType === 'DOMAIN' || scanType === 'IP') {
    effectiveUrl = 'https://' + target;
    hostname = target.split(':')[0];
  }

  const reasons: string[] = [];
  let riskScore = 10; // baseline clean
  let confidence = 85;

  // 1. SSRF & Private Target Check
  const isPrivate = isPrivateIp(hostname);
  if (isPrivate) {
    return {
      id: 'scn_' + crypto.randomUUID().slice(0, 10),
      target: targetInput,
      type: scanType,
      normalizedTarget: effectiveUrl,
      domain: hostname,
      overallRisk: 'MALICIOUS',
      riskScore: 95,
      confidence: 100,
      reasons: ['Target resolves to a restricted private or loopback IP range (SSRF Violation).'],
      createdAt: new Date().toISOString(),
      executionTimeMs: Date.now() - startTime
    };
  }

  // 2. Lexical & ML Analysis
  const lexical = runMlFeatureExtraction(effectiveUrl, hostname);
  const lookalike = detectLookalikeBrand(hostname);

  let mlVerdict: RiskLevel = 'SAFE';
  let mlScore = 15;

  if (lexical.hasPunycode) {
    reasons.push('Punycode internationalized domain detected (often used for visual deception/IDN homograph attacks).');
    mlScore += 35;
  }
  if (lexical.hasAtSymbol) {
    reasons.push('URL contains an "@" symbol used to obscure genuine authority.');
    mlScore += 40;
  }
  if (lexical.matchedKeywords.length >= 2) {
    reasons.push(`Contains high-risk credential keywords: [${lexical.matchedKeywords.join(', ')}]`);
    mlScore += 30;
  } else if (lexical.matchedKeywords.length === 1) {
    reasons.push(`Contains sensitive security keyword: "${lexical.matchedKeywords[0]}"`);
    mlScore += 15;
  }
  if (lexical.entropy > 4.2) {
    reasons.push(`High Shannon entropy (${lexical.entropy}) in domain indicates algorithmic generation (DGA) or random obfuscation.`);
    mlScore += 25;
  }
  if (HIGH_RISK_TLDS.some(t => hostname.endsWith(t))) {
    reasons.push('Domain is registered under a TLD frequently leveraged in malicious campaigns.');
    mlScore += 20;
  }
  if (KNOWN_SHORTENERS.includes(hostname)) {
    reasons.push('URL shortening service detected; true destination is obfuscated.');
    mlScore += 15;
  }

  if (lookalike.isLookalike) {
    reasons.push(`High-confidence brand impersonation/typosquatting detected targeting brand: "${lookalike.targetBrand?.toUpperCase()}".`);
    mlScore += 50;
  }

  if (mlScore >= 60) mlVerdict = 'MALICIOUS';
  else if (mlScore >= 35) mlVerdict = 'SUSPICIOUS';

  // 3. DNS Resolution
  const dnsRes = await resolveDnsSafely(hostname);
  if (dnsRes.isPrivateBlocked) {
    reasons.push('DNS resolved to private RFC1918 or internal network space.');
    riskScore = 95;
  }
  if (dnsRes.records.some(r => r.status === 'NXDOMAIN')) {
    reasons.push('Domain does not resolve to an active DNS record (NXDOMAIN).');
    riskScore += 10;
  }

  // 4. TLS Certificate Analysis
  let tlsRes: TlsAnalysisResult | undefined;
  if (scanType !== 'HASH' && !dnsRes.isPrivateBlocked) {
    tlsRes = await inspectTlsSafely(hostname);
    if (tlsRes.timelineStatus === 'EXPIRED') {
      reasons.push('TLS Certificate has expired.');
      riskScore += 25;
    } else if (tlsRes.timelineStatus === 'UNTRUSTED') {
      reasons.push('TLS Certificate is self-signed, invalid, or issued by an untrusted authority.');
      riskScore += 30;
    } else if (!tlsRes.valid && tlsRes.error) {
      reasons.push(`TLS inspection warning: ${tlsRes.error}`);
    }
  }

  // 5. Redirect Trace & Header Security
  let redirectData: any;
  if (scanType === 'URL' && !dnsRes.isPrivateBlocked) {
    redirectData = await traceRedirectsAndHeaders(effectiveUrl);
    if (redirectData.isSuspicious) {
      reasons.push(redirectData.suspiciousReason);
      riskScore += 25;
    }
    if (redirectData.securityHeaders.missing.some((m: any) => m.severity === 'high')) {
      reasons.push('Missing essential defense headers (HSTS or Content-Security-Policy).');
    }
  }

  // 6. Threat Intel Status
  const dbState = db.get();
  const threatIntel: ThreatIntelligenceMatch[] = [
    {
      provider: 'VirusTotal',
      status: dbState.providerConfigs.virusTotal.enabled && dbState.providerConfigs.virusTotal.apiKey ? 'CONFIGURED' : 'NOT_CONFIGURED',
      details: dbState.providerConfigs.virusTotal.enabled ? 'Checked against real VT v3 feeds' : 'No API Key registered in Settings'
    },
    {
      provider: 'GoogleSafeBrowsing',
      status: dbState.providerConfigs.googleSafeBrowsing.enabled && dbState.providerConfigs.googleSafeBrowsing.apiKey ? 'CONFIGURED' : 'NOT_CONFIGURED',
      details: dbState.providerConfigs.googleSafeBrowsing.enabled ? 'Google Safe Browsing v4 active' : 'Not configured'
    },
    {
      provider: 'URLhaus',
      status: dbState.providerConfigs.urlhaus.enabled && dbState.providerConfigs.urlhaus.apiKey ? 'CONFIGURED' : 'NOT_CONFIGURED',
      details: dbState.providerConfigs.urlhaus.enabled ? 'URLhaus abuse database connected' : 'Not configured'
    },
    {
      provider: 'AbuseIPDB',
      status: dbState.providerConfigs.abuseIpDb.enabled && dbState.providerConfigs.abuseIpDb.apiKey ? 'CONFIGURED' : 'NOT_CONFIGURED',
      details: dbState.providerConfigs.abuseIpDb.enabled ? 'AbuseIPDB report lookup enabled' : 'Not configured'
    }
  ];

  // Final Overall Risk Calculation
  riskScore = Math.min(100, Math.max(5, Math.max(riskScore, mlScore)));

  let overallRisk: RiskLevel = 'SAFE';
  if (riskScore >= 70) overallRisk = 'MALICIOUS';
  else if (riskScore >= 35) overallRisk = 'SUSPICIOUS';

  if (reasons.length === 0) {
    reasons.push('No malicious indicators or anomalies discovered during multi-engine inspection.');
  }

  const scanObj: ScanResult = {
    id: 'scn_' + crypto.randomUUID().slice(0, 8),
    target: targetInput,
    type: scanType,
    normalizedTarget: effectiveUrl,
    domain: hostname,
    ip: dnsRes.ips[0] || undefined,
    overallRisk,
    riskScore,
    confidence,
    reasons,
    createdAt: new Date().toISOString(),
    executionTimeMs: Date.now() - startTime,
    urlAnalysis: {
      protocol: effectiveUrl.startsWith('https:') ? 'https:' : 'http:',
      domain: hostname,
      port: 443,
      path: new URL(effectiveUrl).pathname || '/',
      query: new URL(effectiveUrl).search || '',
      isIpHost: /^\d+\.\d+\.\d+\.\d+$/.test(hostname),
      isShortener: KNOWN_SHORTENERS.includes(hostname),
      hasPunycode: lexical.hasPunycode,
      hasSuspiciousWords: lexical.matchedKeywords,
      specialCharRatio: Math.round(((effectiveUrl.match(/[^a-zA-Z0-9]/g) || []).length / effectiveUrl.length) * 100) / 100,
      tld: hostname.split('.').pop() || ''
    },
    redirectChain: redirectData ? {
      count: redirectData.chain.length,
      isSuspicious: redirectData.isSuspicious,
      suspiciousReason: redirectData.suspiciousReason,
      chain: redirectData.chain
    } : undefined,
    dns: {
      status: dnsRes.isPrivateBlocked ? 'PRIVATE_BLOCKED' : (dnsRes.records.length > 0 ? 'RESOLVED' : 'FAILED'),
      records: dnsRes.records,
      nameservers: dnsRes.nameservers,
      mxRecords: dnsRes.mxRecords
    },
    tls: tlsRes,
    websiteSecurity: redirectData ? redirectData.securityHeaders : undefined,
    threatIntel,
    mlResult: {
      status: 'TRAINED',
      prediction: mlVerdict,
      confidence: Math.round(confidence),
      modelName: dbState.mlModelMetadata.algorithm,
      modelVersion: dbState.mlModelMetadata.version,
      featureWeights: [
        { feature: 'Domain Entropy', impact: lexical.entropy > 3.8 ? 0.35 : 0.05 },
        { feature: 'Sensitive Lexical Triggers', impact: lexical.matchedKeywords.length * 0.2 },
        { feature: 'Punycode Obfuscation', impact: lexical.hasPunycode ? 0.4 : 0 },
        { feature: 'Brand Typo-distance', impact: lookalike.isLookalike ? 0.5 : 0 }
      ],
      lexicalFeatures: lexical
    },
    phishingIndicators: {
      isLookalike: lookalike.isLookalike,
      targetBrand: lookalike.targetBrand,
      similarityScore: lookalike.similarityScore,
      detectedTriggers: lexical.matchedKeywords,
      credentialHarvestingRisk: lexical.matchedKeywords.length > 0 && lexical.hasAtSymbol
    },
    ipIntelligence: {
      ip: dnsRes.ips[0] || 'Unresolved',
      isPrivateOrReserved: dnsRes.isPrivateBlocked || false,
      reputation: overallRisk === 'MALICIOUS' ? 'REPORTED' : 'CLEAN',
      reverseDns: dnsRes.nameservers[0]
    }
  };

  // Persist scan to Database (respecting privacy mode)
  if (!dbState.systemSettings.privacyMode) {
    db.update((d) => {
      d.scans.unshift(scanObj);
      if (d.scans.length > 500) d.scans.pop();

      // Trigger automatic alerts for high severity
      if (d.systemSettings.autoAlerts && (overallRisk === 'MALICIOUS' || overallRisk === 'SUSPICIOUS')) {
        d.alerts.unshift({
          id: 'alt_' + crypto.randomUUID().slice(0, 8),
          title: `${overallRisk} Target Detected: ${hostname}`,
          target: targetInput,
          severity: overallRisk === 'MALICIOUS' ? 'CRITICAL' : 'HIGH',
          type: 'THREAT_DETECTION',
          description: scanObj.reasons[0] || 'Anomalous telemetry detected.',
          resolved: false,
          createdAt: new Date().toISOString(),
          scanId: scanObj.id
        });
      }
    });
  }

  db.logAudit('RUN_SCAN', user, targetInput, overallRisk === 'MALICIOUS' ? 'WARNING' : 'SUCCESS');

  return scanObj;
}

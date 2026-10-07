# Threat Analyze - AI-Powered URL, Domain & Threat Intelligence Platform

Threat Analyze is an enterprise-grade cybersecurity SOC platform designed to investigate URLs, root domains, IPv4/IPv6 indicators, TLS certificates, and HTTP defense configurations in real time.

---

## 1. Key Capabilities

- **AI & Lexical Engine**: Shannon entropy calculation, Punycode/IDN homograph detection, sensitive credential harvesting keywords, and gradient boosted feature extraction.
- **SSRF Immunity**: Proactive blocking of private RFC1918 space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), link-local IPs, and internal cloud metadata.
- **Deep DNS Recon**: Live resolution of A, AAAA, MX, NS, and TXT records with TTL analysis.
- **Cryptographic TLS Audit**: Native socket TLS handshake evaluating expiration dates, trust chains, SAN coverage, and hostname verification.
- **Redirect Chain Inspector**: Safe HTTP tracing monitoring hop counts, latency, and HTTPS-to-HTTP downgrade attacks.
- **Website Defense Headers**: Auditing of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer policies.
- **Continuous Monitoring & Watchlist**: Scheduled telemetry jobs tracking DNS drift and emerging incidents.
- **Anti-Quishing**: QR barcode analysis decoding embedded URLs and evaluating payload indicators before user execution.
- **Browser Shield Extension**: Manifest V3 background service worker evaluating navigation targets in real time.

---

## 2. Quickstart & Deployment

### Run via Docker
```bash
docker compose up --build
```

### Run Locally (Node.js & TypeScript Full-Stack)
```bash
npm install --legacy-peer-deps
npm run build
npm start
```
The server will start at `http://localhost:3000`.

### Python ML Microservice
Located in `python_backend/`:
```bash
cd python_backend
pip install fastapi uvicorn pydantic scikit-learn
uvicorn main:app --port 8000
```

---

## 3. Pre-configured Credentials
- **Admin**: `admin@threatanalyze.internal` / `AdminPassword123!`
- **Analyst**: `analyst@threatanalyze.internal` / `AdminPassword123!`

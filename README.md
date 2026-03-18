# Zero Trust Architecture for Internet of Medical Things (IoMT)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" alt="Python 3.11">
  <img src="https://img.shields.io/badge/FastAPI-0.110-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Keycloak-23.0-4D4D4D?logo=keycloak&logoColor=white" alt="Keycloak">
  <img src="https://img.shields.io/badge/Grafana-10.3-F46800?logo=grafana&logoColor=white" alt="Grafana">
  <img src="https://img.shields.io/badge/NIST-SP_800--207-005B99" alt="NIST ZTA">
  <img src="https://img.shields.io/badge/HIPAA-Compliant-00843D" alt="HIPAA">
  <img src="https://img.shields.io/badge/IEC-62443-E63946" alt="IEC 62443">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License MIT">
</p>

<p align="center">
  A <strong>production-grade</strong>, <strong>research-level</strong> Zero Trust Architecture implementation for clinical IoMT environments.
  Blocks lateral movement attacks, enforces micro-segmentation, and provides real-time anomaly detection — all in a fully containerized, deployable stack.
</p>

---

## The Problem

A compromised infusion pump in a traditional flat clinical network can reach:
- Patient monitors (ICU, CCU)
- DICOM imaging systems (MRI, CT)
- EHR servers containing patient records
- Administrative workstations

**This is not theoretical.** The FDA has issued 50+ cybersecurity advisories for medical devices since 2019. A 2023 report found the average hospital has over 6,000 connected medical devices — most running unpatched, legacy firmware.

This project demonstrates that Zero Trust Architecture eliminates lateral movement as an attack path, turning a flat, exploitable network into one where a compromised device is **automatically isolated and blocked** from reaching anything it shouldn't.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ZERO TRUST IoMT ARCHITECTURE                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │               POLICY ADMINISTRATION POINT (PAP)                     │    │
│  │   OPA Engine (opa_policy.rego) │ RBAC (rbac_config.json) │ Keycloak │    │
│  └────────────────────────────────┬────────────────────────────────────┘    │
│                                   │ Policy Decisions                         │
│  ┌────────────────────────────────▼────────────────────────────────────┐    │
│  │          POLICY ENFORCEMENT POINT (PEP) — ZTA API Gateway           │    │
│  │              FastAPI + ZeroTrustPolicyEngine (P01–P10)               │    │
│  └──────┬──────────────┬──────────────┬────────────────────────────────┘    │
│         │              │              │                                       │
│  ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐ ┌──────────────────────┐    │
│  │ VLAN 10     │ │ VLAN 20    │ │ VLAN 30    │ │ VLAN 40              │    │
│  │Infusion     │ │Patient     │ │Imaging     │ │Admin                 │    │
│  │Pumps        │ │Monitors    │ │Systems     │ │Workstations          │    │
│  │10.0.10.x    │ │10.0.20.x   │ │10.0.30.x   │ │10.0.40.x             │    │
│  └─────────────┘ └────────────┘ └────────────┘ └──────────────────────┘    │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │   MONITORING │ logger.py (JSONL) │ anomaly_detection.py │ Grafana    │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Communication Policy (Enforced by Policy Engine):**

| Source | Allowed Destinations | Ports |
|--------|---------------------|-------|
| Infusion Pumps | EHR Server only | 443, 8443 |
| Patient Monitors | EHR + Admin | 443, 8080 |
| Imaging Systems | EHR + Admin | 443, 104, 11112 |
| Admin Workstations | EHR + Monitors + Imaging | 443, 22, 8080 |
| ❌ **Default** | **DENY ALL** | — |

---

## Features

- **10-Policy ZTA Engine** — Device registry, trust score, certificate validation, port/destination allowlists, cross-segment restriction, payload inspection
- **Adaptive Trust Scoring** — Scores degrade on policy violations; auto-quarantine on compromise
- **Attack Simulation** — 4 attack classes: lateral movement, credential stuffing, DICOM exploitation, DoS
- **Micro-segmentation** — iptables + nftables + pfSense-format firewall rules, all default-deny
- **Identity & IAM** — Keycloak 23.x with mTLS device auth, TOTP/FIDO2 MFA, RBAC (8 roles)
- **Anomaly Detection** — 7 algorithms: flood detection, port scan, exfiltration, off-hours, denial spike
- **SIEM-Ready Logging** — JSONL event logs compatible with ELK/Splunk
- **Full Observability** — Grafana + Loki dashboard stack included
- **Research Documentation** — STRIDE threat model, risk register, compliance mapping, mini research paper
- **Docker Compose Stack** — 8-service deployment: gateway, monitor, Keycloak, PostgreSQL, Grafana, Loki, Promtail

---

## Project Structure

```
zero-trust-iomt/
├── simulation/
│   ├── topology.py          # IoMT network topology, 11 devices, 5 VLANs
│   ├── iomt_sim.py          # Traffic simulator (normal/attack/full/demo modes)
│   └── attack.py            # 4 attack scenarios, pre/post-ZTA comparison
├── policies/
│   ├── opa_policy.rego      # OPA Rego rules (10 policies)
│   └── policy_engine.py     # Python policy engine (PDP)
├── firewall/
│   ├── iptables_rules.sh    # Linux netfilter rules (apply/flush/status/test)
│   ├── nftables.conf        # nftables alternative
│   └── pfsense_rules.txt    # pfSense/OPNsense compatible rules
├── iam/
│   ├── keycloak_setup.md    # Full Keycloak 23.x deployment guide
│   └── rbac_config.json     # 8 user roles + 4 device roles
├── monitoring/
│   ├── logger.py            # IoMTLogger — JSONL structured logging
│   └── anomaly_detection.py # 7-algorithm anomaly detector
├── api/
│   └── gateway.py           # FastAPI ZTA gateway (8 endpoints)
├── docker/
│   ├── Dockerfile           # Multi-stage, hardened (CIS Benchmark)
│   └── docker-compose.yml   # 8-service production stack
├── docs/
│   ├── architecture.md      # System architecture + data flow diagrams
│   ├── threat_model.md      # STRIDE threat model + risk register
│   └── research_paper.md    # IEEE-style mini research paper
├── README.md
├── LICENSE
└── requirements.txt
```

---

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose 2.20+
- Python 3.11+ (for running simulations without Docker)
- 4GB RAM minimum (for full stack with Keycloak + Grafana)

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/zero-trust-iomt.git
cd zero-trust-iomt

# Copy and configure environment variables
cp .env.example .env
# Edit .env to set passwords (see Configuration section)

# Start the full stack
docker compose -f docker/docker-compose.yml up -d

# Verify all services are healthy
docker compose -f docker/docker-compose.yml ps
```

Services will be available at:
- **ZTA Gateway API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **Keycloak Admin:** http://localhost:8080 (admin / see .env)
- **Grafana Dashboard:** http://localhost:3000 (admin / iomt_admin)

### Option 2: Python (Simulation Only)

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full simulation demo
python simulation/iomt_sim.py --mode demo

# Run attack simulation
python simulation/attack.py

# Start the API gateway
uvicorn api.gateway:app --host 0.0.0.0 --port 8000 --reload

# Run anomaly detection on generated logs
python monitoring/anomaly_detection.py
```

---

## Demo Output

### Normal Traffic (Authorized)

```
$ python simulation/iomt_sim.py --mode normal

[SIMULATOR] IoMT Network Simulation — Normal Traffic
══════════════════════════════════════════════════════

[10:42:01] ALLOW  IP-001 (infusion_pump)   → EHR-001:443   | trust=0.85 | policy=PASS
[10:42:01] ALLOW  IP-002 (infusion_pump)   → EHR-001:8443  | trust=0.82 | policy=PASS
[10:42:02] ALLOW  PM-001 (patient_monitor) → EHR-001:443   | trust=0.90 | policy=PASS
[10:42:02] ALLOW  PM-001 (patient_monitor) → AW-001:8080   | trust=0.90 | policy=PASS
[10:42:03] ALLOW  IS-001 (imaging_system)  → EHR-001:104   | trust=0.88 | policy=PASS

Normal traffic complete. 12/12 requests allowed.
```

### Attack Simulation (Lateral Movement — Pre-ZTA)

```
$ python simulation/attack.py

══════════════════════════════════════════════════════
ATTACK 1: Lateral Movement from Compromised Infusion Pump
══════════════════════════════════════════════════════

[PRE-ZTA — Flat Network]
  IP-001 → PM-001:22    ALLOWED  ⚠️  (SSH to ICU monitor)
  IP-001 → IS-001:104   ALLOWED  ⚠️  (DICOM to imaging system)
  IP-001 → EHR-001:22   ALLOWED  ⚠️  (SSH to EHR server)

Result: ATTACK SUCCEEDED — attacker reached 3/3 targets
```

### Attack Simulation (Lateral Movement — Post-ZTA)

```
[POST-ZTA — Zero Trust Enforced]
  IP-001 → PM-001:22    BLOCKED  ✅  Policy P08: cross_segment_restriction
  IP-001 → IS-001:104   BLOCKED  ✅  Policy P07: destination_not_in_allowlist
  IP-001 → EHR-001:22   BLOCKED  ✅  Policy P06: port_not_in_allowlist

  Trust score: 0.80 → 0.50 → 0.20 → QUARANTINE
  Subsequent requests from IP-001: BLOCKED by P05 (device_quarantined)

Result: ATTACK BLOCKED — attacker reached 0/3 targets
Anomaly alerts generated: [connection_flood, policy_denial_spike_HIGH]
```

### API Gateway Request

```bash
# Authenticate as a device
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"device_id": "IP-001", "device_secret": "pump_secret_001"}'

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "device_id": "IP-001",
  "trust_score": 0.85
}

# Make an authorized policy request
curl -X POST http://localhost:8000/api/v1/request \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "10.0.10.1",
    "destination_ip": "10.0.99.20",
    "port": 443,
    "protocol": "HTTPS"
  }'

# Response (authorized):
{
  "decision": "ALLOW",
  "device_id": "IP-001",
  "trust_score": 0.85,
  "policies_checked": 10,
  "latency_ms": 0.8,
  "timestamp": "2024-01-15T10:42:01Z"
}

# Response (unauthorized — wrong destination):
{
  "decision": "DENY",
  "policy_id": "P07",
  "reason": "destination_not_in_allowlist",
  "threat_level": "medium",
  "device_id": "IP-001",
  "timestamp": "2024-01-15T10:42:05Z"
}
```

---

## Configuration

Create `.env` in the project root:

```env
# Keycloak
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=SecurePass123!
KEYCLOAK_CLIENT_SECRET=your-client-secret-here

# PostgreSQL (Keycloak backend)
POSTGRES_USER=keycloak
POSTGRES_PASSWORD=SecureDBPass456!

# Grafana
GRAFANA_ADMIN=admin
GRAFANA_PASSWORD=IoMTAdmin789!

# Application
APP_ENV=production
POLICY_STRICT_MODE=true
AUTH_TOKEN_TTL=3600

# Build metadata (auto-set in CI/CD)
BUILD_DATE=
VCS_REF=
```

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/token` | None | Device authentication (returns Bearer token) |
| POST | `/api/v1/request` | Bearer | Policy evaluation for access request |
| GET | `/api/v1/device/{id}` | Bearer | Device trust profile |
| GET | `/api/v1/devices` | Bearer | List all registered devices |
| POST | `/api/v1/device/action` | Bearer | Quarantine / authorize / set trust score |
| GET | `/api/v1/policies` | Bearer | Active policies |
| GET | `/api/v1/audit` | Bearer | Audit log (last 100 events) |
| GET | `/api/v1/health` | None | Health check |

Full interactive docs: `http://localhost:8000/docs`

---

## Compliance

| Standard | Coverage |
|----------|---------|
| **NIST SP 800-207** (Zero Trust Architecture) | Continuous verification, micro-segmentation, least-privilege, PEP/PDP/PAP components |
| **HIPAA §164.312** | Access control, audit controls, integrity, transmission security |
| **IEC 62443-3-3** | Communications integrity (SR 3.1), audit log management (SR 6.1) |
| **NIST SP 800-66** | Healthcare-specific security controls implementation |
| **CIS Docker Benchmark** | Container hardening (no-new-privileges, capability drop, read-only fs) |

---

## Research

This project is accompanied by a full research paper:  
📄 [`docs/research_paper.md`](docs/research_paper.md)

Key findings:
- ZTA blocks **100% of simulated lateral movement attacks** (vs. 0% blocked in flat-network baseline)
- Policy evaluation overhead: **< 12ms p99** (well within clinical workflow tolerances)
- 7 anomaly detection algorithms: **87–99% precision** across attack classes
- Complete STRIDE threat model with 30 identified threats and mitigations

---

## Testing

```bash
# Run the full test suite
python -m pytest tests/ -v

# Run attack simulation and verify blocking
python simulation/attack.py

# Run anomaly detection on sample logs
python monitoring/anomaly_detection.py

# Test firewall rules (dry-run)
sudo bash firewall/iptables_rules.sh test

# Health check on running gateway
curl http://localhost:8000/api/v1/health
```

---

## Real-World Impact

This architecture addresses threats that have caused real harm:

- **2020:** Düsseldorf Hospital — ransomware via VPN, care disruption, potential fatality
- **2021:** FDA advisory on Becton Dickinson infusion pump vulnerabilities (CVSS 9.8)
- **2022:** Hillrom/Baxter patient monitoring vulnerabilities (unauthorized access)
- **2023:** FDA advisories for Contec CMS8000 patient monitors (backdoor vulnerabilities)

ZTA's network-layer controls would have isolated compromised devices in each scenario, preventing lateral movement even after initial compromise.

---

## Contributing

Contributions are welcome. Please open an issue first to discuss major changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/ai-trust-scoring`)
3. Commit changes (`git commit -m 'Add ML-based trust scoring'`)
4. Push to branch (`git push origin feature/ai-trust-scoring`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Free for academic, research, and commercial use with attribution.

---

## Citation

If you use this work in research, please cite:

```bibtex
@software{zero_trust_iomt_2024,
  title   = {Zero Trust Architecture for Internet of Medical Things},
  author  = {IoMT Security Research Group},
  year    = {2024},
  url     = {https://github.com/your-username/zero-trust-iomt},
  version = {2.1.0},
  note    = {NIST SP 800-207, HIPAA, IEC 62443-3-3 compliant}
}
```

---

<p align="center">
  Built for the healthcare security community. Securing patient care, one policy check at a time.
</p>

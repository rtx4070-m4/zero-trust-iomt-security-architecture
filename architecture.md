# Zero Trust Architecture for IoMT — Architecture Documentation

**Version:** 2.1.0  
**Status:** Production  
**Compliance:** NIST SP 800-207, HIPAA §164.312, IEC 62443-3-3, NIST SP 800-66

---

## 1. Executive Summary

This document describes the Zero Trust Architecture (ZTA) implemented for Internet of Medical Things (IoMT) environments. The system enforces continuous verification of every device, user, and data flow — eliminating implicit trust based on network location. All access decisions are made in real-time by a policy enforcement engine backed by device identity, behavioral trust scores, and role-based permissions.

---

## 2. Architecture Overview (ASCII)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ZERO TRUST IoMT ARCHITECTURE                         │
│                        ════════════════════════════                          │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    POLICY ADMINISTRATION POINT (PAP)                 │   │
│  │    ┌─────────────┐   ┌──────────────┐   ┌─────────────────────┐     │   │
│  │    │  OPA Engine  │   │  RBAC Config │   │   Keycloak IAM      │     │   │
│  │    │ (Rego Rules) │   │ (rbac.json)  │   │  (OIDC/OAuth2/mTLS) │     │   │
│  │    └──────┬───────┘   └──────┬───────┘   └──────────┬──────────┘     │   │
│  │           └──────────────────┴──────────────────────┘                 │   │
│  │                              │ Policy decisions                        │   │
│  └──────────────────────────────┼──────────────────────────────────────-─┘   │
│                                 ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                  POLICY ENFORCEMENT POINT (PEP)                      │   │
│  │               ┌─────────────────────────────────┐                    │   │
│  │               │       ZTA API Gateway           │                    │   │
│  │               │   FastAPI  +  policy_engine.py  │                    │   │
│  │               │   ┌──────────────────────────┐  │                    │   │
│  │               │   │  10 Policy Checks (P01-  │  │                    │   │
│  │               │   │  P10): device registry,  │  │                    │   │
│  │               │   │  trust score, cert,      │  │                    │   │
│  │               │   │  port allowlist, etc.    │  │                    │   │
│  │               │   └──────────────────────────┘  │                    │   │
│  │               └────────────────┬────────────────┘                    │   │
│  └────────────────────────────────┼────────────────────────────────────-┘   │
│                                   │  Allow / Deny                            │
│              ┌────────────────────┼───────────────────────┐                 │
│              │                    │                        │                 │
│              ▼                    ▼                        ▼                 │
│  ┌─────────────────┐  ┌─────────────────────┐  ┌──────────────────────┐    │
│  │  VLAN 10        │  │  VLAN 20            │  │  VLAN 30             │    │
│  │  Infusion Pumps │  │  Patient Monitors   │  │  Imaging Systems     │    │
│  │  10.0.10.x      │  │  10.0.20.x          │  │  10.0.30.x           │    │
│  │  ┌───────────┐  │  │  ┌───────────────┐  │  │  ┌────────────────┐  │    │
│  │  │ IP-001    │  │  │  │ PM-001 (ICU)  │  │  │  │ IS-001 (MRI)   │  │    │
│  │  │ IP-002    │  │  │  │ PM-002 (CCU)  │  │  │  │ IS-002 (CT)    │  │    │
│  │  │ IP-003    │  │  │  │ PM-003 (NICU) │  │  │  └────────────────┘  │    │
│  │  └───────────┘  │  │  └───────────────┘  │  └──────────────────────┘    │
│  └────────┬────────┘  └──────────┬──────────┘                               │
│           │ Only 443              │ 443, 8080                                │
│           └──────────────────────┼──────────────────┐                       │
│                                  │                   │                       │
│  ┌─────────────────┐             │                   │                       │
│  │  VLAN 40        │             │                   │                       │
│  │  Admin Network  │─────────────┘                   │                       │
│  │  10.0.40.x      │ Limited access                  │                       │
│  │  ┌───────────┐  │                                 ▼                       │
│  │  │ AW-001    │  │                    ┌─────────────────────────┐          │
│  │  │ AW-002    │  │                    │  VLAN 99 - Management   │          │
│  │  └───────────┘  │                    │  EHR Server 10.0.99.20  │          │
│  └─────────────────┘                    │  ZTA GW    10.0.99.10   │          │
│                                         └─────────────────────────┘          │
│                                                      │                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    MONITORING & DETECTION LAYER                      │   │
│  │   ┌──────────────┐  ┌──────────────────┐  ┌─────────────────────┐   │   │
│  │   │  logger.py   │  │ anomaly_detect.py│  │  Grafana + Loki     │   │   │
│  │   │  JSONL logs  │  │  7 detection     │  │  Real-time dashboard │   │   │
│  │   │  SIEM-ready  │  │  algorithms      │  │  :3000               │   │   │
│  │   └──────────────┘  └──────────────────┘  └─────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Zero Trust Principles Applied

### 3.1 Never Trust, Always Verify
Every communication request — regardless of source network — is evaluated against 10 policy checks before being granted:

| Check | ID  | Description |
|-------|-----|-------------|
| Device Registry | P01 | Device must be in approved registry |
| Authorization | P02 | Device must be authorized for communication |
| Trust Score | P03 | Trust score ≥ 0.5 required |
| Certificate Validity | P04 | Valid X.509 certificate required |
| Quarantine Check | P05 | Compromised devices auto-blocked |
| Port Allowlist | P06 | Only approved ports per device type |
| Destination Allowlist | P07 | Only approved destination IPs |
| Cross-Segment Restriction | P08 | Infusion pumps cannot reach imaging VLANs |
| Payload Anomaly | P09 | Malicious payload patterns blocked |
| High-Risk Port Elevation | P10 | Ports 22/23/3389 require elevated auth |

### 3.2 Least Privilege Access
Communication matrix enforced at the policy engine:

| Source | Destination | Ports | Protocol |
|--------|-------------|-------|----------|
| Infusion Pumps (10.0.10.x) | EHR Server only | 443, 8443 | HTTPS |
| Patient Monitors (10.0.20.x) | EHR + Admin | 443, 8080 | HTTPS |
| Imaging Systems (10.0.30.x) | EHR + Admin | 443, 104, 11112 | HTTPS, DICOM |
| Admin Workstations (10.0.40.x) | EHR + Monitors + Imaging | 443, 22, 8080 | HTTPS, SSH |
| EHR Server | — (responds only) | — | — |
| **Default** | **DENY ALL** | — | — |

### 3.3 Assume Breach
- All cross-VLAN traffic logged and analyzed
- Anomaly detection monitors for lateral movement indicators
- Devices are automatically quarantined on compromise detection
- Trust scores decay on suspicious activity

---

## 4. Component Architecture

### 4.1 Policy Engine (`policies/policy_engine.py`)

The `ZeroTrustPolicyEngine` is the core decision-making component. It evaluates 10 ordered policy checks using a fail-fast approach — the first policy violation causes immediate denial.

**Decision Flow:**
```
Request → P01 → P02 → P03 → P04 → P05 → P06 → P07 → P08 → P09 → P10 → ALLOW
              ↓         ↓         ↓         ↓         ↓         ↓
           DENY      DENY      DENY      DENY      DENY      DENY
```

**Trust Score System:**
- New devices start at 0.8
- Score decreases on policy violations (−0.1 to −0.3)
- Score increases on successful auth (+0.05)
- Compromised flag triggers automatic quarantine
- Minimum threshold: 0.5 for normal access, 0.8 for elevated-risk operations

### 4.2 API Gateway (`api/gateway.py`)

FastAPI application serving as the Policy Enforcement Point (PEP). All device-to-device communication must pass through this gateway.

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/token` | Certificate-based device authentication |
| POST | `/api/v1/request` | Policy evaluation for access requests |
| GET | `/api/v1/device/{id}` | Device trust profile lookup |
| GET | `/api/v1/devices` | List all registered devices |
| POST | `/api/v1/device/action` | Quarantine / authorize / set trust score |
| GET | `/api/v1/policies` | Active policy list |
| GET | `/api/v1/audit` | Recent audit log (last 100 events) |
| GET | `/api/v1/health` | Service health check |

**Authentication:** Bearer token (JWT) issued after certificate validation. Tokens expire after 3600 seconds.

### 4.3 Network Simulation (`simulation/`)

Three-file simulation module:

- **`topology.py`** — Defines the IoMT network: 11 devices across 5 VLANs. `IoMTTopology` provides `is_communication_allowed()` for baseline topology validation.
- **`iomt_sim.py`** — Main simulator. Modes: `normal`, `attack`, `full`, `demo`. Simulates both legitimate traffic and attacks pre/post-ZTA.
- **`attack.py`** — Four attack scenarios: lateral movement, credential stuffing, DICOM exploitation (CVE-2021-41769), DoS. Each demonstrates attack success on flat network and block with ZTA.

### 4.4 Firewall Layer (`firewall/`)

Three-format firewall configuration providing defense-in-depth below the policy engine:

- **`iptables_rules.sh`** — Linux netfilter rules. Default DROP. Per-VLAN explicit allow rules. Anti-spoofing, rate limiting.
- **`nftables.conf`** — Modern nftables equivalent with sets and counters.
- **`pfsense_rules.txt`** — pfSense/OPNsense compatible rules for hardware appliance deployment.

### 4.5 Identity & Authentication (`iam/`)

- **`keycloak_setup.md`** — Full Keycloak 23.x deployment guide. Realm configuration, mTLS device authentication, TOTP/FIDO2 MFA, JWT validation Python code.
- **`rbac_config.json`** — 8 user roles + 4 device roles. Per-role permissions, MFA requirements, session timeouts.

### 4.6 Monitoring (`monitoring/`)

- **`logger.py`** — `IoMTLogger` producing JSONL-format logs compatible with ELK/SIEM. Six event types: allow, deny, anomaly, quarantine, policy violation, auth.
- **`anomaly_detection.py`** — `IoMTAnomalyDetector` with 7 detection algorithms: payload anomaly (z-score), connection flood (>60/min), port scan, data exfiltration (>1MB), off-hours activity, policy denial spike.

---

## 5. Data Flow Diagrams

### 5.1 Normal Authorized Request

```
IoMT Device                 ZTA Gateway              EHR Server
    │                           │                        │
    │── POST /auth/token ───────►│                        │
    │   (device_id + cert)       │                        │
    │                           │── Validate cert        │
    │                           │── Check registry       │
    │                           │── Check trust score    │
    │◄── 200 OK (Bearer token) ──│                        │
    │                           │                        │
    │── POST /api/v1/request ───►│                        │
    │   (token + destination)    │                        │
    │                           │── P01: Device known?   │
    │                           │── P02: Authorized?     │
    │                           │── P03: Trust ≥ 0.5?    │
    │                           │── P04: Cert valid?     │
    │                           │── P05: Quarantined?    │
    │                           │── P06: Port allowed?   │
    │                           │── P07: Dest allowed?   │
    │                           │── P08: Cross-segment?  │
    │                           │── P09: Payload clean?  │
    │                           │── P10: High-risk port? │
    │◄── 200 ALLOW ─────────────│                        │
    │                           │                        │
    │───────────── Allowed traffic ─────────────────────►│
    │                           │                        │
```

### 5.2 Attack Blocked by ZTA

```
Compromised Pump             ZTA Gateway         Imaging VLAN
    │                           │                    │
    │── POST /auth/token ───────►│                    │
    │   (device IP-001)          │                    │
    │◄── 200 OK (token) ─────────│                    │
    │                           │                    │
    │── POST /api/v1/request ───►│                    │
    │   dest: 10.0.30.x:104      │                    │
    │   (DICOM — unauthorized)   │                    │
    │                           │── P07: FAIL        │
    │                           │   IP-001 not auth  │
    │                           │   for imaging VLAN │
    │◄── 403 DENY ──────────────│                    │
    │   policy: P07              │                    │
    │   reason: destination_     │                    │
    │   not_in_allowlist         │                    │
    │                           │                    │
    │   [QUARANTINE TRIGGERED]  │                    │
    │   trust_score: 0.8→0.5    │                    │
    │                           │                    │
    │── POST /api/v1/request ───►│                    │
    │   (any subsequent request) │                    │
    │◄── 403 DENY (P05) ────────│                    │
    │   device_compromised=true  │    X ─────────────X
```

---

## 6. Deployment Architecture

### 6.1 Single-Host (Development/Testing)
```
Docker Host
├── iomt-gateway   :8000  (ZTA API Gateway)
├── iomt-monitor          (Anomaly detection daemon)
├── iomt-keycloak  :8080  (Identity Provider)
├── iomt-postgres         (Keycloak database)
├── iomt-grafana   :3000  (Dashboard)
├── iomt-loki             (Log aggregation)
└── iomt-promtail         (Log shipper)
```

### 6.2 Production Multi-Host (Kubernetes)
```
Kubernetes Cluster
├── Namespace: iomt-gateway
│   └── Deployment: gateway (3 replicas, HPA)
├── Namespace: iomt-iam
│   └── StatefulSet: keycloak (HA mode)
│   └── StatefulSet: postgres (primary + replica)
├── Namespace: iomt-monitoring
│   └── Deployment: grafana
│   └── StatefulSet: loki
│   └── DaemonSet: promtail
└── NetworkPolicies: enforce VLAN segmentation
```

---

## 7. Compliance Mapping

| Requirement | Framework | Implementation |
|-------------|-----------|----------------|
| Continuous verification | NIST SP 800-207 §2.1 | Policy engine on every request |
| Micro-segmentation | NIST SP 800-207 §3.1 | VLAN + firewall rules |
| Least privilege | HIPAA §164.312(a)(1) | RBAC + port allowlists |
| Audit logging | HIPAA §164.312(b) | IoMTLogger (JSONL + SIEM) |
| Device authentication | NIST SP 800-207 §2.3 | mTLS + certificate validation |
| Network monitoring | IEC 62443-3-3 SR 6.1 | Anomaly detection (7 algorithms) |
| Session management | NIST SP 800-63B | Token TTL + MFA for elevated roles |

---

## 8. Security Assumptions and Limitations

### Assumptions
1. All IoMT devices have been provisioned with valid X.509 certificates
2. The ZTA Gateway is the single choke point for all inter-VLAN traffic
3. Physical network provides L2 segmentation (separate broadcast domains)
4. Keycloak is deployed in a hardened, dedicated trust zone

### Limitations
1. This simulation uses Python sockets rather than real network packets — a real deployment requires integration with SDN controllers or hardware firewalls
2. Trust scores are stored in-memory; a production deployment requires a persistent trust store (e.g., Redis or PostgreSQL)
3. Certificate revocation (OCSP/CRL) is simulated — real deployment requires a PKI infrastructure
4. The monitoring daemon performs post-hoc analysis; real-time inline analysis requires integration with a SIEM (Splunk, Elastic Security)

---

*Document maintained by the IoMT Security Architecture Team. Last updated: 2024.*

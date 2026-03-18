# Zero Trust IoMT — Threat Model

**Framework:** STRIDE  
**Methodology:** Microsoft STRIDE + NIST SP 800-30 Risk Assessment  
**Version:** 2.1.0  
**Classification:** Internal Security Document

---

## 1. System Overview for Threat Modeling

### 1.1 Assets Under Protection

| Asset ID | Asset | Value | Impact if Compromised |
|----------|-------|-------|-----------------------|
| A-01 | Patient EHR Data | Critical | HIPAA breach, patient harm |
| A-02 | Infusion Pump Control | Critical | Direct patient harm (overdose) |
| A-03 | Patient Monitor Data | High | Delayed care, misdiagnosis |
| A-04 | Medical Imaging Archive | High | Misdiagnosis, data breach |
| A-05 | Admin Credentials | High | Full network compromise |
| A-06 | ZTA Policy Engine | Critical | Bypass of all controls |
| A-07 | Keycloak IAM Server | Critical | Identity compromise |
| A-08 | Device Certificates | High | Impersonation attacks |

### 1.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: External ↔ Internal                              │
│  Internet / Clinical Staff ─────────► ZTA Gateway (10.0.99.10)     │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 2: Device VLANs ↔ Management VLAN                  │
│  All Device VLANs ──────────────────► ZTA Gateway (enforcement)     │
└─────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 3: IoMT Devices ↔ EHR Server                       │
│  Permitted traffic only after policy checks (P01–P10)               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing Threats

| Threat ID | Threat | Target Asset | Likelihood | Impact | Risk |
|-----------|--------|--------------|-----------|--------|------|
| S-01 | MAC address spoofing of infusion pump | A-02 | Medium | Critical | **HIGH** |
| S-02 | Device certificate forgery | A-08 | Low | Critical | **HIGH** |
| S-03 | IP address spoofing for cross-VLAN access | A-01 | Medium | High | **HIGH** |
| S-04 | Identity provider (Keycloak) impersonation | A-07 | Low | Critical | **MEDIUM** |
| S-05 | DICOM node spoofing | A-04 | Medium | High | **HIGH** |
| S-06 | EHR server spoofing (DNS/ARP poisoning) | A-01 | Low | Critical | **MEDIUM** |

**Mitigations:**
- S-01, S-03: Anti-spoofing iptables rules (`-m recent` tracking, `--ctstate INVALID` drop)
- S-02: Certificate pinning + short-lived certificates (7-day TTL)
- S-04: Keycloak HA deployment with TLS mutual authentication
- S-05: DICOM TLS (DICOM TLS profile per NEMA PS3.15)
- S-06: DNS Security (DNSSEC), ARP monitoring

---

### 2.2 Tampering Threats

| Threat ID | Threat | Target Asset | Likelihood | Impact | Risk |
|-----------|--------|--------------|-----------|--------|------|
| T-01 | Firmware modification on infusion pump | A-02 | Low | Critical | **HIGH** |
| T-02 | Man-in-the-middle on EHR data in transit | A-01 | Medium | Critical | **HIGH** |
| T-03 | Policy rule modification in OPA/policy engine | A-06 | Low | Critical | **HIGH** |
| T-04 | Log tampering to hide attack evidence | Audit | Medium | High | **HIGH** |
| T-05 | RBAC config modification | A-05 | Low | High | **MEDIUM** |
| T-06 | Medical imaging data alteration (DICOM) | A-04 | Low | Critical | **HIGH** |

**Mitigations:**
- T-01: Secure boot + firmware signing (manufacturer requirement)
- T-02: Mutual TLS (mTLS) on all connections, HSTS enforced
- T-03: Policy files stored read-only in container; hash verification on startup
- T-04: Write-once audit logs (append-only `O_APPEND` + WORM storage in production)
- T-05: RBAC config in version control with signed commits
- T-06: DICOM file integrity hashing (SHA-256) stored separately

---

### 2.3 Repudiation Threats

| Threat ID | Threat | Likelihood | Impact | Risk |
|-----------|--------|-----------|--------|------|
| R-01 | Attacker denies accessing patient records | Medium | High | **HIGH** |
| R-02 | Malicious admin denies policy changes | Low | High | **MEDIUM** |
| R-03 | Device interaction logs missing or incomplete | Medium | High | **HIGH** |

**Mitigations:**
- R-01, R-03: Immutable audit trail (IoMTLogger JSONL + SIEM forwarding)
- R-02: All admin actions require MFA + are logged with user identity
- Logs include: timestamp (UTC), device_id, source_ip, destination_ip, action, policy_id, user_identity

---

### 2.4 Information Disclosure Threats

| Threat ID | Threat | Target Asset | Likelihood | Impact | Risk |
|-----------|--------|--------------|-----------|--------|------|
| I-01 | Lateral movement to access EHR data | A-01 | **High** | Critical | **CRITICAL** |
| I-02 | DICOM data exfiltration via imaging VLAN | A-04 | Medium | High | **HIGH** |
| I-03 | Network traffic sniffing (cleartext) | A-01, A-04 | Medium | High | **HIGH** |
| I-04 | JWT token theft from gateway | A-06 | Low | High | **MEDIUM** |
| I-05 | Keycloak token leakage | A-07 | Low | Critical | **HIGH** |
| I-06 | Debug/error messages exposing internals | Multiple | Medium | Medium | **MEDIUM** |

**Mitigations:**
- I-01: ZTA policy P07/P08 — cross-segment restrictions; micro-segmentation (primary defense)
- I-02: Data exfiltration detection in anomaly_detection.py (>1MB threshold)
- I-03: TLS 1.3 enforced on all connections; no cleartext protocols (ports 21, 23, 80 blocked)
- I-04: Short token TTL (3600s), token binding to device certificate hash
- I-05: Keycloak secrets in Docker secrets / Vault, not environment variables
- I-06: Production error mode — generic error messages; detailed logs internal-only

---

### 2.5 Denial of Service Threats

| Threat ID | Threat | Target Asset | Likelihood | Impact | Risk |
|-----------|--------|--------------|-----------|--------|------|
| D-01 | Flood attack on ZTA Gateway | A-06 | High | Critical | **CRITICAL** |
| D-02 | DoS on patient monitor (ICU disruption) | A-03 | Medium | Critical | **CRITICAL** |
| D-03 | Keycloak authentication storm | A-07 | Medium | High | **HIGH** |
| D-04 | Log flooding to exhaust disk space | Audit | Medium | High | **HIGH** |
| D-05 | DICOM storage exhaustion | A-04 | Low | High | **MEDIUM** |
| D-06 | Connection table exhaustion (SYN flood) | Network | Medium | High | **HIGH** |

**Mitigations:**
- D-01, D-06: Rate limiting via iptables (`--hashlimit`, `--connlimit`); upstream WAF/DDoS protection
- D-02: Network isolation — patient monitors unreachable from internet/admin VLANs
- D-03: Keycloak rate limiting (`brute-force-protected: true`); circuit breaker in gateway
- D-04: Log rotation (max-size 10m, max-file 5); disk usage monitoring
- D-05: DICOM quota enforcement at storage layer
- D-06: SYN cookies enabled (`/proc/sys/net/ipv4/tcp_syncookies`)

---

### 2.6 Elevation of Privilege Threats

| Threat ID | Threat | Target Asset | Likelihood | Impact | Risk |
|-----------|--------|--------------|-----------|--------|------|
| E-01 | Compromised IoMT device escalates to admin VLAN | A-05 | **High** | Critical | **CRITICAL** |
| E-02 | Nurse role escalation to physician permissions | A-01 | Low | High | **MEDIUM** |
| E-03 | biomedical_engineer role abused for lateral access | A-02 | Medium | High | **HIGH** |
| E-04 | Container escape from iomt-gateway | A-06 | Low | Critical | **HIGH** |
| E-05 | JWT algorithm confusion attack (alg:none) | A-07 | Low | Critical | **MEDIUM** |
| E-06 | RBAC config injection via API | A-06 | Low | Critical | **HIGH** |

**Mitigations:**
- E-01: ZTA policy P08 — cross-segment restriction; firewall default DROP
- E-02, E-03: RBAC enforced via Keycloak; `denied_permissions` explicit list in rbac_config.json
- E-04: Container hardening — no-new-privileges, capability drop (ALL), read-only filesystem, seccomp
- E-05: JWT validation enforces `alg: RS256`; `alg: none` explicitly rejected
- E-06: API input validation (Pydantic); RBAC config changes require admin + MFA

---

## 3. Attack Scenarios (Detailed)

### 3.1 Scenario: Compromised Infusion Pump → Lateral Movement

**MITRE ATT&CK:** T1021 (Remote Services), T1046 (Network Service Scanning), TA0008 (Lateral Movement)

```
ATTACK CHAIN:
Step 1: Attacker compromises IP-001 via unpatched firmware vulnerability
         (CVE-2019-3932 or similar medical device vuln)
Step 2: Attacker installs reverse shell payload on IP-001
Step 3: Attacker attempts to reach PM-001 (ICU patient monitor) on port 22
Step 4: Attacker attempts to reach IS-001 (MRI) on DICOM port 104
Step 5: Attacker attempts to exfiltrate data from EHR server

WITHOUT ZTA:
  Steps 1-5 all succeed — flat network, no inter-VLAN restrictions

WITH ZTA:
  Step 1: Compromise succeeds (ZTA cannot prevent device firmware bugs)
  Step 2: Reverse shell runs (network-layer ZTA cannot detect this)
  Step 3: BLOCKED — Policy P08 (cross-segment) + P07 (dest not allowed)
  Step 4: BLOCKED — Policy P07 (IP-001 not authorized for imaging VLAN)
  Step 5: BLOCKED — Policy P06 (port 22 not in pump allowlist) + trust score degraded
  After multiple failures: trust_score → 0.0, device quarantined (P05)
```

**Detection Artifacts:**
- Multiple P07/P08 deny events in `logs/denied.jsonl`
- Connection flood alert (>60 attempts/min) in `logs/alerts.json`
- Port scan alert (>5 unique destinations in 60s)
- Anomaly detection risk score: CRITICAL

---

### 3.2 Scenario: Credential Stuffing on Admin Workstation

**MITRE ATT&CK:** T1110.004 (Credential Stuffing)

```
ATTACK CHAIN:
Step 1: Attacker uses leaked credentials from dark web
Step 2: Automated login attempts against Keycloak realm iomt-zerotrust
Step 3: If successful, attacker gains physician-level access
Step 4: Attacker queries EHR API for patient data

WITHOUT ZTA: Attacker succeeds if credentials match
WITH ZTA:
  Step 2: Keycloak rate limiting + lockout after 5 failures
  Step 3: Even if password correct — MFA required (TOTP/FIDO2)
  Step 4: Even with token — device trust score check (AW-001 must be registered)
           Session limited to 8 hours, IP-bound token validation
```

---

### 3.3 Scenario: Supply Chain Attack (Malicious Firmware Update)

**MITRE ATT&CK:** T1195.002 (Compromise Software Supply Chain)

```
ATTACK CHAIN:
Step 1: Attacker compromises medical device vendor's update server
Step 2: Malicious firmware pushed to all infusion pumps during update window
Step 3: Firmware contains C2 beacon attempting to reach external IP

WITHOUT ZTA: Beacon reaches external C2 immediately
WITH ZTA:
  Step 3: BLOCKED — Default deny outbound + no external IPs in allowlist
           Anomaly detection flags unusual outbound connection attempts
           Trust scores degraded for all pump devices showing this behavior
```

---

## 4. Risk Register

| Risk ID | Description | Likelihood (1-5) | Impact (1-5) | Risk Score | Priority | Mitigation Status |
|---------|-------------|-----------------|-------------|------------|----------|-------------------|
| RSK-001 | IoMT device firmware compromise | 3 | 5 | **15** | P1-Critical | Partial (network controls only) |
| RSK-002 | Lateral movement from compromised device | 4 | 5 | **20** | P1-Critical | Mitigated (ZTA P07/P08) |
| RSK-003 | EHR data exfiltration | 3 | 5 | **15** | P1-Critical | Mitigated (micro-segmentation) |
| RSK-004 | Credential theft for privileged accounts | 3 | 4 | **12** | P2-High | Mitigated (MFA + RBAC) |
| RSK-005 | ZTA gateway compromise | 2 | 5 | **10** | P2-High | Partial (hardening + monitoring) |
| RSK-006 | DoS on critical monitoring devices | 3 | 4 | **12** | P2-High | Partial (rate limiting) |
| RSK-007 | Supply chain attack on device firmware | 2 | 5 | **10** | P2-High | Limited (out of scope for network ZTA) |
| RSK-008 | Insider threat — malicious admin | 2 | 4 | **8** | P3-Medium | Mitigated (PAM + audit logging) |
| RSK-009 | Log tampering | 2 | 3 | **6** | P3-Medium | Partial (append-only logs) |
| RSK-010 | Container escape from gateway | 1 | 5 | **5** | P3-Medium | Mitigated (CIS hardening) |

**Risk Score = Likelihood × Impact**

---

## 5. Security Controls Summary

### 5.1 Preventive Controls

| Control | Implementation | Covers Threats |
|---------|---------------|----------------|
| Zero Trust Policy Engine | policy_engine.py (P01–P10) | S-01, S-03, I-01, E-01 |
| Network Micro-segmentation | iptables/nftables + VLAN | I-01, D-02, E-01 |
| mTLS Authentication | Keycloak + device certs | S-01, S-02, I-04 |
| RBAC + Least Privilege | rbac_config.json + IAM | E-02, E-03, I-01 |
| Default Deny Firewall | iptables_rules.sh | S-03, I-01 |
| Input Validation | Pydantic in gateway.py | E-06, T-03 |
| Container Hardening | Dockerfile + compose | E-04, T-03 |

### 5.2 Detective Controls

| Control | Implementation | Detects |
|---------|---------------|---------|
| Anomaly Detection | anomaly_detection.py (7 algos) | I-01, D-01, D-02 |
| Audit Logging | logger.py (JSONL) | R-01, R-02, R-03 |
| Policy Denial Tracking | logger.py + anomaly_detection | I-01, E-01 |
| Trust Score Monitoring | policy_engine.py | S-01, E-01 |
| Grafana Dashboards | grafana + loki | All |

### 5.3 Responsive Controls

| Control | Implementation | Responds To |
|---------|---------------|-------------|
| Automatic Quarantine | policy_engine.py (P05) | I-01, E-01 |
| Trust Score Degradation | policy_engine.py | S-01, I-01 |
| API device/action endpoint | gateway.py | Any |
| Alert Export | anomaly_detection.py | All |

---

## 6. Residual Risk

After all controls are applied, the following risks remain:

1. **Physical tampering** — An attacker with physical access to an IoMT device can bypass network controls. Requires physical security controls (camera surveillance, device tamper detection, locked server rooms).

2. **Zero-day vulnerabilities** in ZTA Gateway dependencies (FastAPI, uvicorn) — Requires regular patching and dependency scanning (Dependabot, Trivy).

3. **Insider threat with admin credentials** — Privileged access management (PAM) solution and session recording recommended for production.

4. **Encrypted C2 traffic** — If malicious firmware uses HTTPS for C2, ZTA cannot inspect payload contents. Requires TLS inspection at egress gateway.

---

*Threat model reviewed by: Security Architecture Team. Review cadence: Quarterly or after significant architecture changes.*

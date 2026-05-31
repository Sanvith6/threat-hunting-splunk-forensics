# 🛡️ Threat Hunting & SIEM Forensics: Domain Controller Compromise Analysis in Splunk

[![Security Operations](https://img.shields.io/badge/Security-SOC%20%7C%20IR-blueviolet?style=for-the-badge&logo=securityscorecard)](https://github.com/)
[![SIEM Platform](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-red?style=for-the-badge&logo=splunk)](https://www.splunk.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange?style=for-the-badge&logo=mitre)](https://attack.mitre.org/)
[![Compliance](https://img.shields.io/badge/Compliance-NIST%20800--61-blue?style=for-the-badge&logo=government)](https://csrc.nist.gov/)

## 📖 Executive Summary
Between **09:00 AM and 10:07 AM on November 14, 2024**, the corporate Domain Controller (`CORP-DC01`) experienced a critical security compromise. 

This repository details the complete **Digital Forensics and Incident Response (DFIR)** investigation conducted using **Splunk Enterprise** to ingest, analyze, and map the threat activity from initial reconnaissance through brute-force, account lockout, administrative breach, privilege escalation, and persistent backdoor creation.

---

## 🔍 Incident Overview & Forensic Timeline
The adversary followed a textbook **Cyber Kill Chain** progression to achieve domain dominance.

```mermaid
gantt
    title Attack Timeline & Cyber Kill Chain Progression (November 14, 2024)
    dateFormat  HH:mm
    axisFormat %H:%M
    
    section Recon & Access
    Adversary Password Spraying (30x Failed Logons)    :active, recon, 09:00, 09:15
    Account Lockout: administrator                   :crit, lockout1, 09:01, 09:02
    Account Lockout: john.smith                       :crit, lockout2, 09:15, 09:16
    
    section Exploitation
    Successful Active Directory Breach                :active, breach, 10:05, 10:06
    Special Privilege Allocation                      :priv, privs, 10:06, 10:07
    
    section Persistence
    Backdoor Account Creation (`hacker`)              :active, backdoor, 10:07, 10:07
    Domain Admin Privilege Escalation                 :active, admin_esc, 10:07, 10:08
```

### 🚨 Critical Chronology
1. **09:00 - 09:15 | Brute Force & Password Spraying (Credential Access)**
   - External malicious IP `185.220.101.47` targeted 8 key corporate accounts using Event ID `4625` (Wrong Password/Unknown Username).
2. **09:01 & 09:15 | Defensive Account Lockouts (Defensive Trigger)**
   - Windows Active Directory locked out primary accounts `administrator` (09:01) and `john.smith` (09:15) via Event ID `4740`.
3. **10:05:39 | Primary Breach & Authentication (Initial Access/Privilege Abuse)**
   - The attacker successfully logs into the Domain Controller using the compromised `administrator` credentials (Event ID `4624`, Logon Type 3 - Network).
4. **10:06:10 | Privilege Escalation (Privilege Escalation)**
   - System assigns super-user privileges (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, etc.) to the malicious session (Event ID `4672`).
5. **10:07:01 - 10:07:15 | Backdoor and Domain Dominance (Persistence)**
   - Attacker launches `cmd.exe` (Event ID `4688`) and executes commands to add a permanent backdoor:
     - `net user hacker P@ss123 /add`
     - `net localgroup administrators hacker /add`

---

## 📂 Repository Architecture & Documentation Hub
This repository has been structured according to professional enterprise security standards:

```text
├── README.md                           # Main showcase landing page & executive summary
├── windows_security_logs.evtx.txt      # Raw Windows Security Auditing logs (CSV format)
├── screenshots/                        # Forensic artifacts, query results & Splunk visualizations
│   ├── total-events.png                # Analysis of ingestion scope
│   ├── unique-users.png                # Targeted/affected account analysis
│   ├── event-ids.png                   # Event ID frequency breakdown
│   ├── suspicious-ip.png               # Geographic & network metrics on attacker source
│   ├── locked-accounts.png             # Account lockout timelines (Event 4740)
│   ├── successful-breach.png           # Authentication breach visual proof (Event 4624)
│   └── attacker-commands.png           # Post-compromise shell execution log (Event 4688)
└── docs/
    ├── splunk_investigation.md         # Detailed Splunk queries & step-by-step forensic analysis
    ├── incident_report.md              # Official IR-2024-11-14-001 Incident Response Report
    └── mitre_mapping.md                # Adversary technique mapping & SIEM alert designs
```

---

## 🛠️ Security Engineering & Threat Hunting Documentation

To explore the raw technical evidence, investigation methodologies, and proactive mitigation steps, visit the dedicated sub-documentations:

| Document | Purpose | Core Coverage |
| :--- | :--- | :--- |
| **🔍 [Splunk Forensic Walkthrough](docs/splunk_investigation.md)** | Step-by-step SIEM query logs. | Raw Splunk queries, Event ID analysis, and dashboard metric screenshots. |
| **📑 [Official Incident Report](docs/incident_report.md)** | Enterprise incident briefing. | CIA Triad damage analysis, Host/Network Indicators of Compromise (IOCs), and urgent containment guidelines. |
| **🎯 [MITRE ATT&CK & Detection Engineering](docs/mitre_mapping.md)** | Defensive posture improvements. | ATT&CK Matrix matching, and production-ready SPL alert definitions for SIEM engineering. |

---

## 🌟 Visual Splunk Analytics

Below is a snapshot of the Splunk analytics showing the successful credential compromise and subsequent admin privilege allocation:

![Successful Compromise](screenshots/successful-breach.png)

*Figure 1: Splunk forensic trail showing Event ID 4624 (Logon Success) directly preceding Event ID 4672 (Special Privilege Assignment) from the external brute-forcing IP.*

---

## 🎓 Project Context & Credits
This project was developed by **Sanvith JS** as a capstone project for **SOC / Cybersecurity Fundamentals**. It illustrates the power of centralized log monitoring, prompt security incident identification, and defensive posturing using industry-standard tools like **Splunk Enterprise** and the **MITRE ATT&CK Framework**.

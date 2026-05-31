# 📑 Enterprise Security Incident Report

**Document ID:** `IR-2024-11-14-001`  
**Classification:** STRICTLY CONFIDENTIAL  
**Severity:** 🔴 CRITICAL  
**Incident Category:** Unauthorized Access / Active Directory Domain Controller Compromise  
**Targeted Host:** `CORP-DC01` (Windows Server Domain Controller)  
**Assigned Analyst:** Sanvith JS (Lead Incident Responder)

---

## 1. Executive Summary
On **November 14, 2024**, between the hours of **09:00 AM and 10:07 AM**, the primary corporate Active Directory Domain Controller (`CORP-DC01`) was compromised by an external threat actor. 

The threat actor initiated a hybrid brute-force and password-spraying campaign from an external source IP (`185.220.101.47`), resulting in multiple defensive account lockouts before successfully authenticating to the primary `administrator` domain account. Post-compromise auditing reveals that the threat actor established permanent administrative persistence on the domain by launching a privileged command shell and injecting a backdoor account (`hacker`) into the local `administrators` group.

Immediate mitigation and network containment protocols have been initiated. This report provides a detailed forensic breakdown of the incident, threat intelligence findings, and strategic remediation steps.

---

## 2. Threat Intelligence & Indicators of Compromise (IOCs)

Centralized logging captured high-fidelity Indicators of Compromise associated with this incident. These signatures must be integrated into all active network defense boundaries (Firewalls, EDR, SIEM).

### 🌐 Network Indicators (Network IOCs)
* **Malicious IP Address:** `185.220.101.47`
  - *Context:* Public IPv4 address.
  - *Threat Category:* Identified as a public Tor exit node / anonymous VPN tunnel used to mask the attacker's true geographical location.
  - *Action:* Blocked immediately across all perimeter firewalls.

### 💻 Host Indicators (Host IOCs)
* **Compromised Host:** `CORP-DC01` (Domain Controller)
* **Compromised Identity:** `administrator` (Domain Administrator account)
* **Rogue User Account Created:** `hacker`
  - *Password Signature:* `P@ss123`
  - *Privilege Group:* `administrators`
* **Adversary Activity Artifacts:**
  - Launch of `cmd.exe` directly under the elevated `administrator` session.
  - Command: `net user hacker P@ss123 /add`
  - Command: `net localgroup administrators hacker /add`

---

## 📅 Attack Progression & Kill Chain Timeline

The threat actor's actions perfectly reflect the chronological progression of a professional cyber intrusion:

```text
[09:00:01 AM] -- Attack Initiated: Password spray / Brute force begins from 185.220.101.47.
      |
[09:01:55 AM] -- Account Locked: "administrator" account locks out due to invalid attempts (Event 4740).
      |
[09:15:24 AM] -- Account Locked: "john.smith" account locks out (Event 4740).
      |
[10:05:39 AM] -- System Breach: Attacker successfully logs in via Network Logon (Event 4624) as "administrator".
      |
[10:06:10 AM] -- Privilege Escalation: Super-user tokens mapped to the attacker session (Event 4672).
      |
[10:06:45 AM] -- Command Shell Spawned: Interactive cmd.exe created (Event 4688).
      |
[10:07:01 AM] -- Persistence Injection: Rogue account "hacker" created (Event 4688).
      |
[10:07:15 AM] -- Domain Dominance: "hacker" promoted to local Administrators group (Event 4688).
```

---

## ⚖️ Impact Analysis (CIA Triad Assessment)

We have evaluated the scope of damage across the three core security pillars of the **CIA Triad**:

| Security Pillar | Impact Rating | Forensic Reasoning & Observations |
| :--- | :---: | :--- |
| **🔒 Confidentiality** | <span style="color:red">**CRITICAL**</span> | **Compromised.** The adversary acquired Domain Administrator status on `CORP-DC01`. With these credentials, the attacker gained unrestricted access to the Active Directory database (`NTDS.dit`), enabling the extraction of all domain user credentials, hashes, security keys, and corporate intellectual property. |
| **✍️ Integrity** | <span style="color:red">**CRITICAL**</span> | **Compromised.** The adversary successfully altered system configurations. Specifically, they manipulated the system local accounts list by registering a rogue administrative user (`hacker`) and modifying the high-privilege `administrators` group, thereby altering the trust boundary of the entire domain. |
| **⚡ Availability** | <span style="color:orange">**HIGH RISK**</span> | **At High Risk.** Although the logs do not indicate that the attacker shut down services or deleted data, their Domain Admin level access grants them full authority to disable domain authentication, wipe systems, or deploy ransomware across all domain-joined network assets. |

---

## 🛠️ Containment, Remediation & Hardening Roadmap

To contain the compromise and prevent future occurrences, we recommend a multi-phased incident response approach based on the **NIST SP 800-61 Rev. 2** framework:

### ⚠️ Phase 1: Immediate Containment (T = 0)
1. **Network Isolation:** Disconnect `CORP-DC01` from the external internet immediately. Limit internal traffic to emergency administrative VLANs to prevent lateral movement.
2. **Purge Backdoor Account:** Delete the rogue user account `hacker` immediately:
   ```cmd
   net user hacker /delete
   ```
3. **Terminate Sessions:** Kill all active TCP network sessions originating from IP `185.220.101.47` on the Domain Controller.

### 🔑 Phase 2: Credential & Identity Hygiene (T + 2 hours)
1. **Force Global Password Reset:** Force a domain-wide password reset for all Active Directory users, service accounts, and administrative users.
2. **Revoke Active Tickets:** Invalidate all Active Directory Kerberos Ticket Granting Tickets (TGT) to prevent the attacker from utilizing forged tickets (Silver/Golden Ticket attacks).
3. **Enforce Multi-Factor Authentication (MFA):** Mandate MFA for all local and remote administrative connections to Active Directory systems.

### 🌐 Phase 3: Perimeter & Network Security (T + 4 hours)
1. **Blacklist Attacker IP:** Deploy permanent egress and ingress block rules for `185.220.101.47` at the corporate perimeter firewall.
2. **Geographical & Tor Blocking:** Configure firewalls to block all incoming traffic originating from known Tor exit nodes and high-risk VPN subnets.
3. **Disable Remote NTLM:** Disable insecure network authentication protocols (like NTLMv1) and transition entirely to Kerberos.

### 🛡️ Phase 4: Long-Term Architectural Hardening
1. **Transition to Tiered Administration:** Implement a tiered administrative model in Active Directory (Tier 0: Domain Controllers; Tier 1: Servers; Tier 2: Workstations) to restrict admin accounts from logging onto lower-tier devices.
2. **Zero Trust Integration:** Introduce Just-in-Time (JIT) access policies so administrative privileges are granted dynamically and expire automatically.
3. **Advanced SIEM Alerting:** Configure active correlation searches in Splunk to flag process creations (`4688`) containing keywords such as `net localgroup administrators` or `net user`.

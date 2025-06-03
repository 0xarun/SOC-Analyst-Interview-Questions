# SOC Blueprint - Interview & Investigation Guide

A comprehensive guide for SOC analysts covering interview techniques, investigation procedures, and incident reporting templates.

## Table of Contents
- [Interview Response Framework](#interview-response-framework)
- [Technical Investigation Checklist](#technical-investigation-checklist)
- [Reporting Templates](#reporting-templates)
  - [Short Note Template](#short-note-template)
  - [Full Incident Report Template](#full-incident-report-template)

---

## Interview Response Framework

### D.R.I.L. Method for Scenario-Based Questions

Use this structured approach for interview questions like "How do you handle unusual traffic?" or "How do you respond to a ransomware attack?"

| Step | Focus | Example Response |
|------|-------|------------------|
| **D - Detect** | How do you detect or validate the alert? | "First, I validate the alert from SIEM or EDR. I check if it's genuine using logs, process trees, or network patterns." |
| **R - Respond** | What are your immediate containment actions? | "I isolate the host from the network to prevent further damage." |
| **I - Investigate** | What logs, artifacts, or forensics do you check and how? | "I pivot on the source IP, review Sysmon logs (event ID 1, 3), and analyze related commands/processes." |
| **L - Learn & Log** | How do you wrap up, document, and learn from the incident? | "I document everything in a report, extract IOCs, create new detection rules, and share learnings with the team." |

### Interview Script Template

> *"I usually follow a structured flow when investigating: Detect, Respond, Investigate, Learn. First, I validate the alert and understand if it's real. Then I contain the source if needed. Next, I collect all the logs — EDR, Sysmon, firewall — to deeply investigate. Finally, I document all findings, extract IOCs, and update rules to improve detection."*

---

## Technical Investigation Checklist

Use this comprehensive checklist when working in a SOC or home lab environment.

### Core Investigation Areas

| Area | Things to Check | Tools |
|------|-----------------|-------|
| **Validate Alert** | • Check SIEM logs (Splunk, Sentinel)<br>• Confirm alert correlation rules | SIEM |
| **Host Forensics** | • Sysmon Logs (Event IDs 1, 3, 11, 13)<br>• Running processes<br>• Registry entries<br>• File paths | Sysmon, Windows Logs |
| **Process Analysis** | • Command line<br>• Parent-child process<br>• Suspicious binaries (certutil, PowerShell) | EDR, ProcMon |
| **Network Traffic** | • Lateral movement (445, 3389)<br>• External IP connections<br>• Beaconing patterns | Zeek, Suricata, Netstat |
| **Persistence Mechanisms** | • Scheduled Tasks<br>• Registry Run Keys<br>• WMI Event Consumers | Autoruns, Regedit |
| **Malware Analysis** | • File Hashes<br>• Sandbox test<br>• Signature match | Any.Run, HybridAnalysis |
| **Threat Intelligence** | • Known IOCs<br>• MITRE ATT&CK mapping<br>• VirusTotal checks | OTX, VirusTotal |
| **User Activity** | • Logon/logoff history<br>• Failed login attempts<br>• Lateral admin use | Event Logs (4624, 4625) |

---

## Reporting Templates

### Short Note Template

Use this template for low-priority alerts or False Positive/True Positive tracking:

```markdown
**Alert Name:** Lateral Movement via SMB
**Date:** 2025-06-03
**Analyst:** [Your Name]
**Status:** [False Positive / True Positive]

**Summary:**
Received an alert indicating lateral SMB traffic from host 10.1.1.23 to 10.1.1.45.

**Investigation Steps Taken:**
- Validated alert in Splunk
- Checked Sysmon Event ID 3 (network connection)
- Process tied to legitimate IT update process (patch system)

**Conclusion:**
False positive. Legitimate internal patch activity.

**Recommendations:**
- Tuning SIEM to whitelist known IT maintenance IPs
```

### Full Incident Report Template

Use this comprehensive template for confirmed incidents and high-priority alerts:

```markdown
# Incident Report

## 1. Summary
- **Incident Name:** Lateral Malware Spread via PsExec
- **Date & Time Detected:** 2025-06-03 14:00 IST
- **Reported By:** SIEM Alert (Splunk Correlation Rule)
- **Analyst:** [Your Name]
- **Severity:** High
- **Status:** Closed

## 2. Timeline
| Time (IST) | Action |
|------------|--------|
| 14:00 | SIEM alert triggered: SMB traffic from Host-A to Host-B |
| 14:10 | Host-A isolated via Defender ATP |
| 14:30 | Process traced: powershell.exe invoking PsExec |
| 15:00 | Malware hash submitted to VirusTotal - flagged |
| 16:00 | IOC sweep performed across all endpoints |
| 17:00 | 3 infected machines isolated and remediated |

## 3. Technical Analysis
- **Initial Infection Vector:** Likely phishing (user downloaded ZIP)
- **Tools Used by Attacker:** PsExec, SMB, RDP
- **Persistence Methods:** Scheduled task + registry Run key
- **C2 Communication:** Detected via abnormal DNS requests (beaconing)
- **Lateral Movement:** PsExec from 10.1.1.23 to 10.1.1.45, 10.1.1.51

## 4. IOCs
| Type | Value |
|------|-------|
| File Hash | `d41d8cd98f00b204e9800998ecf8427e` |
| Domain | `evil-domain.com` |
| IP Address | `45.76.23.198` |
| File Name | `invoice.exe` |

## 5. Impact
- 3 endpoints affected
- No critical data loss
- No exfiltration detected

## 6. Mitigation & Response
- Blocked PsExec via GPO
- Added hash to EDR blocklist
- Reset local admin passwords
- Patched vulnerable services

## 7. Lessons Learned
- Improve attachment sandboxing
- Review SMB access policies
- Continuous hunt for lateral movement patterns

## 8. Recommendations
- Enforce stricter email filtering
- Enable LSA protection on endpoints
- Use tiered admin accounts for RDP
```

---

## Quick Reference

### Key Sysmon Event IDs
- **Event ID 1:** Process creation
- **Event ID 3:** Network connection
- **Event ID 11:** File create
- **Event ID 13:** Registry value set

### Common Attack Vectors to Monitor
- **Lateral Movement Ports:** 445 (SMB), 3389 (RDP)
- **Suspicious Processes:** certutil, PowerShell, PsExec
- **Persistence Locations:** Registry Run Keys, Scheduled Tasks, WMI Event Consumers

### Essential Log Sources
- **Windows Event Logs:** 4624 (Logon), 4625 (Failed Logon)
- **Sysmon Logs:** Process and network activity
- **EDR Logs:** Endpoint detection and response data
- **Network Logs:** Firewall, DNS, proxy logs

---

*This blueprint serves as a practical guide for SOC analysts in both interview scenarios and real-world incident response situations.*

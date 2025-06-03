# SOC Analyst Interview Questions & Answers

## Table of Contents
- [Role & Responsibilities](#role--responsibilities)
- [Technical Fundamentals](#technical-fundamentals)
- [Network Security](#network-security)
- [Email Analysis](#email-analysis)
- [Incident Response](#incident-response)
- [Malware Analysis](#malware-analysis)
- [Active Directory & Authentication](#active-directory--authentication)
- [SIEM & Detection](#siem--detection)
- [Threat Intelligence & Frameworks](#threat-intelligence--frameworks)
- [Cloud Security](#cloud-security)
- [Scenario-Based Questions](#scenario-based-questions)

---

## Role & Responsibilities

### 1. Walk me through your day-to-day roles and responsibilities.
As a SOC Analyst, my day starts with reviewing SIEM dashboards for any critical alerts from overnight. I triage alerts based on priority—phishing, malware, login anomalies, etc.—and perform initial investigation using tools like EDR, threat intel platforms, and network logs. I document findings, escalate confirmed incidents, and update tickets. I also handle email investigations, monitor threat intel feeds for emerging IOCs, fine-tune detection rules, and participate in incident response when needed.

### 2. What's the purpose of Tier 1 analysts?
Tier 1 analysts are the first line of defense in the SOC. We monitor alerts, triage incidents, escalate real threats to Tier 2 or 3, and do basic investigations like log reviews or threat intel lookups.

---

## Technical Fundamentals

### 3. What is the CIA triad?
CIA stands for:
- **Confidentiality** – keeping data private
- **Integrity** – making sure data isn't altered
- **Availability** – making sure services and data are accessible when needed

### 4. How is authentication different from authorization?
- **Authentication** is verifying who the user is (e.g., via username/password)
- **Authorization** is verifying what the user is allowed to do (like accessing admin features)

### 5. What is the principle of least privilege, and how do you implement it?
Granting users only the minimum level of access needed to perform their job functions, essentially minimizing the potential damage caused by a security breach by limiting unnecessary permissions. Implementation involves defining user roles, assigning specific access based on those roles, and regularly reviewing and updating access policies.

### 6. What is the difference between a risk, a vulnerability, and a threat?
- **Risk** = the potential for loss or damage (combination of threat and vulnerability)
- **Vulnerability** = a weakness, like unpatched software
- **Threat** = an actor or event that exploits a vulnerability, like malware or a hacker

### 7. What is the difference between encoding, encryption and hashing?
- **Encoding** is a technique where data is transformed from one form to another (ASCII, BASE64)
- **Encryption** is encoding using an encryption algorithm so only authorized persons can access information (RSA, AES, DES)
- **Hashing** is converting data into a fixed-size string using a hash function (MD5, SHA256)

### 8. What is the OSI layer?
The OSI Model is a 7-layer framework for understanding network communication:
1. Physical
2. Data Link
3. Network
4. Transport
5. Session
6. Presentation
7. Application

### 9. What are the attacks that can happen in each OSI layer?
- **Physical** – Cable tapping, device theft
- **Data Link** – MAC spoofing, ARP poisoning
- **Network** – IP spoofing, DoS, routing attacks
- **Transport** – SYN flooding, port scanning
- **Session** – Session hijacking
- **Presentation** – SSL stripping, encoding abuse
- **Application** – XSS, SQL Injection, CSRF, RCE

### 10. What is Three Way Handshake?
The TCP three-way handshake establishes a reliable connection:
1. **SYN**: Client sends SYN packet with initial sequence number
2. **SYN-ACK**: Server replies with SYN-ACK, acknowledging client's ISN and including its own
3. **ACK**: Client sends final ACK, acknowledging server's ISN

---

## Network Security

### 11. Explain the difference between IDS and IPS. When would you use one over the other?
- **IDS** (Intrusion Detection System) only detects threats and sends alerts
- **IPS** (Intrusion Prevention System) can both detect and prevent threats in real-time
- Use IDS for monitoring and alerting; use IPS when you need active blocking capabilities

### 12. How does a firewall work, and what are its limitations?
Firewalls monitor and filter network traffic based on pre-defined rules, acting as a barrier between private networks and the internet. Limitations include inability to protect against sophisticated attacks, insider threats, user negligence, and potential performance impact.

### 13. What is network segmentation and how is it helpful?
Network segmentation divides a network into smaller zones to reduce lateral movement. If one part is compromised, attackers can't easily move to other segments. It helps contain breaches and limit blast radius.

### 14. What are some common network protocols and why are they important?
- **HTTP/HTTPS** – web traffic
- **DNS** – domain name resolution
- **SMTP** – email
- **RDP/SSH** – remote access
Understanding these helps identify normal traffic patterns and detect misuse.

### 15. How does DNS work, and what are some common DNS-based attacks?
DNS translates domain names to IP addresses through a recursive query process involving root servers, TLD servers, and authoritative servers.

Common attacks:
- DNS hijacking (redirecting to malicious sites)
- DNS cache poisoning (storing incorrect IP addresses)
- DNS amplification attacks (overwhelming targets with traffic)
- DNS tunneling (hiding malicious activity in DNS queries)

### 16. What port number does ping use?
Ping uses ICMP (Internet Control Message Protocol), which doesn't rely on port numbers. ICMP is a network-layer protocol for sending error messages and operational information.

### 17. What is DHCP?
DHCP (Dynamic Host Configuration Protocol) assigns IP addresses and network configuration parameters automatically to devices, allowing communication without manual configuration.

### 18. How does SSL/TLS ensure secure communication?
SSL/TLS ensures secure communication through encryption, authentication, and digital signatures to scramble data in transit, verify party identities, and guarantee data integrity.

---

## Email Analysis

### 19. What is the return path in an email header?
The return path is an SMTP header indicating where bounce-back messages (delivery failures) should be sent. It's different from the "From" address and can help detect spoofing.

### 20. What is bounce-back?
A bounce-back is a message automatically sent by a mail server when an email cannot be delivered, including error codes and reasons like invalid recipient, spam filters, or server issues.

### 21. How does email travel on the internet?
Email travels from sender's client to their SMTP server, then to recipient's SMTP server using DNS MX record resolution. The recipient's server forwards it to their mailbox, accessed via IMAP or POP3.

### 22. How do you triage a phishing email?
1. Analyze email headers (Return-Path, SPF/DKIM/DMARC)
2. Inspect links and attachments in a sandbox
3. Check sender domain reputation
4. Extract and search IOCs (URLs, hashes, IPs)
5. Identify affected users and check for engagement
6. Quarantine or remove email if malicious
7. Document findings and raise incident if needed

---

## Incident Response

### 23. Describe an incident response process.
1. **Preparation** – setting up tools, playbooks, and training
2. **Identification** – detecting that an incident occurred
3. **Containment** – limiting damage by isolating affected systems
4. **Eradication** – removing root cause like malware or compromised accounts
5. **Recovery** – restoring systems and monitoring for issues
6. **Lessons Learned** – documenting incident and improving defenses

### 24. What stakeholders are important to include during an incident? Why are they important?
- **IT Team** – help isolate systems
- **Legal** – compliance and breach reporting
- **Management** – business-level decisions
- **HR** – if insider threats are involved
- **PR/Communications** – if public disclosure is required

They're important because effective response needs both technical and business coordination.

### 25. After an incident, why is it important to do a lessons learned?
It helps understand what went wrong, what worked, and what needs improvement. It prevents the same issue from recurring and improves detection and response playbooks.

### 26. What is the difference between a security event and a security incident?
- **Security event** is any observable occurrence (user login, port scan)
- **Security incident** is when an event turns out malicious or causes harm (data exfiltration, ransomware)

### 27. How do you escalate a critical incident?
1. Validate and classify the alert
2. Check blast radius and affected systems
3. Gather evidence (logs, PCAP, EDR data)
4. Notify team lead/IR team with timeline and risk level
5. Escalate through proper communication channels
6. Document all actions and assist in containment

---

## Malware Analysis

### 28. Walk me through any recent successful malware attack.
Black Basta ransomware attack on Ascension hospitals: Attackers used QakBot for initial access, then Cobalt Strike and remote management tools for lateral movement. Data was encrypted and exfiltrated, causing major healthcare disruption.

### 29. How does ransomware work in an environment?
Ransomware enters through phishing, drive-by downloads, or RDP brute force. It establishes persistence, performs privilege escalation, encrypts files using symmetric/asymmetric encryption, drops ransom notes demanding cryptocurrency payment. Modern strains may exfiltrate data for double extortion.

### 30. Explain malware behavior.
Malware may exhibit:
- Creating/modifying registry keys (persistence)
- Dropping malicious executables
- Establishing C2 communication (DNS, HTTP/S)
- Disabling security tools/processes
- Lateral network spreading
- Process injection (hollowing, DLL injection)

### 31. How do you triage a malware-related alert?
1. Validate alert source and hash
2. Search hash in EDR and threat intel platforms
3. Analyze execution tree (parent-child process)
4. Check persistence mechanisms (registry, scheduled tasks)
5. Look for lateral movement or dropped files
6. Isolate device, collect memory/disk if needed
7. Escalate or remediate based on impact

### 32. What are some methods or tools you might use to identify a worm on the network?
- NetFlow or Zeek logs to detect traffic spreading from one host to many
- EDR tools to check for file replication
- SIEM queries to spot brute-force or exploit attempts across systems
- VirusTotal/hash lookups for known malware samples

---

## Active Directory & Authentication

### 33. What is KRBTGT account?
KRBTGT is a default Active Directory account used by Kerberos authentication service to encrypt and sign all Kerberos tickets. It acts as the trust anchor for issuing and validating TGTs (Ticket Granting Tickets).

### 34. What is a Golden Ticket?
A Golden Ticket is a forged Kerberos TGT created by attackers who compromised the KRBTGT account. It gives unrestricted access to any domain system or service, often undetected.

### 35. How do you remediate if the KRBTGT account got compromised?
Reset the KRBTGT password twice with a wait period (~10 hours) between resets for Kerberos ticket lifetime to expire. This invalidates existing TGTs, including forged ones, with minimal disruption.

### 36. What is Kerberos and NTLM?
- **Kerberos** is a ticket-based authentication protocol using a trusted third party (KDC), more secure and default in modern Windows
- **NTLM** is an older challenge-response protocol used when Kerberos fails, susceptible to pass-the-hash and relay attacks

### 37. What is the difference between interactive and non-interactive logon?
- **Interactive logon**: User logs in physically or via RDP (Logon Type 2 or 10)
- **Non-interactive logon**: System/service uses credentials in background (scheduled task/network logon – Type 3 or 4)

### 38. What are conditional access policies?
Conditional Access Policies in Azure AD enforce access controls based on user, location, device status, or risk level. Example: requiring MFA from unknown locations or blocking legacy authentication methods.

---

## SIEM & Detection

### 39. What is a SIEM?
SIEM (Security Information and Event Management) collects and correlates logs from various sources (firewalls, endpoints, servers) to provide real-time alerts and help detect, investigate, and respond to security incidents.

### 40. What is the purpose of a SIEM, and how do you investigate an alert in it?
SIEM collects, analyzes, and correlates security logs to identify potential threats by detecting unusual patterns. Investigation involves reviewing related log entries, analyzing event context, cross-checking with other security data sources, and determining if activity is malicious.

### 41. What are some common detection tools that may report security issues and how do they work?
- **EDR tools** (SentinelOne, CrowdStrike) – monitor endpoint behavior and detect anomalies
- **SIEMs** (Splunk) – correlate logs and generate alerts
- **Suricata/Snort** – detect network intrusions
- **Sysmon** – deep Windows event logging

They work by setting detection rules and alerting on known attack patterns or anomalies.

### 42. What is Workspace?
In security tools like Microsoft Sentinel, a workspace is an isolated container where logs are stored, analyzed, and queried using KQL. It's the environment where data ingestion and rule-based detection happens.

### 43. What is Playbook?
A playbook is automated actions triggered by alerts, used in SOAR platforms like Sentinel or Cortex XSOAR. Example: phishing playbook extracts IOCs, checks threat intel, and auto-quarantines emails.

### 44. Where to write and view rule logic?
In tools like Sentinel, rule logic is written in the Analytics blade using KQL (Kusto Query Language). You define detection criteria, set thresholds, alert frequency, and attach playbooks for automation.

### 45. Write a KQL to view a desired column.
```kql
DeviceLogonEvents
| project TimeGenerated, AccountName, DeviceName
```

### 46. Write a KQL for any use case (e.g., Windows logon failures).
```kql
DeviceLogonEvents
| where LogonType == "2" and ActionType == "LogonFailed"
| summarize count() by AccountName, bin(TimeGenerated, 1h)
| order by count_ desc
```

### 47. How do you search for a specific file or hash in an EDR tool?
In EDR tools like Microsoft Defender or CrowdStrike, search using:
- File hash (SHA256/SHA1/MD5)
- File path or name
- Parent process ID or command line
Then investigate device timeline for file behavior, execution, network activity, and process chains.

### 48. Difference between device events and device file events.
- **Device events** refer to system-level activities (logons, network connections, registry changes)
- **Device file events** are specific to file activities (creation, modification, deletion, execution)

### 49. What is Syslog?
Syslog is a standard protocol for sending system logs or event messages to a central logging server, widely used in Linux and network devices for log collection.

---

## Threat Intelligence & Frameworks

### 50. What are indicators of compromise (IOCs)?
IOCs are forensic data pieces suggesting system compromise, including suspicious IP addresses, unusual file hashes, unexpected domain names, or irregular login patterns. They help detect and trace malicious activity during investigations.

### 51. Difference between Cyber Kill Chain and MITRE Framework?
- **Cyber Kill Chain** is a linear Lockheed Martin model with seven attack phases: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives
- **MITRE ATT&CK** is a detailed, non-linear matrix mapping adversary TTPs observed in real-world attacks, providing more granularity for detection and threat hunting

### 52. What is the ATT&CK framework?
MITRE ATT&CK is a knowledge base of real-world attack techniques used by threat actors. It helps map attack stages from Initial Access to Exfiltration, useful for detection engineering and threat hunting.

### 53. What is the CVE database and how is it helpful?
CVE (Common Vulnerabilities and Exposures) is a public database listing known vulnerabilities with unique IDs. It helps stay updated on critical vulnerabilities and assess system impact.

### 54. Are you updated with the recent cyber trends?
Yes, I follow threat intel feeds like Mandiant, The DFIR Report, and cybersecurity researchers on Twitter/X. I stay informed about new CVEs, malware campaigns, and APT tactics through ATT&CK, Reddit, and BleepingComputer.

### 55. What is an Advanced Persistent Threat (APT) and how might you identify one?
APT is a stealthy, targeted attack usually from nation-states or organized groups that maintains long-term system presence. Identify through signs like beaconing, legitimate tool usage (PowerShell, PsExec), and unusual lateral movement.

---

## Cloud Security

### 56. How do cloud applications affect the security of the customer environment?
Cloud applications increase attack surface. Misconfigured S3 buckets or exposed APIs can cause data leaks. Logs and controls are in cloud provider hands, making visibility and monitoring more complex.

### 57. How would you approach a misconfigured S3 bucket exposing sensitive data?
1. Immediately restrict bucket access by changing permissions to block public access
2. Conduct thorough analysis of exposed data to determine sensitivity and impact
3. Initiate mitigation steps like data encryption and access control updates

---

## Scenario-Based Questions

### 58. What is account enumeration? And if you observe account enumeration, what will you do?
Account enumeration is when attackers try discovering valid usernames through login portals or error messages.

Response actions:
1. Correlate logs to find source IP and time range
2. Check for brute-force or spray patterns
3. Block source at firewall or identity provider level
4. Notify IT/security for password resets if needed
5. Implement login failure obfuscation (generic error messages)

### 59. You are observing multiple account lockout events from an account but no anomalies found in the logs, what could be the reason and how do you troubleshoot?
Possible causes:
- Stale credentials in mapped drives, services, or scheduled tasks
- Cached credentials on another machine
- Mobile device syncing with outdated password

Troubleshooting:
1. Check domain controller logs for source machines
2. Use Event ID 4740 and correlate with logon/logoff times
3. Interview user for device changes
4. Remove and re-add affected services with correct credentials

### 60. How do you investigate an unfamiliar sign-in properties alert?
1. Check sign-in location, device, browser, and IP reputation
2. Correlate with user activity logs (logon type, device ID)
3. Investigate geolocation anomalies or impossible travel
4. Use threat intel on IP, ASN, and verify with user
5. If suspicious, force password reset and monitor account activity

### 61. Explain a difficult situation you faced in your current organization and how it was resolved.
During a ransomware simulation, EDR alerts spiked and we suspected a live attack. I coordinated with the IR team, quickly isolated affected endpoints, and began triaging alerts. It turned out to be a red team exercise with poor prior notice. Despite confusion, we followed playbooks, maintained clear communication, and used the opportunity to refine our escalation process and alert tuning.

---

*This guide covers essential SOC Analyst interview topics. Practice these scenarios and stay updated with current threat landscape for successful interviews.*

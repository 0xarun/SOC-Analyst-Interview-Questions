# SOC L1 Analyst Field Guide: Common Alert Scenarios

## Table of Contents
1. [True Positive vs False Positive - The Basics](#tp-vs-fp)
2. [Common Alert Scenarios](#common-scenarios)
3. [Investigation Checklist](#investigation-checklist)
4. [Escalation Decision Tree](#escalation-tree)
5. [Documentation Best Practices](#documentation)
6. [Quick Reference Tables](#quick-reference)

---

## True Positive vs False Positive - The Basics {#tp-vs-fp}

### True Positive (TP)
- **Definition**: Alert correctly identified a real security threat or policy violation
- **Action Required**: Investigate, contain, remediate, escalate
- **Examples**: Actual malware, confirmed phishing, unauthorized access, data exfiltration

### False Positive (FP)
- **Definition**: Alert triggered but there's NO real security threat
- **Action Required**: Document findings, close ticket, consider tuning rule
- **Examples**: Legitimate business tools, authorized testing, misconfigured rules

### Key Question to Ask Yourself:
> "Is there actual harm or risk to the organization?"
> - YES → Likely True Positive
> - NO → Likely False Positive
> - UNSURE → Investigate deeper or escalate

---

## Common Alert Scenarios {#common-scenarios}

### 1. Email Security Alerts

#### Scenario A: Suspicious Email Attachment
**Alert**: "Malicious attachment detected - .ps1/.exe/.zip file"

**Investigation Steps**:
1. Check sender:
   - Internal or external?
   - Known contact or random?
   - Domain reputation (use VirusTotal, MXToolbox)

2. Check recipient:
   - Was this expected?
   - What's their role? (IT, Finance, HR get different files)
   - Multiple recipients or targeted?

3. Analyze attachment:
   - File hash check (VirusTotal, Hybrid Analysis)
   - File name (generic like "invoice.exe" = suspicious)
   - Sandbox analysis if available

4. Check email content:
   - Urgency language? ("ACT NOW", "URGENT")
   - Grammar/spelling errors?
   - Matches sender's usual communication?

**True Positive Indicators**:
- Unknown external sender with executable
- Suspicious hash (malware detected on VT)
- Phishing language in email body
- Spoofed sender address
- User didn't expect this file

**False Positive Indicators**:
- Internal IT sharing legitimate scripts
- Known vendor sending regular files
- Clean hash, known good software
- Part of expected business workflow

**Decision**:
- **TP + High Priority**: External executable from unknown sender → Escalate immediately
- **TP + Medium**: Suspicious but not confirmed malware → Escalate with findings
- **FP**: Internal IT script with clean hash → Close as FP, document

---

#### Scenario B: Missing SPF/DKIM/DMARC
**Alert**: "Email failed authentication - No DMARC/DKIM"

**Investigation Steps**:
1. Check email authentication:
   - SPF: Pass/Fail/Neutral?
   - DKIM: Present or missing?
   - DMARC: What's the policy?

2. Analyze sender domain:
   - Legitimate business domain?
   - Newly registered? (check WHOIS)
   - Similar to known domain? (typosquatting)

3. Email content review:
   - Any links? (check URLs in URLscan.io)
   - Attachments?
   - Subject line (impersonation attempt?)
   - Body content (requests for action?)

4. Context check:
   - First time receiving from this domain?
   - Recipient's role (Finance/HR = high risk)
   - Similar emails to other users?

**True Positive Indicators**:
- Impersonation attempt (looks like CEO/vendor)
- Requests for money transfer/credentials
- Malicious links or attachments
- Domain registered recently (<30 days)
- Multiple red flags combined

**False Positive Indicators**:
- Legitimate business domain with poor email security
- Newsletter/marketing email from known company
- No malicious content, just missing auth records
- Expected communication from the sender

**Decision**:
- **TP**: Impersonation + urgency + requests action → Block email, escalate
- **FP but report**: Legit company with no DMARC → Close FP, note to IT to contact them
- **FP**: Marketing email from known sender → Close as FP

---

### 2. Endpoint Security Alerts

#### Scenario C: Suspicious Process Execution
**Alert**: "Uncommon process executed - powershell.exe with encoded command"

**Investigation Steps**:
1. Identify the process:
   - Process name and path
   - Parent process (what launched it?)
   - Command line arguments
   - User account running it

2. Check the host:
   - User's role (IT admin or regular user?)
   - Recent login activity
   - Other alerts on this host?
   - Known software on the system?

3. Analyze the command:
   - Encoded/obfuscated? (Base64 = suspicious)
   - What does it do? (decode if encoded)
   - Network connections initiated?
   - File modifications?

4. Timeline analysis:
   - When did this run?
   - Business hours or off-hours?
   - Triggered by user action or scheduled?

**True Positive Indicators**:
- Encoded PowerShell from non-IT user
- Downloads files from internet
- Disables security tools
- Creates persistence mechanisms
- Off-hours execution on regular user account
- Multiple suspicious behaviors chained

**False Positive Indicators**:
- IT admin account running scripts
- Known software update process
- Scheduled task during maintenance window
- Part of documented automation

**Decision**:
- **TP + Critical**: Encoded PowerShell downloading malware → Isolate host, escalate immediately
- **TP + High**: Suspicious script on regular user → Escalate with details
- **FP**: IT admin running documented maintenance → Close as FP, verify with IT if needed

---

#### Scenario D: Unauthorized Software Installation
**Alert**: "New software installed - TeamViewer/AnyDesk/Chrome Remote Desktop"

**Investigation Steps**:
1. Verify the software:
   - What was installed?
   - Installation path (legitimate location?)
   - Digital signature valid?
   - Version (latest or old/vulnerable?)

2. Check who installed it:
   - User account details
   - User's role and access level
   - Recent tickets/requests for this software?
   - User contacted about this?

3. Review activity:
   - Was it used immediately after install?
   - Any network connections established?
   - Files accessed/transferred?
   - Other suspicious activity on the host?

4. Policy check:
   - Is this software allowed?
   - Does user have approval?
   - IT ticket for installation?

**True Positive Indicators**:
- Remote access tool installed by regular user
- No IT ticket/approval
- Immediate connection to external IP
- User claims they didn't install it
- Paired with other suspicious activity

**False Positive Indicators**:
- IT support installed with ticket number
- Part of approved software list
- User requested and got approval
- Installation during scheduled maintenance

**Decision**:
- **TP + Critical**: Unauthorized remote tool used immediately → Isolate, escalate
- **TP + Medium**: Installed without approval → Escalate to verify
- **FP**: IT installed with ticket → Close as FP, reference ticket

---

### 3. Network Security Alerts

#### Scenario E: Connection to Suspicious IP/Domain
**Alert**: "Outbound connection to known malicious IP"

**Investigation Steps**:
1. Identify the connection:
   - Source: Which host?
   - Destination: IP/Domain and port
   - Protocol used
   - Amount of data transferred
   - Timestamp and duration

2. Check threat intelligence:
   - IP reputation (AbuseIPDB, VirusTotal)
   - Domain reputation (if applicable)
   - Category (C2, malware, phishing, etc.)
   - When was it categorized as malicious?

3. Investigate the source host:
   - What process initiated connection?
   - User logged in at the time?
   - Any malware detections?
   - Recent suspicious activity?

4. Determine causation:
   - User clicked a link?
   - Malware infection?
   - Legitimate site compromised?
   - Advertising/tracking network?

**True Positive Indicators**:
- Connection to known C2 server
- Large data transfer outbound (exfiltration)
- Process: Unknown malware executable
- No user interaction (automatic behavior)
- Host shows other compromise indicators

**False Positive Indicators**:
- IP recently categorized (legitimate site compromised)
- Ad network flagged temporarily
- Single connection, no data transfer
- Known false positive in threat feed
- CDN or cloud service misclassified

**Decision**:
- **TP + Critical**: C2 connection with data transfer → Isolate immediately, escalate
- **TP + High**: Confirmed malicious, investigating infection → Escalate
- **Uncertain**: Check with user, review → Escalate if suspicious
- **FP**: Known false positive from threat feed → Close as FP, note in ticket

---

#### Scenario F: Excessive Failed Login Attempts
**Alert**: "Multiple failed login attempts - Account: jsmith"

**Investigation Steps**:
1. Review login details:
   - How many attempts?
   - Time window (1 hour vs 1 day matters)
   - Source IP addresses
   - Successful login eventually?

2. Check the source:
   - Internal or external IPs?
   - Geographic location (expected?)
   - Single IP or multiple?
   - Reputation of IPs

3. Contact the user:
   - Were they trying to login?
   - Forgot password?
   - On vacation/out of office?
   - Notice anything suspicious?

4. Account context:
   - Account type (admin, regular, service)
   - Recent password changes?
   - Account lockout triggered?
   - Similar activity on other accounts?

**True Positive Indicators**:
- External IP from unexpected country
- User denies login attempts
- Privileged account targeted
- Successful login after many failures
- Multiple accounts targeted (spray attack)
- Off-hours attempts

**False Positive Indicators**:
- User forgot password, tried multiple times
- Known IP (user's home/mobile)
- Service account with expired password
- Application misconfiguration
- User admits it was them

**Decision**:
- **TP + Critical**: Successful login after failures from foreign IP → Reset password, escalate
- **TP + High**: Spray attack on multiple accounts → Escalate, monitor
- **Medium**: User denies but no success → Reset password, escalate if continues
- **FP**: User forgot password → Close as FP, remind about password reset process

---

### 4. Web Security Alerts

#### Scenario G: User Visited Malicious Website
**Alert**: "Web filter blocked access to malicious site"

**Investigation Steps**:
1. Analyze the blocked site:
   - Full URL and domain
   - Category (malware, phishing, C2, etc.)
   - Reputation score
   - How recent is the classification?

2. Understand how user got there:
   - Direct navigation (typed URL)?
   - Clicked email link?
   - Redirect from legitimate site?
   - Ad/pop-up?

3. Check if successful:
   - Was access blocked successfully?
   - Any data entered before block?
   - Multiple attempts to access?
   - User tried to bypass?

4. Host examination:
   - Run endpoint scan
   - Check browser history
   - Look for malware indicators
   - Recent downloads?

**True Positive Indicators**:
- User clicked phishing link
- Attempted credential entry
- Multiple access attempts
- Part of targeted attack
- Host shows infection signs

**False Positive Indicators**:
- Accidental click on ad
- Legitimate site recently compromised
- Single blocked attempt, user stopped
- Redirect they didn't control
- URL shortener leading to legit site

**Decision**:
- **TP + High**: Phishing attempt, user entered data → Reset credentials, escalate
- **TP + Medium**: Clicked malicious link but blocked → Scan host, user education
- **FP**: Accidental click, immediately stopped → Close as FP, quick user reminder

---

### 5. DLP (Data Loss Prevention) Alerts

#### Scenario H: Sensitive Data Sent Externally
**Alert**: "PII/Credit card data sent to external email"

**Investigation Steps**:
1. Review the data:
   - What type? (PII, credit cards, passwords, IP)
   - How much data?
   - Actual sensitive info or false trigger?
   - Review actual content (if allowed)

2. Check sender:
   - Who sent it?
   - Their role (authorized to handle this data?)
   - Job function requires this?
   - History of similar activity?

3. Review recipient:
   - External email domain
   - Known partner/vendor?
   - Personal email address?
   - First time communication?

4. Context matters:
   - Business justification?
   - Ticket/approval for data transfer?
   - Part of normal workflow?
   - User contacted for explanation?

**True Positive Indicators**:
- Data sent to personal email
- No business justification
- User can't explain why
- Large volume of records
- Resignation/termination pending
- Outside business hours

**False Positive Indicators**:
- Sent to known vendor with contract
- Part of approved business process
- Test data, not real PII
- DLP rule triggered incorrectly
- User has valid explanation

**Decision**:
- **TP + Critical**: Mass data exfil to personal email → Block, escalate immediately
- **TP + High**: Unauthorized data transfer → Escalate for review
- **Medium**: Needs verification → Contact user, escalate if no valid reason
- **FP**: Legitimate business need with approval → Close as FP, document

---

## Investigation Checklist {#investigation-checklist}

### Universal Questions for ANY Alert

**Basic Information**:
- [ ] What exactly triggered the alert?
- [ ] When did it happen? (Date/time/timezone)
- [ ] Who was involved? (User/system/service)
- [ ] Where did it happen? (Host/network/location)
- [ ] What was the outcome? (Blocked/Allowed/Partial)

**Context Gathering**:
- [ ] Is this normal behavior for this user/system?
- [ ] Any recent changes? (New software/policy/user role)
- [ ] Similar alerts recently?
- [ ] Business context? (Time of day/project/deadline)
- [ ] User contacted? What did they say?

**Technical Analysis**:
- [ ] Threat intelligence lookup
- [ ] Hash/URL/IP reputation check
- [ ] Timeline of events
- [ ] Related alerts or activity
- [ ] Indicators of Compromise (IOCs)

**Risk Assessment**:
- [ ] What's the potential impact?
- [ ] Is data at risk?
- [ ] Are systems compromised?
- [ ] Could this spread?
- [ ] What assets are affected?

**Decision Factors**:
- [ ] Confidence level in findings (High/Medium/Low)
- [ ] Evidence collected
- [ ] Company policy considerations
- [ ] Need for escalation?
- [ ] Immediate actions needed?

---

## Escalation Decision Tree {#escalation-tree}

### 🔴 ESCALATE IMMEDIATELY (Critical)

**Confirmed Security Incidents**:
- Active malware infection spreading
- Ransomware detected
- Data exfiltration in progress
- Compromised privileged accounts
- Active intrusion/unauthorized access
- C2 communication confirmed
- Successful phishing with credential entry

**High-Value Targets**:
- Executive/C-level accounts compromised
- Domain admin credentials at risk
- Critical infrastructure affected
- Financial systems targeted

**Action**: Call/IM your senior analyst NOW. Don't just ticket it.

---

### 🟡 ESCALATE (High Priority)

**Suspicious but Needs Expert Review**:
- Potential compromise indicators
- Unclear if legitimate or malicious
- Multiple weak indicators together
- User can't explain suspicious activity
- Pattern suggests attack but not confirmed
- Policy violation with unclear intent

**Sensitive Scenarios**:
- DLP incidents involving executive data
- Potential insider threat indicators
- Repeated policy violations
- Unusual admin activity

**Action**: Create escalation ticket with all findings. Tag L2/senior.

---

### 🟢 HANDLE & CLOSE (You Got This)

**Clear False Positives**:
- Verified legitimate business activity
- Known good software behavior
- Authorized testing/maintenance
- Misconfigured rule (document for tuning)
- User explanation makes sense

**Low-Risk True Positives**:
- Successfully blocked threat
- No user interaction occurred
- Single blocked connection to bad site
- Email quarantined before delivery
- User education needed only

**Action**: Document thoroughly, close ticket, user follow-up if needed.

---

### 🤔 UNSURE? Default: ESCALATE

**When in Doubt**:
- Not confident in your assessment
- First time seeing this type of alert
- Conflicting indicators
- Gut feeling something's off
- Limited information available

**It's ALWAYS better to escalate as a junior analyst than to miss a real incident.**

---

## Documentation Best Practices {#documentation}

### What to Document in Every Ticket

**1. Alert Summary**
```
Alert Type: [Email Security / Endpoint / Network / etc.]
Severity: [Critical / High / Medium / Low]
Triggered: [Date/Time]
Source: [User/Host/IP]
Status: [TP / FP / Escalated]
```

**2. Investigation Timeline**
```
[Timestamp] - Alert received
[Timestamp] - Started investigation
[Timestamp] - Contacted user (if applicable)
[Timestamp] - Checked threat intel
[Timestamp] - Completed analysis
[Timestamp] - Escalated / Closed
```

**3. Findings**
- What you discovered
- Evidence collected (hashes, IPs, URLs)
- Threat intel results
- User statement (if contacted)
- Related alerts or patterns

**4. Analysis**
- Why you classified it as TP/FP
- Risk level justification
- Business impact assessment
- Supporting evidence

**5. Actions Taken**
- What did you do?
- User contacted? Response?
- Blocks implemented?
- Scans run?
- Who did you escalate to?

**6. Recommendations**
- Next steps
- Prevention measures
- Rule tuning needed?
- User training required?

### Example Good Documentation

```
TICKET #12345: Suspicious Email with Attachment

SUMMARY:
Alert Type: Email Security - Malicious Attachment
Severity: High
Triggered: 2025-10-16 14:32 UTC
User: jdoe@company.com
Status: TRUE POSITIVE - ESCALATED

INVESTIGATION:
[14:35] Alert review started
[14:37] Sender: external - accounting@compamy.com (note typo)
[14:40] Attachment hash checked on VT: 3/68 vendors flagged
[14:42] Email subject: "Urgent Invoice Payment Required"
[14:45] Contacted user - claims not expecting invoice
[14:48] Checked similar emails - 12 other users received same
[14:50] Email quarantined across organization

FINDINGS:
- Spoofed sender domain (compamy.com vs company.com - typosquatting)
- Attachment: Invoice_Oct.exe (1.2MB)
- VT Hash: 3 vendors detect as suspicious
- Phishing language: urgency, payment request
- No legitimate business relationship
- Mass targeted attack (13 users total)

ANALYSIS:
TRUE POSITIVE - Phishing campaign
- External attacker using typosquatted domain
- Executable disguised as document
- Mass targeted (credential harvesting likely)
- Urgency tactics used
- No user interaction confirmed

ACTIONS TAKEN:
- Quarantined email for all recipients
- Blocked sender domain at gateway
- Added hash to blocklist
- Contacted all 13 recipients (no one opened attachment)
- Submitted hash to threat intel team

ESCALATION:
Escalated to L2 (ticket #12346) for:
- Further malware analysis
- Review of email gateway rules
- Company-wide notification
- Domain blocking strategy

RECOMMENDATIONS:
- User education on typosquatting
- Enhanced email filtering for .exe attachments
- Monitor for similar domains
```

---

## Quick Reference Tables {#quick-reference}

### Common File Extensions Risk Levels

| Extension | Risk Level | Notes |
|-----------|-----------|-------|
| .exe, .msi, .bat, .cmd | 🔴 HIGH | Direct executables |
| .ps1, .vbs, .js | 🔴 HIGH | Script files, often obfuscated |
| .scr, .com, .pif | 🔴 HIGH | Less common executables |
| .zip, .rar, .7z | 🟡 MEDIUM | Need to check contents |
| .iso, .img | 🟡 MEDIUM | Disk images, check purpose |
| .dll, .sys | 🟡 MEDIUM | System files, unusual in email |
| .doc, .xls, .pdf | 🟡 MEDIUM | Can contain macros/exploits |
| .docx, .xlsx, .pptx | 🟢 LOW | Safer modern formats |
| .txt, .jpg, .png | 🟢 LOW | Generally safe |

---

### Threat Intelligence Sources (Quick Checks)

| Resource | What to Check | URL |
|----------|---------------|-----|
| VirusTotal | Files, URLs, IPs, Domains | virustotal.com |
| AbuseIPDB | IP reputation | abuseipdb.com |
| URLhaus | Malicious URLs | urlhaus.abuse.ch |
| URLscan.io | URL analysis & screenshots | urlscan.io |
| MXToolbox | Email headers, domains | mxtoolbox.com |
| Hybrid Analysis | Malware sandbox | hybrid-analysis.com |
| Talos Intelligence | IP/Domain reputation | talosintelligence.com |
| AlienVault OTX | Threat intelligence | otx.alienvault.com |

---

### Common Indicators of Compromise (IOCs)

**Phishing Emails**:
- ❌ Urgency language ("Immediate action required")
- ❌ Threats ("Account will be closed")
- ❌ Too good to be true ("You won $1M")
- ❌ Grammar/spelling errors
- ❌ Generic greetings ("Dear user")
- ❌ Mismatched sender address
- ❌ Suspicious links (hover to check)
- ❌ Unexpected attachments

**Malware Behavior**:
- ❌ Runs from temp directories
- ❌ Creates scheduled tasks
- ❌ Disables security software
- ❌ Modifies registry run keys
- ❌ Creates hidden files
- ❌ Connects to unknown IPs
- ❌ Encrypts files (ransomware)
- ❌ Unusual PowerShell activity

**Compromised Account**:
- ❌ Login from impossible locations
- ❌ Multiple concurrent sessions
- ❌ Off-hours activity
- ❌ Unusual data access patterns
- ❌ Mass email sending
- ❌ Password spray attempts
- ❌ MFA bypass attempts
- ❌ Forwarding rules created

---

### Severity Assessment Guide

| Factor | Critical | High | Medium | Low |
|--------|----------|------|--------|-----|
| **Threat** | Active C2, Ransomware | Malware detected | Suspicious activity | Blocked attempt |
| **Asset** | Domain controllers | Servers, Databases | Workstations | Non-critical systems |
| **User** | Admins, Executives | Privileged users | Regular users | Service accounts |
| **Impact** | Data breach, Outage | System compromise | Single host issue | No impact |
| **Spread** | Multiple systems | Potential to spread | Contained | Cannot spread |
| **Action** | Call senior NOW | Escalate immediately | Investigate & escalate | Handle & close |

---

### Email Header Quick Reference

**Key Headers to Check**:
- `Return-Path`: Where bounces go (spoofed?)
- `From`: Displayed sender (check carefully)
- `Reply-To`: Where replies go (different from From = suspicious)
- `Received`: Email path (trace origin)
- `Authentication-Results`: SPF, DKIM, DMARC status
- `X-Originating-IP`: Actual sender IP

**Authentication Results**:
- **SPF**: Pass ✓ / Fail ✗ / Neutral ~ / None -
- **DKIM**: Pass ✓ / Fail ✗ / None -
- **DMARC**: Pass ✓ / Fail ✗ / None -

**Red Flags**:
- All three auth methods fail
- Reply-To ≠ From
- Received headers show suspicious origin
- X-Originating-IP from unexpected country

---

## Common Mistakes to Avoid

### ❌ Don't:
1. **Close tickets too quickly** - Always investigate thoroughly
2. **Ignore "gut feeling"** - If something feels off, dig deeper
3. **Assume it's FP because user says so** - Verify independently
4. **Over-rely on automated tools** - Use human judgment
5. **Forget to document** - Future you will thank current you
6. **Be afraid to escalate** - That's what L2 is there for
7. **Skip threat intel checks** - Quick lookup saves time later
8. **Ignore patterns** - One alert might be FP, ten similar alerts = pattern
9. **Rush through alerts** - Quality > Speed
10. **Not ask questions** - Clarify, learn, improve

### ✅ Do:
1. **Follow your investigation checklist** - Be systematic
2. **Document everything** - Timestamps, findings, actions
3. **Think like an attacker** - What would they do next?
4. **Consider context** - Time, user role, business activity
5. **Verify with multiple sources** - Don't trust one tool
6. **Communicate clearly** - Especially when escalating
7. **Learn from feedback** - Ask L2 why they made decisions
8. **Build your knowledge** - Each alert teaches something
9. **Trust but verify** - User says it's fine? Still check
10. **Keep improving** - Review closed tickets, learn patterns

---

## Escalation Template

Use this when escalating to L2:

```
TO: L2-SOC-Team
SUBJECT: [PRIORITY: HIGH] Alert Escalation - [Brief Description]

ALERT DETAILS:
- Alert ID: #12345
- Alert Type: [Type]
- Severity: [Level]
- Timestamp: [When]
- Affected Asset: [User/Host/System]

INITIAL FINDINGS:
[What you discovered during investigation]

INDICATORS OF COMPROMISE:
- [IOC 1]
- [IOC 2]
- [IOC 3]

ACTIONS TAKEN SO FAR:
- [Action 1]
- [Action 2]

REASON FOR ESCALATION:
[Why you're escalating - complexity, uncertainty, criticality]

RECOMMENDED NEXT STEPS:
- [Suggestion 1]
- [Suggestion 2]

URGENCY:
[Why this needs immediate attention if applicable]

ATTACHMENTS:
- [Logs, screenshots, evidence]

Investigated by: [Your Name]
Contact: [Your extension/email]
```

---

## Final Tips for Success

### Building Your Skills:
1. **Review closed tickets** - Learn from past incidents
2. **Ask L2 analysts questions** - They were once L1 too
3. **Practice on CTFs** - Capture The Flag exercises
4. **Read threat reports** - Stay updated on current attacks
5. **Join security communities** - Reddit, Discord, Twitter
6. **Take notes** - Build your personal playbook
7. **Stay curious** - Always ask "why" and "what if"

### Mental Models:
- **Think in layers**: Is there one indicator or multiple?
- **Timeline matters**: What happened before and after?
- **Context is king**: Normal for this user/time/system?
- **Patterns over points**: One alert vs. trend?
- **Better safe than sorry**: When unsure, escalate

### Your Growth Path:
- **Month 1-3**: Learning alerts, building confidence, asking lots of questions
- **Month 3-6**: Recognizing patterns, handling routine alerts independently
- **Month 6-12**: Complex investigations, mentoring newer analysts
- **Year 1+**: Ready for L2 promotion, leading incident response

---

## Remember:

> **Every senior analyst was once confused by their first alerts. The difference between good and great analysts isn't never being wrong - it's being thorough, asking questions, and learning from every ticket.**

You've got this! 🛡️

---

*Last Updated: October 2025*
*Version 1.0 - L1 SOC Analyst Field Guide*

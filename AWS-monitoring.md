# 🛡️ AWS Security Monitoring with Wazuh — SOC Analyst Notes

## 📘 Overview

AWS provides multiple cloud-native security and logging services.  
As a SOC Analyst, you must integrate these with your SIEM (like **Wazuh**) to detect, investigate, and respond to security incidents across cloud infrastructure.

Monitoring AWS ensures:
- Visibility into user and service activity
- Detection of misconfigurations and threats
- Correlation with on-prem or hybrid environment alerts
- Compliance with frameworks (CIS, PCI DSS, ISO 27001, etc.)

---

## ☁️ Key AWS Security & Monitoring Services

| Service | Description | What It Detects / Tracks |
|----------|--------------|---------------------------|
| **AWS CloudTrail** | Records all AWS API calls and user actions | IAM actions, EC2 changes, login events, policy modifications |
| **Amazon GuardDuty** | Threat detection service using ML and threat intelligence | Reconnaissance, crypto-mining, privilege escalation, data exfiltration |
| **Amazon CloudWatch** | Monitors performance metrics and logs | EC2 metrics, Lambda logs, app/system logs |
| **VPC Flow Logs** | Captures network traffic metadata within VPCs | Unusual traffic, open ports, data transfer patterns |
| **AWS Config** | Tracks resource configurations and compliance | Misconfigurations, policy violations |
| **AWS Security Hub** | Centralized security findings from multiple AWS services | Combined alerts from GuardDuty, Inspector, etc. |
| **AWS Inspector** | Automated vulnerability management | OS and software vulnerabilities in EC2, ECR, Lambda |

---

## 🔗 Integration Architecture (AWS → Wazuh)

### 🧩 Option 1: Using AWS Lambda Forwarder

```
AWS Service (CloudTrail, GuardDuty, etc.)
        ↓
CloudWatch Logs / S3 Bucket
        ↓
AWS Lambda Function (Parse + Forward)
        ↓
Wazuh API Endpoint or Agent on EC2
```

- Lambda triggers on new logs (from CloudWatch or S3)
- Sends parsed JSON data to Wazuh API
- Wazuh decoders & rules process them for alerts

### 🧩 Option 2: Using Wazuh Agent on EC2

```
EC2 Instance → Wazuh Manager
```

- The agent collects OS logs (auth, syslog, Windows events)
- Monitors application logs and system metrics
- Sends them directly to Wazuh via port 1514/udp or tcp

---

## 📊 How Wazuh Handles AWS Logs

1. **Decoders** parse AWS JSON logs (CloudTrail, GuardDuty, etc.)
2. **Rules** classify events (e.g., unauthorized access, new policy)
3. **Alerts** are generated with severity levels
4. **Kibana Dashboard** displays AWS alerts for investigation

---

## 🚨 Common AWS Security Alerts to Monitor

| Category | Event / Detection | Source | Why It Matters |
|-----------|-------------------|---------|----------------|
| **Unauthorized Access / Login** | Console login failures, root user login | CloudTrail | Detect brute-force or compromised accounts |
| **Privilege Escalation** | `AttachUserPolicy`, `PutRolePolicy` | CloudTrail | Detect privilege abuse attempts |
| **Resource Creation** | New EC2/Lambda/IAM roles created | CloudTrail | Detect persistence or rogue resource deployment |
| **Network Exposure** | Security groups open to `0.0.0.0/0`, public S3 buckets | AWS Config / CloudTrail | Detect exposed assets |
| **Data Exfiltration** | S3 access from unknown IP or region | GuardDuty / CloudTrail | Detect data theft |
| **Reconnaissance** | Port probes, DNS queries | GuardDuty | Detect scanning and enumeration |
| **Crypto-mining Activity** | `CryptoCurrency:EC2/BitcoinTool.B!DNS` | GuardDuty | Detect resource abuse |
| **Malicious API Usage** | High-frequency API calls (`List*`, `Describe*`) | CloudTrail | Detect recon or automation abuse |
| **Disabling Logs or Monitoring** | CloudTrail/GuardDuty stopped | CloudTrail / Config | Detect attacker evasion |
| **Access Key Misuse** | New keys for root or inactive users | CloudTrail | Detect privilege escalation or misuse |

---

## 🧠 SOC Analyst Focus Areas

1. **High-value detections**
   - Root user activity
   - Unauthorized logins
   - IAM privilege changes
   - GuardDuty findings (severity > 7)
   - CloudTrail disabled events

2. **Correlation**
   - Combine AWS alerts with on-prem logs (Windows, Linux, firewall)
   - Detect cross-environment attack paths

3. **Automation**
   - Use Wazuh rules to auto-alert on high-severity AWS events
   - Set up email or Slack notifications

4. **Dashboards**
   - Build visualizations in Kibana for:
     - Top API calls
     - Failed login trends
     - GuardDuty finding categories
     - IAM policy changes

---

## 🧩 Example: Unauthorized Console Login Detection

**Log snippet (CloudTrail):**
```json
{
  "eventName": "ConsoleLogin",
  "userIdentity": {
    "userName": "test-user",
    "type": "IAMUser"
  },
  "sourceIPAddress": "8.8.8.8",
  "errorMessage": "Failed authentication"
}
```

**Wazuh Detection Flow:**
- Decoder: `aws-cloudtrail`  
- Rule Trigger: `AWS: Unauthorized login`  
- Alert:
  ```
  Rule: 100540 (level 5) -> AWS: Console login failed
  srcip: 8.8.8.8
  user: test-user
  ```

---

## 🧰 Wazuh Configuration References

| File | Purpose |
|------|----------|
| `/var/ossec/etc/ossec.conf` | Main config (AWS module, S3 bucket, API integration) |
| `/var/ossec/etc/rules/aws_cloudtrail_rules.xml` | Rules for CloudTrail |
| `/var/ossec/etc/rules/aws_guardduty_rules.xml` | Rules for GuardDuty |
| `/var/ossec/etc/decoders/aws_cloudtrail_decoders.xml` | Decoders for CloudTrail logs |
| `/var/ossec/etc/decoders/aws_guardduty_decoders.xml` | Decoders for GuardDuty logs |

---

## 🛠️ Steps Summary: AWS Logs → Wazuh

1. **Enable CloudTrail**
   - Send logs to an S3 bucket
2. **Create an S3 → Lambda trigger**
   - Lambda parses new logs and forwards to Wazuh API
3. **Configure Wazuh to receive logs**
   - API endpoint or agent-based
4. **Validate via Kibana**
   - Check if logs appear under `aws.cloudtrail` or `aws.guardduty`
5. **Tune rules**
   - Disable noisy alerts, focus on critical detections

---

## 🧩 Key Benefits of AWS–Wazuh Integration

- 🔍 Unified visibility across on-prem + cloud
- ⚙️ Automated detection of AWS threats
- 📈 Real-time alerts and dashboards
- 🔐 Compliance-ready log retention and reporting
- 🤝 Easier SOC workflow with correlation and triage

---

## 🧾 References
- [Wazuh AWS Integration Docs](https://documentation.wazuh.com/current/cloud_security/amazon/index.html)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [AWS GuardDuty Docs](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [AWS Security Hub Overview](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)

---

## ✅ Summary Cheat Sheet

| Layer | Tool | Purpose |
|--------|------|----------|
| Audit / API logs | **CloudTrail** | Who did what in AWS |
| Threat detection | **GuardDuty** | Detects active threats |
| Metrics / App logs | **CloudWatch** | Performance + system monitoring |
| Network logs | **VPC Flow Logs** | Traffic visibility |
| Compliance | **AWS Config** | Detect misconfigurations |
| Central findings | **Security Hub** | Aggregates alerts |
| SIEM Integration | **Wazuh** | Unified detection + response |

---

> **Tip:**  
> Treat AWS CloudTrail like your **Event Viewer**,  
> GuardDuty like your **antivirus + threat intel**,  
> and Wazuh like your **SIEM brain** that ties everything together.

---

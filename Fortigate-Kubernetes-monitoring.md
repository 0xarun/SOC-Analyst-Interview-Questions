
# SOC - FortiGate Firewall & Kubernetes Security Monitoring Guide

> **Note:** This document focuses on what a SOC Analyst needs to know for **real-world monitoring**, **alert triage**, and **incident correlation** involving **FortiGate Firewalls** and **Kubernetes clusters**.  
> Practical understanding > theory.

---

## 🧱 1. FortiGate Firewall (Network Security Source)

### 🔹 Overview
FortiGate firewalls are NGFWs (Next-Gen Firewalls) used for **network protection**, **traffic filtering**, and **intrusion detection/prevention**.  
From a SOC view, FortiGate is one of the **primary log sources** for detecting perimeter-based threats.

---

### 🔹 Key Log Types for SOC
| Log Type | Description |
|-----------|--------------|
| **Traffic Logs** | Shows allowed/denied traffic between source and destination IPs. |
| **Event Logs** | Configuration changes, admin logins, VPN sessions, policy hits, etc. |
| **UTM Logs** | Security feature logs like AV, Web Filter, IPS, and App Control. |
| **VPN Logs** | VPN tunnel creation, authentication success/failure. |
| **System Logs** | Resource usage, interface changes, system reboots, etc. |

---

### 🔹 Important Fields
```
srcip, dstip, srcport, dstport, proto, action, policyid, service, msg, devname, user, logid, type, subtype
```

---

### 🔹 Common Alerts to Monitor

| Alert Type | Description | What Analyst Should Check |
|-------------|-------------|-----------------------------|
| **Multiple VPN Login Failures** | Possible brute-force attack on VPN users. | Check source IP, geolocation, and login timestamps. |
| **VPN Login Success from Unusual Location** | Possible credential theft. | Compare with user's known IP or country. |
| **Port Scanning** | Multiple destination ports accessed from single IP. | Cross-check with Suricata/Wazuh logs for correlation. |
| **High Outbound Connections** | Possible malware beaconing or data exfil. | Investigate process or endpoint involved. |
| **Blocked Traffic Spikes** | Flooding, misconfig, or DDoS attempt. | Review rate of denials and destination target. |
| **Policy Change Events** | Firewall rules modified. | Check admin user and change approval trail. |
| **IPS Signature Hits** | Intrusion detection triggered. | Identify source, payload, and pattern (false positive or real?). |

---

### 🔹 SOC Workflow Example
1. Receive FortiGate alert: "Multiple VPN login failures."
2. Check **source IP** and **username**.
3. Go to **Elastic Discover** → search `srcip: <attacker_ip>` → correlate with Wazuh/endpoint logs.
4. Determine if attack succeeded → escalate or close.

---

### 🔹 FortiGate → SIEM Integration Tips
- Send logs via **Syslog (UDP/514 or TCP/601)**.
- Parse using decoders in Wazuh or Elastic ingest pipelines.
- Tag log source as `fortigate` for easier correlation.

---

## ☸️ 2. Kubernetes Security (Cloud/Container Monitoring)

### 🔹 Overview
Kubernetes (K8s) is an orchestration platform that manages containers (Pods, Services, Deployments, etc.).  
From a SOC perspective — **it's a high-risk attack surface** if misconfigured.

---

### 🔹 Key Components to Understand
| Component | Description | Security Focus |
|------------|--------------|----------------|
| **API Server** | Central control plane for managing K8s. | Unauthorized access attempts, API misuse. |
| **kubelet** | Agent running on worker nodes. | Privilege abuse, reverse shell from pods. |
| **etcd** | Key-value store for cluster data. | Secrets exposure or deletion attempts. |
| **Controller Manager / Scheduler** | Manages deployments and scaling. | Unauthorized scaling or privilege escalation. |
| **Pods** | Running container instances. | Suspicious images, privilege abuse. |
| **Namespaces** | Logical isolation. | Lateral movement between namespaces. |

---

### 🔹 Important Logs for Monitoring
| Source | Description | Log Location |
|---------|--------------|--------------|
| **Audit Logs** | API calls to the cluster. | `/var/log/kubernetes/audit.log` |
| **kubelet Logs** | Node-level events. | `/var/log/syslog` or journalctl |
| **Container Logs** | App-level logs. | `/var/log/containers/` |
| **Network Policy Logs** | Pod-to-pod connections. | From CNI plugin (e.g., Calico, Cilium) |

---

### 🔹 Common Security Alerts

| Alert | Description | Action for Analyst |
|--------|--------------|--------------------|
| **Unauthorized Access to API Server** | Brute-force or token abuse. | Check IP, user agent, and kubeconfig usage. |
| **Privileged Pod Created** | Pod runs as root with host privileges. | Validate necessity, alert if unexpected. |
| **Container Escape Attempt** | Process tries accessing host files (e.g., `/etc/shadow`). | Check command history and image origin. |
| **Suspicious Command Execution** | `curl`, `wget`, or `nc` used inside containers. | Check for external callbacks or reverse shells. |
| **New ServiceAccount with ClusterAdmin Role** | Privilege escalation attempt. | Verify if done by admin or attacker. |
| **Image Pulled from Unknown Registry** | Untrusted container source. | Block or review image for malware. |
| **etcd Access Attempt from Pod** | Attempt to extract secrets/configs. | Investigate immediately. |

---

### 🔹 Tools to Monitor Kubernetes in SOC

| Tool | Purpose |
|------|----------|
| **Falco** | Runtime threat detection for containers (rules-based). |
| **Kubewatch** | Monitors changes to Kubernetes resources. |
| **Kube-Bench** | CIS Benchmark checks for K8s configurations. |
| **Kube-Hunter** | Simulates attacks on cluster. |
| **GuardDuty (EKS)** | AWS-managed threat detection for EKS clusters. |
| **Elastic Agent / Wazuh Agent** | Collects pod and node logs for centralized visibility. |

---

### 🔹 SOC Workflow Example
1. Receive alert: "Privileged pod created in default namespace."
2. Search in **Elastic**: `kubernetes.namespace: default AND kubernetes.container.name: *`
3. Check who created it → `user.name`, `source.ip`.
4. Verify against DevOps change logs → if not planned → escalate.

---

### 🔹 Kubernetes → SIEM Integration Tips
- Use **Filebeat / Elastic Agent** with Kubernetes integration.
- Enable **Audit logs** on API Server:  
```yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
```
- For Wazuh, use Kubernetes module or collect logs via Fluentd → Syslog → Wazuh Manager.

---

## ⚙️ 3. Correlation Ideas (Elastic/Wazuh)

| Scenario | Source 1 | Source 2 | Insight |
|-----------|-----------|-----------|----------|
| VPN login success → kube API call | FortiGate | Kubernetes audit logs | Stolen VPN creds used for internal attack. |
| Blocked outbound IP → pod making external request | FortiGate | Kubernetes network logs | Possible C2 communication from compromised pod. |
| Admin login to FortiGate + new privileged pod | FortiGate | K8s | Insider threat or misused credentials. |

---

## 🧭 4. Analyst Learning Roadmap

1. Understand **network flow** → how traffic reaches and exits cluster via FortiGate.
2. Practice **alert triage** using sample data in Elastic Discover.
3. Learn **Falco rule writing** (similar to Wazuh custom rules but for containers).
4. Study **MITRE ATT&CK for Containers** — tactics like Persistence, Defense Evasion, Lateral Movement.
5. Simulate **real-world scenarios**:
   - `kubectl exec` → reverse shell
   - FortiGate → port scanning
   - Elastic/Wazuh → correlate both.

---

## 📘 References
- [FortiGate Log Reference Guide](https://docs.fortinet.com/)
- [Kubernetes Audit Logging](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Falco Rules Repository](https://github.com/falcosecurity/falco)

---

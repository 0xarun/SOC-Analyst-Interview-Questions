# Windows Event IDs Reference

This document provides a comprehensive reference for Windows Event IDs commonly used in security monitoring, incident response, and threat hunting.

## Table of Contents
- [Logon & Logoff Events](#logon--logoff-events)
- [Account Management](#account-management)
- [Privilege Use / Escalation](#privilege-use--escalation)
- [Object Access](#object-access)
- [Policy Changes](#policy-changes)
- [Network Events](#network-events)
- [Kerberos & Active Directory](#kerberos--active-directory)

---

## Logon & Logoff Events

| Event ID | Description |
|----------|-------------|
| **4624** | Successful logon |
| **4625** | Failed logon |
| **4647** | User initiated logoff |
| **4634** | Logoff event |
| **4672** | Special privileges assigned (admin logon) |
| **4776** | Credential validation |
| **4648** | Logon with explicit credentials (often lateral movement) |

**Key Notes:**
- Event 4625 is crucial for detecting brute force attacks
- Event 4648 often indicates lateral movement or privilege escalation attempts
- Event 4672 shows when administrative privileges are granted

---

## Account Management

| Event ID | Description |
|----------|-------------|
| **4720** | User account created |
| **4722** | User account enabled |
| **4723** | Password change |
| **4724** | Password reset |
| **4725** | User account disabled |
| **4726** | User account deleted |
| **4732** | User added to a security-enabled local group |
| **4728** | User added to a global group |
| **4735** | Group modified |
| **4756** | User added to a universal group |

**Key Notes:**
- Monitor 4720, 4722, 4732, and 4728 for unauthorized account creation or privilege escalation
- Events 4723 and 4724 can indicate password attacks or legitimate maintenance

---

## Privilege Use / Escalation

| Event ID | Description |
|----------|-------------|
| **4673** | Privileged service called |
| **4674** | Privileged object operation |
| **4688** | New process created |
| **4689** | Process ended |
| **4697** | New service installed |
| **7045** | A new service was installed (from System log, not Security) |

**Key Notes:**
- Event 4688 is essential for process monitoring and threat hunting
- Events 4697 and 7045 can indicate persistence mechanisms
- Enable command line logging for Event 4688 to capture full process details

---

## Object Access

> **Note:** Audit Policy must be configured for these events to be generated

| Event ID | Description |
|----------|-------------|
| **4663** | Access to an object (file/folder) |
| **4656** | Handle to an object requested |
| **4657** | Registry value modified |

**Key Notes:**
- These events require specific audit policies to be enabled
- Can generate high volume of logs - configure carefully
- Useful for monitoring access to sensitive files and registry keys

---

## Policy Changes

| Event ID | Description |
|----------|-------------|
| **4739** | Domain policy changed |
| **4719** | Audit policy changed |
| **4902** | Security policy was updated |
| **4946** | Rule added to the Windows Firewall exception list |

**Key Notes:**
- Critical for detecting unauthorized policy modifications
- Event 4719 shows changes to audit configuration
- Event 4946 can indicate firewall bypass attempts

---

## Network Events

> **Note:** Requires Sysmon or advanced logging configuration

| Event ID | Description |
|----------|-------------|
| **Sysmon 3** | Network connection initiated |
| **Sysmon 1** | Process creation |
| **Sysmon 7** | Image loaded |
| **Sysmon 10** | Process accessed another process |

**Key Notes:**
- Sysmon must be installed and configured separately
- Sysmon Event 3 provides detailed network connection information
- Sysmon Event 1 offers enhanced process creation details beyond Event 4688

**Memorize Event IDs 1, 3, 10, 11, 7, and 8 especially:**

- 1 = Process Create
- 3 = Network Connection
- 10 = Process Access (often used for LSASS dumping)
- 8 = CreateRemoteThread (code injection)
- 11 = File Create
- 7 = Image Loaded (DLLs loaded)

---

## Kerberos & Active Directory

| Event ID | Description |
|----------|-------------|
| **4768** | TGT requested |
| **4769** | TGS requested |
| **4771** | Kerberos pre-auth failed |
| **4770** | TGT renewal |
| **4729** | User removed from security-enabled global group |
| **4740** | Account locked out |

**Key Notes:**
- Events 4768 and 4769 are fundamental for Kerberos authentication monitoring
- Event 4771 can indicate Kerberoasting or password spray attacks
- Event 4740 shows account lockouts, useful for detecting brute force attempts

---

## Usage Tips

### For Security Monitoring:
- Focus on failed logons (4625) and privilege escalation events (4672, 4688)
- Monitor account management events for unauthorized changes
- Set up alerts for policy changes and new service installations

### For Incident Response:
- Correlate logon events (4624) with process creation (4688) for timeline analysis
- Use Kerberos events to track authentication across domain controllers
- Examine object access events for data exfiltration indicators

### For Threat Hunting:
- Look for unusual patterns in network connections (Sysmon 3)
- Correlate process creation with network activity
- Monitor for credential dumping indicators through process access events

---

## Log Sources

- **Security Log**: Most events (4xxx series)
- **System Log**: Service-related events (7045)
- **Sysmon Log**: Enhanced process and network monitoring
- **Domain Controller Logs**: Kerberos and AD-specific events

---

*Last Updated: June 2025*

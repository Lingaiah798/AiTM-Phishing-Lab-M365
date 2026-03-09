# 🛡️ AiTM Phishing Attack — Lab Detection & Disruption

> **⚠️ Disclaimer:** This repository documents a **controlled lab simulation** of an Adversary-in-the-Middle (AiTM) phishing attack conducted in an isolated Microsoft 365 test environment. All findings are for **educational and defensive security purposes only**. Do not replicate outside of authorized lab environments.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Attack Scenario](#attack-scenario)
- [Attack Chain](#attack-chain)
- [Lab Environment](#lab-environment)
- [Detection](#detection)
- [Investigation Steps](#investigation-steps)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [Mitigation & Hardening](#mitigation--hardening)
- [Tools Used](#tools-used)
- [Key Takeaways](#key-takeaways)

---

## Overview

| Field | Details |
|---|---|
| **Attack Type** | Adversary-in-the-Middle (AiTM) Phishing |
| **Target Platform** | Microsoft 365 / Exchange Online |
| **Detection Tool** | Microsoft 365 Defender (Attack Disruption) |
| **Lab Date** | March 2026 |
| **Severity** | 🔴 Critical |
| **MFA Bypassed?** | ✅ Yes — via session cookie theft |

---

## Attack Scenario

An AiTM phishing attack is an advanced technique where the threat actor positions a **proxy server between the victim and a legitimate service** (e.g., Microsoft 365). Unlike traditional phishing, this attack does not need to crack or steal the password directly — it steals the **authenticated session cookie** in real time, effectively bypassing Multi-Factor Authentication (MFA).

### Why This Is Dangerous
- ✅ MFA is enabled → Still bypassed
- ✅ Password is strong → Doesn't matter
- ✅ User completes MFA prompt → Attacker gets the cookie anyway

---

## Attack Chain

```
[1] Victim receives phishing email
         ↓
[2] Email contains link to Canva-hosted lure page
    (legitimate domain used to bypass email filters)
         ↓
[3] Victim clicks "DOWNLOAD PAYMENT SUMMARY"
         ↓
[4] Redirected to attacker-controlled domain
    payments.paramountres[.]pro/U4m5e
         ↓
[5] Fake Microsoft login page served via AiTM proxy
         ↓
[6] Victim enters credentials + completes MFA
         ↓
[7] AiTM proxy captures:
    - Username & Password
    - Authenticated Session Cookie
         ↓
[8] Attacker uses cookie to access M365 directly
    (No password or MFA needed from this point)
         ↓
[9] Post-compromise activity:
    - Inbox rule creation
    - Email forwarding
    - Contact harvesting via LinkedIn/GAL
    - File access via OneDrive/SharePoint
```

---

## Lab Environment

- **Platform:** Microsoft 365 (Exchange Online, Defender, Entra ID)
- **Detection:** Microsoft 365 Defender with Attack Disruption enabled
- **Monitoring:** Unified Audit Log, Exchange Admin Center
- **Analysis Tools:** VirusTotal, ANY.RUN sandbox

---

## Detection

### Microsoft 365 Defender Alert
Microsoft 365 Defender's **Attack Disruption** feature automatically detected and flagged the incident:

```
Incident Name: Attack using AiTM phishing (attack disruption)
```

**How Attack Disruption works:**
- Correlates signals across endpoints, email, identity, and cloud apps
- Automatically contains compromised accounts
- Suspends suspicious sessions
- Raises a high-priority incident in the Defender portal

---

## Investigation Steps

### Step 1 — Triage the Defender Incident
```
security.microsoft.com → Incidents & Alerts → Incidents
```
- Review attack timeline
- Identify affected users
- Check suspicious IPs and sign-in locations

### Step 2 — Revoke Compromised Sessions
```powershell
# Revoke all active sessions for the compromised user
Revoke-AzureADUserAllRefreshToken -ObjectId <UserObjectId>

# Or via Microsoft Graph
Invoke-MgInvalidateUserRefreshToken -UserId <user@domain.com>
```

### Step 3 — Audit Email App Settings
```powershell
# Check CAS mailbox settings
Get-CASMailbox -Identity <user@domain.com> | 
Select-Object ImapEnabled, PopEnabled, ActiveSyncEnabled, OWAEnabled, MAPIEnabled
```

### Step 4 — Review OWA Mailbox Policy
```powershell
# Read current OWA policy settings (READ ONLY - safe to run)
Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | Format-List
```

**Key risky settings found in this lab:**

| Setting | Value Found | Risk |
|---|---|---|
| `LinkedInEnabled` | True | External contact sync |
| `FacebookEnabled` | True | Social media exposure |
| `SaveAttachmentsToCloudEnabled` | True | Data exfiltration risk |
| `AdditionalStorageProvidersAvailable` | True | Dropbox/GDrive access |
| `ConditionalAccessPolicy` | Off | No CA enforcement on OWA |
| `DirectFileAccessOnPublicComputersEnabled` | True | Public PC file download |

### Step 5 — Check for Inbox Rules (Post-Compromise)
```powershell
# Check for suspicious inbox rules
Get-InboxRule -Mailbox <user@domain.com> | 
Select-Object Name, Enabled, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage
```

### Step 6 — Search Audit Logs for URL Clicks
```powershell
Search-UnifiedAuditLog `
  -StartDate (Get-Date).AddDays(-7) `
  -EndDate (Get-Date) `
  -Operations "UrlClicked" | 
  Where-Object {$_.AuditData -like "*paramountres*"}
```

### Step 7 — Analyse the Phishing URL
The phishing lure used a **trusted domain (Canva)** to host the initial page, redirecting victims to:
```
hxxps://payments.paramountres[.]pro/U4m5e
```

> ⚠️ Defanged URL — do not click

**VirusTotal Result:** 1/95 vendors flagged (new domain — low detection at time of analysis)

---

## Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| **URL** | `hxxps://payments.paramountres[.]pro/U4m5e` | AiTM proxy landing page |
| **Domain** | `payments.paramountres[.]pro` | Malicious redirect domain |
| **Lure Platform** | `canva.com` | Legitimate site abused for lure hosting |
| **Lure Theme** | ACH Remittance Notice | Financial urgency lure |
| **File Date** | March 5, 2026 | Date shown on lure page |

> 🔒 All IOCs are **defanged** — replace `[.]` with `.` only in authorized analysis environments.

---

## Mitigation & Hardening

### Immediate Response
```powershell
# 1. Disable legacy auth protocols on compromised mailbox
Set-CASMailbox -Identity <user@domain.com> `
  -ImapEnabled $false `
  -PopEnabled $false

# 2. Harden OWA Mailbox Policy
Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default `
  -LinkedInEnabled $false `
  -FacebookEnabled $false `
  -AdditionalStorageProvidersAvailable $false `
  -SaveAttachmentsToCloudEnabled $false `
  -PersonalAccountCalendarsEnabled $false `
  -DirectFileAccessOnPublicComputersEnabled $false

# 3. Block malicious domain in Defender
# security.microsoft.com → Tenant Allow/Block Lists → URLs
# Add: payments.paramountres.pro
```

### Long-Term Hardening

| Control | Action |
|---|---|
| **Phishing-Resistant MFA** | Deploy FIDO2 / hardware keys — immune to AiTM |
| **Conditional Access** | Require compliant devices, block legacy auth |
| **Defender for Office 365** | Enable Safe Links + Safe Attachments |
| **Token Protection** | Enable Conditional Access token binding (preview) |
| **Session Lifetime** | Reduce refresh token lifetime for sensitive roles |
| **UEBA** | Enable anomalous sign-in alerts in Entra ID Protection |

### Conditional Access — Block Legacy Auth
```
Entra ID → Security → Conditional Access → New Policy
- Users: All users
- Cloud apps: All cloud apps  
- Conditions → Client apps: Exchange ActiveSync + Other clients
- Grant: Block access
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| **Microsoft 365 Defender** | Incident detection & attack disruption |
| **Exchange Admin Center** | Mailbox & protocol settings review |
| **Entra ID** | Session management, Conditional Access |
| **Exchange Online PowerShell** | Audit & remediation commands |
| **VirusTotal** | URL & domain reputation analysis |
| **ANY.RUN** | Interactive sandbox for URL behaviour analysis |

---

## Key Takeaways

> 💡 **MFA alone is not enough** against AiTM attacks. Session cookies bypass it entirely.

1. **AiTM is MFA-resistant** — only phishing-resistant MFA (FIDO2) truly stops it
2. **Trusted domains are abused** — Canva, SharePoint, OneDrive links bypass email filters
3. **New domains evade detection** — 1/95 vendors caught this; always sandbox unknown URLs
4. **OWA policy hygiene matters** — default settings are overly permissive
5. **Attack Disruption is powerful** — Microsoft Defender automatically contained this threat
6. **Legacy auth is a gap** — even if CA blocks it, keep IMAP/POP3 disabled at mailbox level too
7. **Audit logs are essential** — always check for inbox rules and URL clicks post-compromise

---

## 📁 Repository Structure

```
AiTM-Phishing-Lab/
├── README.md                          # This file
├── docs/
│   ├── attack-chain.md               # Detailed attack chain breakdown
│   └── investigation-checklist.md   # Step-by-step IR checklist
├── scripts/
│   ├── audit-mailbox.ps1            # PowerShell audit script
│   ├── harden-owa-policy.ps1        # OWA hardening script
│   └── revoke-sessions.ps1          # Session revocation script
├── mitigations/
│   └── conditional-access-policy.md # CA policy configuration guide
└── screenshots/                      # Evidence screenshots (redacted)
```

---

## 🔗 References

- [Microsoft: Defending against AiTM phishing](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
- [Microsoft Defender Attack Disruption](https://learn.microsoft.com/en-us/microsoft-365/security/defender/automatic-attack-disruption)
- [MITRE ATT&CK: T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [MITRE ATT&CK: T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)

---

*Created for educational and defensive security research purposes.*
*All testing conducted in an authorized lab environment.*

# 🔍 AiTM Phishing — Incident Response Checklist

Use this checklist when responding to an AiTM phishing incident in Microsoft 365.

---

## Phase 1 — Initial Detection ⏱️ First 15 Minutes

- [ ] Review Microsoft 365 Defender incident alert
- [ ] Note incident name, severity, and affected users
- [ ] Identify attack timeline (first alert → current time)
- [ ] Screenshot and preserve all Defender alerts

---

## Phase 2 — Immediate Containment ⏱️ First 30 Minutes

- [ ] Revoke all active sessions for affected user(s)
- [ ] Disable account sign-in temporarily
- [ ] Reset user password
- [ ] Notify user and their manager
- [ ] Block malicious domains in Defender Tenant Allow/Block List

---

## Phase 3 — Investigation ⏱️ First 2 Hours

### Email & Mailbox
- [ ] Check for inbox rules (especially forwarding/deletion rules)
- [ ] Check mailbox forwarding settings (ForwardingSmtpAddress)
- [ ] Review sent items for suspicious outbound emails
- [ ] Check delegate access — any new delegates added?

### Authentication & Access
- [ ] Review sign-in logs for suspicious IPs/locations
- [ ] Check for new device registrations in Entra ID
- [ ] Review OAuth app consents granted
- [ ] Check URL click events in audit log

### Protocol & Policy Review
- [ ] Audit CAS mailbox settings (IMAP, POP3, ActiveSync)
- [ ] Review OWA Mailbox Policy settings
- [ ] Confirm Conditional Access policies are active
- [ ] Check for any CA policy bypass conditions

### Data Access
- [ ] Review SharePoint/OneDrive access logs
- [ ] Check for unusual file downloads or shares
- [ ] Review Teams messages for suspicious content

---

## Phase 4 — Eradication

- [ ] Remove any malicious inbox rules
- [ ] Remove any unauthorized delegates
- [ ] Disable unnecessary email protocols (IMAP, POP3)
- [ ] Harden OWA policy settings
- [ ] Revoke any suspicious OAuth consents

---

## Phase 5 — Recovery

- [ ] Re-enable user account after password reset
- [ ] Confirm MFA is properly configured
- [ ] Verify Conditional Access policies are applying correctly
- [ ] Monitor user account for 7 days post-incident

---

## Phase 6 — Lessons Learned

- [ ] Document full attack timeline
- [ ] Record all IOCs (URLs, domains, IPs)
- [ ] Submit phishing URL to Microsoft and VirusTotal
- [ ] Update email security rules based on findings
- [ ] Consider deploying phishing-resistant MFA (FIDO2)
- [ ] Share findings with security team

---

## Key PowerShell Commands Reference

```powershell
# Revoke sessions
Revoke-AzureADUserAllRefreshToken -ObjectId <ObjectId>

# Check inbox rules
Get-InboxRule -Mailbox <user@domain.com>

# Check forwarding
Get-Mailbox <user@domain.com> | Select ForwardingSmtpAddress, DeliverToMailboxAndForward

# Check CAS settings
Get-CASMailbox <user@domain.com> | Select ImapEnabled, PopEnabled, ActiveSyncEnabled

# Search URL clicks
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations "UrlClicked" -UserIds <user@domain.com>

# Check OWA policy (READ ONLY)
Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default | Format-List
```

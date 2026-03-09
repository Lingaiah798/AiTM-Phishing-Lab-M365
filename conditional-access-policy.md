# Conditional Access Policy Configuration Guide

## Policy 1 — Block Legacy Authentication ✅ (Already in place)

**Path:** Entra ID → Security → Conditional Access → New Policy

| Setting | Value |
|---|---|
| Name | Block - All Resources: Block Legacy Authentication |
| Users | All users |
| Cloud Apps | All cloud apps |
| Conditions → Client Apps | Exchange ActiveSync clients, Other clients |
| Grant | Block access |
| Enable Policy | On |

---

## Policy 2 — Require Phishing-Resistant MFA (Recommended)

| Setting | Value |
|---|---|
| Name | Require - High Value Users: Phishing-Resistant MFA |
| Users | Admins, Finance, HR, Executives |
| Cloud Apps | All cloud apps |
| Grant | Require authentication strength → Phishing-resistant MFA |
| Enable Policy | On |

---

## Policy 3 — Block Risky Sign-Ins (Recommended)

| Setting | Value |
|---|---|
| Name | Block - Risky Sign-Ins: High Risk |
| Users | All users |
| Cloud Apps | All cloud apps |
| Conditions → Sign-in risk | High |
| Grant | Block access |
| Enable Policy | On |

---

## Policy 4 — Require Compliant Device for OWA (Recommended)

| Setting | Value |
|---|---|
| Name | Require - OWA Access: Compliant Device |
| Users | All users |
| Cloud Apps | Office 365 Exchange Online |
| Conditions → Client Apps | Browser |
| Grant | Require device to be marked as compliant |
| Enable Policy | Report-only first, then On |

---

## ⚠️ Testing Recommendation

Always set new CA policies to **Report-only** mode first for 7 days before enabling, to avoid unintended lockouts.

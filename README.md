# HTB-Sherlock-PhishNet
# Phishing_Email_Analysis_&_Incident_Response
 
## Overview

A hands-on blue team investigation of a Business Email Compromise (BEC) phishing email targeting a finance department. The objective was to triage the email, extract and validate indicators of compromise, map attacker behavior to MITRE ATT&CK, and document a structured incident response.

---

## Scenario

The accounting department received an urgent email from `finance@business-finance.com` demanding immediate payment of a $4,750 overdue invoice. The email contained a malicious hyperlink and a ZIP attachment concealing a Windows batch script disguised as a PDF.

---

## Tools Used

| Tool | Purpose |
|---|---|
| PhishTool | Email triage, header parsing, attachment hash extraction |
| VirusTotal | IOC reputation analysis, hash lookup |
| AlienVault OTX | Threat intelligence enrichment |
| MXToolbox | Mail server and DNS validation |
| WHOIS | Domain registration and infrastructure lookup |
| Manual Analysis | Header inspection, URL dissection, payload identification |

---

## Key Findings

- **Authentication bypass** — SPF, DKIM, and DMARC all returned `pass`, meaning the attacker controlled or compromised the sending domain. Standard mail gateway filtering would not have blocked this email based on authentication alone.
- **Malicious attachment** — `Invoice_2025_Payment.zip` contained `invoice_document.pdf.bat`, a Windows batch script using double-extension masquerading (T1036) to appear as a harmless PDF.
- **Credential harvesting URL** — a deceptive `secure.` subdomain link designed to capture victim credentials.
- **Invoice number mismatch** — the invoice ID in the email body (`INV-2025-0012`) differed from the one in the payload URL (`INV2025-0987`), a common artefact of phishing kit templates.
- **Social engineering** — high-urgency language ("final notice", "penalties", "immediately") used to bypass rational scrutiny.

---

## Indicators of Compromise (IOCs)

### Email

| Type | Value |
|---|---|
| Sender | `finance@business-finance.com` |
| Reply-To | `support@business-finance.com` |
| Originating IP | `45.67.89.10` |
| Relay IP | `203.0.113.25` |
| Phishing Domain | `secure.business-finance.com` |

### File

| Type | Value |
|---|---|
| ZIP Attachment | `Invoice_2025_Payment.zip` |
| Hidden Payload | `invoice_document.pdf.bat` |
| SHA-256 | `8379c41239e9af845b2ab6c27a7509ae8804d7d73e455c800a551b22ba25bb4a` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Initial Access | Spearphishing Link | T1566.002 |
| Execution | User Execution | T1204 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Collection | Phishing for Information | T1598 |

---

## Incident Response Summary

**Immediate containment**
- Quarantined the email at the gateway
- Blocked sender domain and originating IP at the firewall
- Blocked the phishing URL via DNS/web filtering
- Added the file hash to endpoint detection watchlist
- Searched mail logs for other recipients of the same campaign

**Escalation**
- Escalated to SOC Tier 2, Incident Response Team, and Email Security Team for enterprise-wide scoping

**Recommendations**
- Enforce attachment sandboxing for ZIP and script file types
- Restrict execution of `.bat`/`.cmd` files from user directories
- Conduct phishing awareness training with focus on invoice fraud patterns
- Implement a verified payment request callback procedure for the finance team

---

## Analyst Workflow

```
Detection → Header Analysis → URL Analysis → Attachment Analysis
→ IOC Extraction → Threat Intel Validation → MITRE ATT&CK Mapping
→ Containment → Escalation → Documentation
```

---

## Report

The full investigation report is included in this repository:  
📄 `Phishing_Email_Analysis_Report_PhishNet.pdf`

---

## Skills Demonstrated

`Phishing Triage` `Email Header Analysis` `IOC Extraction` `Malware Identification`  
`Threat Intelligence` `MITRE ATT&CK` `Incident Documentation` `BEC Investigation`

---
<img width="1331" height="617" alt="HTB-Sherlock-2025-PhishNet" src="https://github.com/user-attachments/assets/83967414-0fd0-4589-8a9c-73aa0f4d63a4" />
https://labs.hackthebox.com/achievement/sherlock/2413013/985

---
> **Disclaimer:** This analysis was performed in a controlled lab environment as part of a Hack The Box Sherlock challenge. No real systems or individuals were harmed. All IOCs are fictional and scoped to the exercise.

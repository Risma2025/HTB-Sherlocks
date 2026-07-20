# HTB-Sherlock-PhishNet-Writeup

## Scenario

> An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers and uncover the attacker's scheme.

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

## Task 1 — What is the originating IP address of the sender?

**Answer:** `45.67.89.10`

**Explanation:** The originating IP is listed directly under the email's **Details** tab in PhishTool as well as confirmed via the SPF check in the **Authentication** tab and the `X-Originating-IP` header. This is the IP address the mail actually came from before it entered the legitimate mail relay chain — useful for reputation lookups since it's the attacker's real sending infrastructure.

---

## Task 2 — Which mail server relayed this email before reaching the victim?

**Answer:** `203.0.113.25`

**Explanation:** Looking at the **Transmission** tab, the email passed through three hops. The final hop before delivery to the recipient's mailbox was `mail.business-finance.com (203.0.113.25)`. Tracing the transmission path (Hop 1 → Hop 3) shows how the message moved through the spoofed sender's relay infrastructure before landing in the victim's inbox.

---

## Task 3 — What is the sender's email address?

**Answer:** `finance@business-finance.com`

**Explanation:** Shown in the **From** field of the **Details** tab. The display name "Finance Dept" was used to add legitimacy, but the actual sending address is `finance@business-finance.com` — a lookalike domain designed to impersonate a trusted vendor.

---

## Task 4 — What is the 'Reply-To' email address specified in the email?

**Answer:** `support@business-finance.com`

**Explanation:** Found in the **Details** tab under **Reply-To**. Attackers often set a different Reply-To address than the From address so that any replies (or "helpdesk" contact) get routed to an address they fully control, separate from the spoofed sending identity.

---

## Task 5 — What is the SPF (Sender Policy Framework) result for this email?

**Answer:** `pass`

**Explanation:** Visible in the **Authentication** tab under the **SPF** section, tied to the Originating IP (`45.67.89.10 (Received-SPF)`). An SPF pass here is a red flag in itself — it means the attacker controls a domain with a valid SPF record, not that the email is legitimate. This is a common technique: register a similar-sounding domain and configure proper SPF/DKIM so security filters don't flag it purely on authentication failures.

---

## Task 6 — What is the domain used in the phishing URL inside the email?

**Answer:** `secure.business-finance.com`

**Explanation:** From the **URLs** tab, the "Download Invoice" link resolves to `https://secure.business-finance.com/invoice/details/view/INV-2025-0987/payment`. Note this is a *different* subdomain than the sender's domain — a subdomain likely spun up by the attacker specifically to host a fake payment/credential-harvesting page.

---

## Task 7 — What is the fake company name used in the email?

**Answer:** `Business Finance Ltd.`

**Explanation:** Referenced in the email body signature ("Business Finance Ltd.") in the **Rendered** view. This fabricated company name reinforces the impersonation of a legitimate finance vendor to pressure the accounting team into paying a fake overdue invoice.

---

## Task 8 — What is the name of the attachment included in the email?

**Answer:** `Invoice_2025_Payment.zip`

**Explanation:** Found in the **Attachments** tab. The attacker uses a "convenience" pretext (attaching the invoice directly in case the link doesn't work) as a second delivery vector for the payload, increasing the odds the victim interacts with the malicious content.

---

## Task 9 — What is the SHA-256 hash of the attachment?

**Answer:** `8379C41239E9AF845B2AB6C27A7509AE8804D7D73E455C800A551B22BA25BB4A`

**Explanation:** Listed in the **Attachments** tab alongside the MD5 and SHA-1 hashes. This hash is what you'd submit to VirusTotal to check reputation/detection across AV engines and to pivot on related samples or campaigns.

---

## Task 10 — What is the filename of the malicious file contained within the ZIP attachment?

**Answer:** `invoice_document.pdf.bat`

**Explanation:** Extracting/inspecting the ZIP contents reveals a double-extension file (`.pdf.bat`). This is a classic social engineering trick — Windows hides known file extensions by default, so the file appears to end in `.pdf` at a glance, but it's actually a `.bat` script that will execute code when opened.

---

## Task 11 — Which MITRE ATT&CK technique(s) are associated with this attack?

**Answer:** `T1566.001`

**Explanation:** T1566.001 is **Phishing: Spearphishing Attachment** under the Initial Access tactic. It fits here because the attacker delivered a malicious executable disguised as a PDF invoice inside an email attachment to gain initial access/execution on the victim's machine.

---

## Summary

This Sherlock walks through a textbook Business Email Compromise (BEC) / invoice fraud phishing attack:

1. A lookalike domain (`business-finance.com`) with valid SPF spoofs a "known vendor."
2. Urgency and financial pressure ("overdue," "penalties," "suspension") are used to rush the victim.
3. Two delivery vectors are used — a phishing link (`secure.business-finance.com`) and a malicious ZIP attachment — to maximize the chance of a successful compromise.
4. The payload uses a double-extension trick (`invoice_document.pdf.bat`) to disguise an executable as a harmless PDF.
5. Header analysis (Originating IP, Transmission hops, X-headers) exposes the true source of the email despite a passing SPF result, reinforcing why full header/authentication analysis — not just SPF/DKIM/DMARC status — matters during triage.

>**Key takeaway for SOC L1 analysts:** never trust a passing SPF/DKIM check alone as proof of legitimacy — attackers frequently register their own lookalike domains and configure authentication correctly. Always correlate sender domain, reply-to, URL domains, and attachment behavior before clearing an email as safe.
---

https://labs.hackthebox.com/achievement/sherlock/2413013/985


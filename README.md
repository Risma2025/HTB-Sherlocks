# HTB-Sherlock-PhishNet-Writeup

## Scenario

> An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers and uncover the attacker's scheme.

---

## Tools Used

| Tool | Purpose |
|---|---|
| PhishTool | Email header analysis, email body analysis, attachment hash extraction |
| VirusTotal | IOC reputation analysis, hash lookup, payload name finding  |
| AlienVault OTX | Threat intelligence enrichment |
| MXToolbox | Mail server and DNS validation |
| WHOIS | Domain registration and infrastructure lookup |

---

## Email Body Analysis

- **High-Urgency Lure:** The subject line uses social engineering techniques (*"Urgent: Invoice Payment Required - Overdue Notice"*) to induce panic and rush the target into a quick decision.
- **Malicious Double Delivery:** The email provides a text-based hyperlink ("Download Invoice") while simultaneously referencing a dangerous `.zip` attachment (`Invoice_2025_Payment.zip`), trying multiple ways to get the user to execute the payload.
- **Generic Greeting:** It targets a generic group ("Dear Accounting Team") instead of a specific, named individual within the organization.

---

<img width="1348" height="578" alt="PhishNet_Email_Body" src="https://github.com/user-attachments/assets/0d1c46a3-a1f3-40c0-9476-5db0dfcaf0cf" />

### Task 1 — What is the originating IP address of the sender?

**Answer:** `45.67.89.10`

The originating IP is listed directly under the email's **Details** tab in PhishTool as well as confirmed via the SPF check in the **Authentication** tab and the `X-Originating-IP` header. This is the IP address the mail actually came from before it entered the legitimate mail relay chain — useful for reputation lookups since it's the attacker's real sending infrastructure.

---
<img width="680" height="448" alt="PhishNet_PhishTool_5_Transmission" src="https://github.com/user-attachments/assets/84d5c3d8-3af9-41dc-8a89-28149998af52" />

### Task 2 — Which mail server relayed this email before reaching the victim?

**Answer:** `203.0.113.25`

Looking at the **Transmission** tab, the email passed through three hops. The final hop before delivery to the recipient's mailbox was `mail.business-finance.com (203.0.113.25)`. Tracing the transmission path (Hop 1 → Hop 3) shows how the message moved through the spoofed sender's relay infrastructure before landing in the victim's inbox.

---

### Task 3 — What is the sender's email address?

**Answer:** `finance@business-finance.com`

Shown in the **From** field of the **Details** tab. The display name "Finance Dept" was used to add legitimacy, but the actual sending address is `finance@business-finance.com` — a lookalike domain designed to impersonate a trusted vendor.

---

### Task 4 — What is the 'Reply-To' email address specified in the email?

**Answer:** `support@business-finance.com`

Found in the **Details** tab under **Reply-To**. Attackers often set a different Reply-To address than the From address so that any replies (or "helpdesk" contact) get routed to an address they fully control, separate from the spoofed sending identity.

---
<img width="674" height="608" alt="PhishNet_PhishTool_2_Authentication" src="https://github.com/user-attachments/assets/3d4ccdd2-427a-4b4f-abca-94fc0be33a90" />

### Task 5 — What is the SPF (Sender Policy Framework) result for this email?

**Answer:** `pass`

Visible in the **Authentication** tab under the **SPF** section, tied to the Originating IP (`45.67.89.10 (Received-SPF)`). An SPF pass here is a red flag in itself — it means the attacker controls a domain with a valid SPF record, not that the email is legitimate. This is a common technique: register a similar-sounding domain and configure proper SPF/DKIM so security filters don't flag it purely on authentication failures.

---
<img width="684" height="286" alt="PhishNet_PhishTool_3_URLs" src="https://github.com/user-attachments/assets/ca853cef-967f-41a8-ad13-d551c4cc4033" />

### Task 6 — What is the domain used in the phishing URL inside the email?

**Answer:** `secure.business-finance.com`

From the **URLs** tab, the "Download Invoice" link resolves to `https://secure.business-finance.com/invoice/details/view/INV-2025-0987/payment`. Note this is a *different* subdomain than the sender's domain — a subdomain likely spun up by the attacker specifically to host a fake payment/credential-harvesting page.

---
<img width="680" height="474" alt="PhishNet_PhishTool_6_X-headers" src="https://github.com/user-attachments/assets/7f4aab46-eb14-443c-850e-f6fae76f4562" />

### Task 7 — What is the fake company name used in the email?

**Answer:** `Business Finance Ltd.`

Found in PhishTool's **X-headers** tab under the `x-organization` field. The attacker set this header to reinforce the fake vendor identity across the email, not just in the visible signature — a small detail that adds legitimacy to the impersonation and is easy to miss if you only read the rendered email body.

---
<img width="683" height="419" alt="PhishNet_PhishTool_4_Attachments" src="https://github.com/user-attachments/assets/f00ab1fb-63ab-4de7-aa12-a65494328da6" />

### Task 8 — What is the name of the attachment included in the email?

**Answer:** `Invoice_2025_Payment.zip`

Found in the **Attachments** tab. which also lists the file's size (0.07 KB), type (ZIP), and hashes. The attachment name itself is a deliberate social engineering choice — naming it after an "invoice" and "payment" reinforces the email's financial pretext and makes the file feel expected and legitimate to someone in accounting.

---

### Task 9 — What is the SHA-256 hash of the attachment?

**Answer:** `8379C41239E9AF845B2AB6C27A7509AE8804D7D73E455C800A551B22BA25BB4A`

**Explanation:** Listed in the **Attachments** tab alongside the MD5 and SHA-1 hashes. This hash is what you'd submit to VirusTotal to check reputation/detection across AV engines and to pivot on related samples or campaigns.

---
<img width="1348" height="522" alt="Payload_Name" src="https://github.com/user-attachments/assets/773bb17f-023f-4717-aa53-dd5341895a5c" />

### Task 10 — What is the filename of the malicious file contained within the ZIP attachment?

**Answer:** `invoice_document.pdf.bat`

PhishTool extracted `Invoice_2025_Payment.zip` and calculated its `SHA-256 hash` automatically under the **Attachments** section. Submitting that hash to `VirusTotal` revealed the file details, including the internal filename invoice_document.pdf.bat — a double-extension trick that masquerades a malicious Windows batch script as a harmless PDF. Since Windows hides known file extensions by default, a victim would only see "invoice_document.pdf" and be far more likely to open it.

---
<img width="1351" height="612" alt="mitre_attack" src="https://github.com/user-attachments/assets/418907f3-4039-40d0-85dc-2ac49b375937" />

### Task 11 — Which MITRE ATT&CK technique(s) are associated with this attack?

**Answer:** `T1566.001`

T1566.001 is **Phishing: Spearphishing Attachment** under the Initial Access tactic. It fits here because the attacker delivered a malicious executable disguised as a PDF invoice inside an email attachment to gain initial access/execution, by specifically targeting  an accounting department through a fake overdue invoice. 

---

## Summary

1. This Sherlock walks through a Business Email Compromise (BEC) or phishing email attack.
2. Urgency and financial pressure ("overdue," "penalties," "suspension") are used to rush the victim.
3. A phishing link (`secure.business-finance.com`) and a malicious ZIP attachment — to maximize the chance of a successful compromise.
4. The payload uses a double-extension trick (`invoice_document.pdf.bat`) to disguise an executable as a harmless PDF.
5. Header analysis (Originating IP, Transmission hops, X-headers) exposes the true source of the email despite a passing SPF result, reinforcing why full header/authentication analysis — not just SPF/DKIM/DMARC status — matters during triage.

The Forensic investigation (DFIR) report is included in this repository:[Read the PhishNet DFIR Report](https://github.com/Risma2025/HTB-Sherlocks/blob/HTB-Sherlock-PhishNet/HTB-Sherlock-PhishNet-Phishing_Email_Analysis_%26_IR_Report-.pdf)

>**Key takeaway for SOC L1 analysts:** never trust a passing SPF/DKIM check alone as proof of legitimacy — attackers frequently register their own lookalike domains and configure authentication correctly. Always correlate sender domain, reply-to, URL domains, and attachment behavior before clearing an email as safe.
---
<img width="1331" height="617" alt="HTB-Sherlock-2025-PhishNet" src="https://github.com/user-attachments/assets/2798181c-f933-4d40-830c-e1a99a3228b9" />

https://labs.hackthebox.com/achievement/sherlock/2413013/985

---
## 📬 Contacts & Profiles
**LinkedIn:** [risma-fareedh](https://www.linkedin.com/in/risma-fareedh-066a19199) | **Hack The Box:** [HTB Profile](https://profile.hackthebox.com/profile/019d51eb-d379-72f0-ad54-5a4e2121b80b) | **GitHub:** [Risma2025](https://github.com/Risma2025)


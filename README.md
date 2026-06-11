# HTB-Sherlock-Vantage
# Network-Traffic-Analysis-for-Threat-Hunting-&-Incindent-Response-on-OpenStack-Cloud-Environment

## 📌 Project Overview
This project is a detailed forensic investigation of a compromised OpenStack cloud environment. By analyzing network traffic (`.pcap` files), I mapped an adversary's journey from initial reconnaissance to full data exfiltration and the establishment of persistence using the **Cyber Kill Chain** framework.

**Scenario:** On July 1, 2025, unauthorized access was detected on the `cloud.vantage.tech` subdomain. The attacker bypassed authentication, compromised OpenStack API credentials, and exfiltrated sensitive PII from Swift object storage.

---

## 🛡️ Executive Summary
* **Target:** OpenStack Infrastructure-as-a-Service (IaaS).
* **Attack Vector:** Subdomain fuzzing followed by Credential Brute Force.
* **Impact:** Exfiltration of `user-details.csv` (28 records) and `employee-details.csv` (50 records).
* **Persistence:** Unauthorized creation of a new administrative user `jellibean`.

---
### 📅 Forensic Timeline (July 1, 2025)

| Time (UTC) | Phase | Event | Source/Artifact |
| :--- | :--- | :--- | :--- |
| **09:38:00** | Reconnaissance | Automated fuzzing of `vantage.tech` | `ffuf/2.1.0` |
| **09:40:07** | Initial Access | Successful login to Horizon Dashboard | `admin` account |
| **09:40:29** | Harvesting | Download of `admin-openrc.sh` | API Access Tab |
| **09:41:44** | Discovery | Enumeration of Swift Object Storage | `openstacksdk` |
| **09:45:23** | Exfiltration | Stole `user-details.csv` (28 PII records) | GET /v1/AUTH_.../ |
| **09:45:47** | Exfiltration | Stole `employee-details.csv` (50 records) | GET /v1/AUTH_.../ |
| **09:48:02** | Persistence | Created rogue user `jellibean` | POST /v3/users |
| **09:49:15** | Persistence | Granted `admin` role to `jellibean` | PUT /v3/roles/ |

## 🕵️ Technical Investigation & Kill Chain Mapping

### 1. Reconnaissance
The attacker used **ffuf v2.1.0** to perform directory and subdomain enumeration.
* **Finding:** Identified the `cloud.vantage.tech` dashboard.
* **Artifact:** HTTP GET requests with the User-Agent `Fuzz Faster U Fool v2.1.0-dev`.

### 2. Exploitation
The attacker targeted the Horizon login portal and successfully authenticated using admin credentials at **09:40:07 UTC**.

### 3. Installation & Credential Harvesting
Once inside the dashboard, the attacker navigated to **Project > API Access**.
* **Artifact:** Downloaded `admin-openrc.sh`.
* **Impact:** This file contained the `OS_AUTH_URL` and credentials required to bypass the Horizon GUI. The attacker transitioned to using the **OpenStack SDK/CLI** for programmatic environment traversal.

### 4. Actions on Objectives (Exfiltration)
The attacker systematically enumerated and drained Swift object storage containers using a stolen `X-Auth-Token`.
* **Target Containers:** `dev-files`, `employee-data`, and `user-data`.
* **Exfiltration (09:45:23 UTC):** Downloaded `user-details.csv` (28 PII records).
* **Exfiltration (09:45:47 UTC):** Downloaded `employee-details.csv` (50 internal staff records).
* **Tooling:** Traffic analysis shows the `User-Agent: openstacksdk/4.6.0`, indicating automated or scripted exfiltration.

### 5. Persistence
To ensure long-term access, the attacker performed a two-step persistence maneuver:
* **Account Creation:** Issued a `POST` request to `/v3/users` to create the user `jellibean` (Password: `P@$$word`).
* **Privilege Escalation:** Assigned the **"admin" role** to the `jellibean` account, granting full control over the cloud environment even if original credentials are reset.

---

## 🔍 Threat Hunting Indicators (IOCs)
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP Address** | `134.209.71.220` | Attacker Source IP |
| **User-Agent** | `ffuf/2.1.0` | Initial Discovery Tooling |
| **User-Agent** | `openstacksdk/4.6.0` | API Interaction & Exfiltration Tool |
| **Filename** | `user-details.csv` | Customer PII Leak |
| **Filename** | `employee-details.csv` | Internal Corporate Intelligence Leak |
| **Persistence** | `jellibean` | Rogue Administrative Account |

---

## 💡 Recommendations & Remediation
* **Identity:** Implement Multi-Factor Authentication (MFA) for the Horizon dashboard and API access.
* **Secret Management:** Rotate all API credentials and move away from plaintext `.sh` configuration files to a secure vault system.
* **Monitoring:** Enable real-time alerts for any `POST` requests to the Keystone API involving user creation or role assignment.
* **Network:** Restrict OpenStack API endpoints to internal IP ranges or VPN access only.

---

## 🛠️ Tools Used
* **Wireshark:** Network traffic analysis and HTTP stream carving.
* **OpenStack SDK:** Analysis of API interaction patterns.

---
*This investigation was completed as part of the **Vantage Sherlock** on Hack The Box.*

<img width="1330" height="620" alt="Screenshot (1714)" src="https://github.com/user-attachments/assets/7d2f5698-07c7-40df-9a09-6043e9ffd590" />
https://labs.hackthebox.com/achievement/sherlock/2413013/1162

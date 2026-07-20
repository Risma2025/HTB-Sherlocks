# HTB-Sherlock-Vantage-Writeup

## Scenario

> A small company moved some of its resources to a private cloud installation. The developers left the redirect to the dashboard on their web server. The security team got an email from the alleged attacker stating that the user data was leaked. It is up to you to investigate the situation.

---

Two capture files are provided:

| File | Description |
|---|---|
| `web-server.2025-07-01.pcap` | Traffic to/from the public-facing web server and the Horizon login dashboard | 
| `controller.2025-07-01.pcap` | Traffic to/from the OpenStack controller node (Keystone / Swift API) |

---

### Task 1 — What tool did the attacker use to fuzz the web server? (Format: nmap@7.80)

**Answer:** `ffuf@2.1.0`

Every fuzzing request carries a distinctive `User-Agent` header set by the tool. Filtering HTTP requests and inspecting the `User-Agent` field in the packet details pane (or filtering directly on the string) exposes the tool and its version.

```
http.user_agent contains "Fuzz"
```
<img width="1366" height="546" alt="Vantage-Task1-01" src="https://github.com/user-attachments/assets/7c7bd9f5-8579-4cd2-847d-b40425e6d406" />

Expanding one of the matched HTTP request headers shows `User-Agent: Fuzz Faster U Fool/2.1.0`, which is ffuf's default UA string.

<img width="1366" height="117" alt="Vantage-Task1-02" src="https://github.com/user-attachments/assets/f54c104d-b0a2-44dc-99a4-9f1a75dae432" />

---

### Task 2 — Which subdomain did the attacker discover?

**Answer:** `cloud`

ffuf was brute-forcing the `Host` header (vhost/subdomain fuzzing) against the web server. Most fuzzed subdomains return a generic "not found" page of identical size (`596` bytes), so filtering out that size isolates the one response that actually differs — the successful hit.

```
ip.dst == 117.200.21.26 && http.response.code == 200 && frame.len != 596
```
<img width="1366" height="385" alt="Vantage-Task2-01" src="https://github.com/user-attachments/assets/4cebd825-4ebd-4f9c-9a5e-f94284d0efb3" />

Following that stream shows the server responding for the `Host: cloud.vantage.tech` request, confirming `cloud` as the valid subdomain that fronts the OpenStack Horizon dashboard.

<img width="1366" height="508" alt="Vantage-Task2-02" src="https://github.com/user-attachments/assets/390ab99f-b22e-4a86-8ac0-ee389b87430b" />

---

### Task 3 — How many login attempts did the attacker make before successfully logging in to the dashboard?

**Answer:** `3`

Once `cloud.vantage.tech` was known, the attacker moved to the login form. Filtering on the login URI isolates every POST attempt to the dashboard's auth endpoint; each attempt can then be checked (in order) for its resulting status code.

```
http.host == "cloud.vantage.tech" && http.request.uri == "/dashboard/auth/login/"
```

<img width="1366" height="264" alt="Vantage-Task3-login_attempts" src="https://github.com/user-attachments/assets/b35803e8-b107-44a9-9941-af32ece38567" />

Focus only the source IP from 117.200.221.26, there is total 4 attempts, so we can assume the login attempts was “3” before successfully logging in to the dashboard.

---

### Task 4 — When did the attacker download the OpenStack API remote access config file? (UTC)

**Answer:** `2025-07-01 09:40:29`

After authenticating, the attacker browsed to the dashboard's **Project → API Access** section and pulled the OpenRC file, which bundles the API endpoint URL, project ID, and credentials needed to talk to OpenStack directly instead of through the web UI.

```
http contains "admin-openrc.sh"
```
<img width="1366" height="331" alt="Vantage-Task4" src="https://github.com/user-attachments/assets/464b6e3d-3f83-4210-b015-b9135166f555" />

The matching `GET /dashboard/project/api_access/openrc/` request (served as `admin-openrc.sh`) is timestamped in the Wireshark frame details; converting the frame's epoch/relative time to UTC gives `09:40:29`.

---

### Task 5 — When did the attacker first interact with the API on the controller node? (UTC)

**Answer:** `2025-07-01 09:41:44`

Switching to `controller.2025-07-01.pcap`, the attacker's first request to the controller can be isolated by filtering on the attacker's source IP together with the HTTP protocol, then sorting by time and taking the earliest frame.

```
ip.src == 117.200.21.26 && http
```
<img width="1366" height="630" alt="Vantage-Task5" src="https://github.com/user-attachments/assets/3b5d6c1c-1e21-4c70-900f-b0564c206982" />

The first HTTP request in this filtered list is the initial Keystone token request made using the credentials pulled from the OpenRC file. Its frame timestamp gives `09:41:44 UTC`.

---

### Task 6 — What is the project ID of the default project accessed by the attacker?

**Answer:** `9fb84977ff7c4a0baf0d5dbb57e235c7`

First, I downloaded the OpenRC file (admin-openrc.sh) from Wireshark (view Task 4). This file contained the project details, including the `Project ID`  value ( `OS_PROJECT_ID`).

<img width="1366" height="603" alt="Vantage-Task6" src="https://github.com/user-attachments/assets/56c67783-ad84-47c4-b998-ad6a4901eb5c" />


---

### Task 7 — Which OpenStack service provides authentication and authorization for the OpenStack API?

**Answer:** `keystone`

The service named **Keystone** — OpenStack's Identity service, responsible for issuing and validating auth tokens (`X-Auth-Token`) used on every subsequent API call.

---

### Task 8 — What is the endpoint URL of the Swift service?

**Answer:** `http://134.209.71.220:8080/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7`

The same service catalog from the Keystone token response also lists the object-storage (Swift) endpoint. Swift endpoint URLs always follow the pattern `/v1/AUTH_<project_id>`, using the project ID captured in Task 6.

```
http.request.uri contains "/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7"

```
<img width="1366" height="293" alt="Vantage-Task8" src="https://github.com/user-attachments/assets/9e6e50d6-e5ad-4f57-91f2-89d44d7257a8" />

---

### Task 9 — How many containers were discovered by the attacker?

**Answer:** `3`

After obtaining the Swift endpoint, the attacker listed the account's containers with a JSON-formatted GET request against the root of that endpoint.

```
http.request.uri == "/v1/AUTH_9fb84977ff7c4a0baf0d5dbb57e235c7?format=json"
```

Following this HTTP stream reveals a JSON array listing three containers: `dev-files`, `employee-data`, and `user-data`.

---

### Task 10 — When did the attacker download the sensitive user data file? (UTC)

**Answer:** `2025-07-01 09:45:23`

With the containers enumerated, the attacker requested the object inside `user-data`, downloading the CSV that holds customer PII. Filtering directly on the filename isolates that specific transfer.

```
http.request.uri contains "user-details.csv"
```

The frame timestamp on this GET request (and its `200 OK` response) converts to `09:45:23 UTC`.

---

### Task 11 — How many user records are in the sensitive user data file?

**Answer:** `28`

With the `user-details.csv` request/response packet selected, right-clicking it and choosing **Follow → HTTP Stream** reconstructs the full CSV body that was transferred in the response, exactly as the attacker received it.

```
http.request.uri contains "user-details.csv"
```

Counting the data rows in the reconstructed CSV (excluding the header row) gives 28 individual user records — full names, emails, and phone numbers.

---

### Task 12 — For persistence, the attacker created a new user with admin privileges. What is the username of the new user?

**Answer:** `jellibean`

To guarantee continued access even if the stolen admin credentials were rotated, the attacker called Keystone's identity API to provision a brand-new account. Filtering on the users endpoint isolates that POST request.

```
http.request.uri contains "/identity/v3/users"
```

Following the HTTP stream shows the JSON request body sent to `POST /v3/users`, with `"name": "jellibean"` as the new account's username.

---

### Task 13 — What is the password of the new user?

**Answer:** `P@$$word`

The same POST request body used to create the `jellibean` account (Task 12) also carries the account's initial password in cleartext, since the request was sent over unencrypted HTTP.

```
http.request.uri contains "/identity/v3/users"
```

Reading further into that Follow HTTP Stream output, the JSON `"password"` field shows the value `P@$$word`, set at the same time as the account creation.

---

### Task 14 — What is the MITRE ATT&CK technique ID of the technique in Task 12?

**Answer:** `T1136.003`

Creating a new privileged account inside a compromised cloud environment to survive credential rotation maps directly to the MITRE ATT&CK **Persistence** tactic (TA0003), specifically technique **T1136 – Create Account**, sub-technique **.003 – Cloud Account** — since the account (`jellibean`) was provisioned via the OpenStack (cloud) Keystone identity API rather than a local OS account.

---

## Attack Summary — Cyber Kill Chain mapping

| Stage | Action | Evidence |
|---|---|---|
| Reconnaissance | Subdomain fuzzing with `ffuf@2.1.0` discovers `cloud.vantage.tech` | `web-server.pcap` |
| Weaponization / Delivery | Targeting Horizon login at `/dashboard/auth/login/` | `web-server.pcap` |
| Exploitation | 3 failed logins, 4th attempt succeeds with `admin:StrongAdminSecret` (`302 Found`) | `web-server.pcap` |
| Installation | Downloads `admin-openrc.sh` at `09:40:29 UTC` | `web-server.pcap` |
| Command & Control | Uses stolen token to query Keystone at `09:41:44 UTC`; discovers project ID `9fb84977ff7c4a0baf0d5dbb57e235c7` | `controller.pcap` |
| Actions on Objectives | Lists 3 Swift containers, exfiltrates `user-details.csv` (28 records) at `09:45:23 UTC`; creates admin backdoor user `jellibean` (`T1136.003`) | `controller.pcap` |

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

---

## 🔍 Indicators of Compromise (IOCs)
| Type | Value | Description |
| :--- | :--- | :--- |
| **IP Address** | `134.209.71.220` | Attacker Source IP |
| **User-Agent** | `ffuf/2.1.0` | Initial Discovery Tooling |
| **User-Agent** | `openstacksdk/4.6.0` | API Interaction & Exfiltration Tool |
| **Filename** | `user-details.csv` | Customer PII Leak |
| **Filename** | `employee-details.csv` | Internal Corporate Intelligence Leak |
| **Persistence** | `jellibean` | Rogue Administrative Account |

---
<img width="1330" height="620" alt="Vantage-Achievement-Badge" src="https://github.com/user-attachments/assets/269cb388-a8b3-46e9-a530-92a43a1d768c" />

https://labs.hackthebox.com/achievement/sherlock/2413013/1162

---

## 📬 Contact & Profiles
**LinkedIn:** [risma-fareedh](https://www.linkedin.com/in/risma-fareedh-066a19199) | **Hack The Box:** [HTB Profile](https://profile.hackthebox.com/profile/019d51eb-d379-72f0-ad54-5a4e2121b80b) | **GitHub:** [Risma2025](https://github.com/Risma2025)

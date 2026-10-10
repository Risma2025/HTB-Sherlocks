# PhantomRing — HTB Sherlock Writeup
### Static Malware Analysis on a Linux Post-Exploitation Agent

---

## 📖 Scenario

> The SOC intercepted a suspicious binary (`agent`) sitting in `/var/tmp` on a Linux server, attempting outbound connections. It's suspected to be a post-exploitation agent. Task: statically analyze it to identify its capabilities, extract IOCs, and profile the threat actor's infrastructure — **without ever executing it.**

---

## 🧠 What is Static Malware Analysis?

Static analysis is the process of examining a binary's code, structure, and embedded metadata to understand **what it does**, **how it communicates**, and **how to detect it** — all without executing the file. It's the safest first step in any malware investigation: no sandbox required, no risk of the sample phoning home or detonating on your machine.

## 🧰 The Essential Starter Toolkit

You only need a handful of tools, all built into Linux by default:

| Tool | Purpose |
|---|---|
| `file` | Identifies file type — architecture, 32/64-bit, stripped or not stripped |
| `sha256sum` | Generates a unique cryptographic fingerprint of the file |
| `strings` | Extracts readable/printable text hidden inside the binary |
| `objdump` | Disassembles machine code back into human-readable assembly |

---

## 🔧 Core Techniques

### 1. Fingerprint the file first
Always hash the sample before anything else — it's an immutable reference you can cross-check against VirusTotal / MalwareBazaar.

```bash
sha256sum agent
```

<img width="1336" height="610" alt="Virustotal-analyis" src="https://github.com/user-attachments/assets/1cc53d02-288a-4726-adbe-ce61701ffc51" />

`https://www.virustotal.com/gui/file/2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5/behavior`

### 2. Identify file characteristics

```bash
file agent
```
Check whether it's **stripped** or **not stripped**. A *not stripped* binary keeps its original function names intact — meaning command-handler functions like `<cmd_users>` or `<cmd_privesc>` show up directly in the symbol table, turning feature-enumeration into a simple grep instead of manual reversing.

### 3. Extract Indicators of Compromise (IOCs)

`strings` pulls printable ASCII text — IP addresses, file paths, config data, error messages.

```bash
strings -a agent | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
```

Interesting paths tell their own story: `/var/run/utmp` → spying on logged-in users; `/sys/kernel/debug/tracing/tracing_on` → blinding kernel tracing/logging.

### 4. Read disassembly when text fails

> ⚠️ **Golden Rule:** Never trust `strings` alone for numeric values — ports, sleep timers, buffer sizes. These are compiled as raw integers, not text, so `strings` skips them entirely. You have to read the assembly.

On x86-64 Linux, the first argument to a function call is loaded into `edi`/`rdi` right before the `call` instruction:

```bash
objdump -d -M intel agent | grep -B5 "call.*<function_name>"
```

Then convert whatever hex value you find into decimal:
```bash
printf "%d\n" 0xHEXVALUE
```

---

## 🚩 Task-by-Task Walkthrough

### Task 1 — What is the SHA256 hash of the malicious binary?

Unzip the zip file first
```bash
unzip -j -P hacktheblue PhantomRing.zip

```

<img width="572" height="109" alt="unzipping" src="https://github.com/user-attachments/assets/c937bd26-b159-4866-83cf-43f970f97bcf" />


```bash
sha256sum agent

```
<img width="628" height="80" alt="TASK-1" src="https://github.com/user-attachments/assets/417fd5a7-74ee-485b-af72-b525ed0f6952" />

---

### Task 2 — What is the IP address hardcoded in the binary for C2 communication?
IPs are plain text, so a regex-filtered `strings` search finds them instantly.
```bash
strings -a agent | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
```
<img width="721" height="79" alt="TASK-2" src="https://github.com/user-attachments/assets/be2014f1-fd72-42b3-9e6d-0b3afb5b2061" />

---

### Task 3 — What port does the agent connect to on the C2 server?

`strings -a agent | grep 4445` returns **nothing** — port numbers are raw integers, not text. Confirm the binary uses `io_uring` for networking, then find the `htons()` call:
```bash
objdump -d -M intel agent | grep -B5 "call.*htons"
```

Convert the hex constant loaded into `edi`:
```bash
printf "%d\n" 0x115d
# 4445
```
<img width="687" height="221" alt="TASK-3" src="https://github.com/user-attachments/assets/a002b906-7233-4715-ae07-7e8ce950ca28" />

---

### Task 4 — How many seconds does the agent wait before attempting to reconnect after a failed connection?
Same trick as Task 3 — look for the argument loaded before `sleep()`:
```bash
objdump -d -M intel agent | grep -B2 "call.*sleep@plt"
```

```bash
printf "%d\n" 0x78
# 120
```
<img width="595" height="232" alt="TASK-4" src="https://github.com/user-attachments/assets/2a31fed2-82c6-4f14-9bf0-59d25c8eb645" />

---

### Task 5 — How many different commands does the agent support? (excluding invalid commands)
Since the binary is **not stripped**, every command handler keeps its symbol name:
```bash
objdump -d agent | grep "^0000.*<cmd_"
```
<img width="671" height="233" alt="TASK-5" src="https://github.com/user-attachments/assets/26e2ca18-f8fc-4c22-b900-28dec8bc9537" />

11 handlers. Anything else falls through to the invalid-command branch (`"[*] 404 Command not found [*]"`), which doesn't count.



---

### Task 6 — What Linux kernel interface does this malware abuse to evade EDR syscall monitoring?

```bash
strings -a agent | grep -i "io_uring"
```
<img width="1010" height="475" alt="TASK-6" src="https://github.com/user-attachments/assets/55e2ee41-3acd-4c0b-ac3d-5f73682b1dca" />

Instead of calling `connect()`, `read()`, `write()` directly, the agent submits I/O through **io_uring** queues — bypassing the syscalls most EDR tools hook.


---

### Task 7 —What file does the agent read to enumerate logged-in users?
```bash
strings -a agent | grep -i utmp
```
<img width="608" height="93" alt="TASK-7" src="https://github.com/user-attachments/assets/24af063f-b4eb-4457-8efb-677459717177" />



---

### Task 8 — What directory does the agent scan when searching for SUID binaries for privilege escalation?

```bash
strings -a agent | grep -B2 -A2 "SUID"
```
<img width="580" height="139" alt="TASK-8" src="https://github.com/user-attachments/assets/5b42ebd9-30bc-4722-a32a-87a4bd0aae26" />

---

### Task 9 — What string does the agent search for in /proc/[pid]/maps to identify security tools using eBPF?
```bash
strings -a agent | grep -i "bpf-map\|anon_inode"
```
<img width="631" height="80" alt="TASK-9" src="https://github.com/user-attachments/assets/40ed50bd-24cd-4356-bd7c-032d1c9b221d" />

The kernel exposes this pseudo-file name in `/proc/[pid]/maps` for any process with an eBPF map loaded — the agent greps for it to fingerprint (and kill) eBPF-based security tools.


---

### Task 10 — What is the full path of the first tracing file the agent attempts to disable?

```bash
strings -a agent | grep tracing
```
<img width="520" height="110" alt="TASK-10" src="https://github.com/user-attachments/assets/e1857a9b-ed44-44d3-b207-e7ae62a27a83" />

⚠️ `strings` dumps these in binary layout order, **not necessarily execution order** — always confirm with disassembly:
```bash
objdump -d -M intel agent | grep -A25 "<cmd_killbpf>:"
```
<img width="1314" height="446" alt="TASK-10-2" src="https://github.com/user-attachments/assets/637a911a-7510-44d1-bd2b-bd9b738b52db" />

The `lea` instructions load `tracing_on` first, then `set_event`, then `current_tracer` — confirming the processing order.

```bash
objdump -s -j .rodata agent | grep -A2 "^ 5330"
```
<img width="706" height="108" alt="TASK-10-3" src="https://github.com/user-attachments/assets/4af4f6af-852e-468b-b81b-780b34282926" />

---

### Task 11 — What procfs path does the agent read to find its own executable location before self-destruction?
```bash
strings -a agent | grep "proc/self"
```
<img width="620" height="74" alt="TASK-11" src="https://github.com/user-attachments/assets/bb4fc802-72eb-4f33-ade6-bb0bef7200c7" />

This kernel-maintained symlink always points to a process's own executable path — letting the agent find and delete itself regardless of where it was launched from.

---

### Task 12 — What command string is compared by the agent to trigger deletion of its own binary?
The internal function is named `cmd_selfdestruct`, and there's even a status string `"Agent will self-destruct"`. **Don't trust either of these** — dump the raw `.rodata` bytes instead:

```bash
-s -j .rodata agent | less
```

<img width="1329" height="522" alt="TASK-12-1" src="https://github.com/user-attachments/assets/5a03083f-ee0c-4a53-9d28-222667d36868" />

```bash
objdump -s -j .rodata agent | grep -A5 "^ 54a0"
```
<img width="682" height="148" alt="TASK-12-2" src="https://github.com/user-attachments/assets/04e65a5e-0d37-4c8e-bbc1-fc9a7c4b4429" />

Reading the ASCII across the line break: `sdes` + `truct` = **`sdestruct`** — not "selfdestruct.

---

<img width="1339" height="616" alt="htb-sherlock-phantomring-solved" src="https://github.com/user-attachments/assets/88d7378a-68e1-48d0-9f8d-ba60c832c4d1" />
https://labs.hackthebox.com/achievement/sherlock/2413013/1296
---

## ⚠️ Disclaimer

> All writeups and tools in this repository are for educational and authorized testing purposes only. All activities documented here were performed within designated Hack The Box lab environments.

---
## 📬 Connect With Me

Thank you for reading this write-up! If you have any questions, suggestions, or want to discuss cybersecurity and digital forensics, feel free to reach out through any of the platforms below:
* **LinkedIn:** [risma-fareedh](https://www.linkedin.com/in/risma-fareedh-066a19199)  
* **Hack The Box:** [HTB Profile](https://profile.hackthebox.com/profile/019d51eb-d379-72f0-ad54-5a4e2121b80b) 
* **GitHub:** [Risma2025](https://github.com/Risma2025)

---
*Developed by **Risma Fareedh** | Cybersecurity Analyst / Digital Forensics / SOC / CTF Player / Aspiring Purple Teamer* 🛡️


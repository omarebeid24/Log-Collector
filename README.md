Log-Collector
Dependency-free PowerShell first-look incident response collector for Windows.
`Log-Collector` runs on a Windows machine and collects investigator-friendly summaries from local Windows Event Logs. It is designed for quick triage when you need to understand possible authentication abuse, persistence activity, PowerShell misuse, Defender events, and audit coverage gaps without installing external tools or modules.
> This script is a first-look triage tool, not a full forensic investigation platform. A clean report does not prove a machine is clean.
Features
Collects Windows Event Log activity from the last `N` days
Produces clean decorated `.txt` evidence files instead of CSV/Excel-style output
Includes timestamps for event-level records and first/last seen times for grouped findings
Highlights failed logons, successful logons, risky logon types, and explicit credential use
Detects successful logons after repeated failures
Reviews new services, scheduled tasks, account changes, and privilege-related events
Flags suspicious PowerShell indicators when PowerShell logging is available
Reports Defender/security changes and detection activity
Identifies log clearing and anti-forensics indicators
Documents audit coverage limitations instead of hiding missing telemetry
Runs on PowerShell 5.1+ with no external dependencies
Requirements
Windows 10, Windows 11, or Windows Server
PowerShell 5.1 or later
Administrator PowerShell session recommended
Local event logs must still exist and contain relevant telemetry
Best results require Windows auditing to be enabled before the incident or test activity occurs. The script can only analyze logs that exist.
Quick Start
Download the script and run PowerShell as Administrator.
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\IR-FirstLook.ps1
.\IR-FirstLook.ps1
```
Run with a custom lookback window and output folder:
```powershell
.\IR-FirstLook.ps1 -DaysBack 7 -OutputPath C:\IR_Report
```
Run with verbose console output:
```powershell
.\IR-FirstLook.ps1 -DaysBack 3 -VerboseMode
```
If your execution policy blocks the script, launch it directly with bypass:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\IR-FirstLook.ps1
```
Parameters
Parameter	Description	Example
`-DaysBack`	Number of days of event logs to review.	`-DaysBack 7`
`-OutputPath`	Folder where reports and evidence files will be written.	`-OutputPath C:\IR_Report`
`-VerboseMode`	Enables additional progress output in the console.	`-VerboseMode`
Output
The script creates a timestamped output folder containing summary reports, structured findings, and decorated text evidence files.
Common outputs include:
```text
IR_Summary.html
IR_Summary.txt
Findings.json
Execution_Metadata.txt
Findings_Decorated.txt
FailedLogons_Decorated.txt
SuccessfulLogons_Decorated.txt
ExplicitCredentialUse_Decorated.txt
PrivilegedLogons_Decorated.txt
SuccessAfterFailures_Decorated.txt
NewServices_Decorated.txt
ScheduledTasks_Decorated.txt
PowerShellActivity_Decorated.txt
SuspiciousPowerShell_Decorated.txt
DefenderEvents_Decorated.txt
AuditCoverage_Decorated.txt
LogQueryWarnings_Decorated.txt
```
Each event-level evidence file should include useful investigation fields such as:
`TimeCreated`
`EventID`
`LogName`
`ProviderName`
`RecordId`
User/account fields when available
Source IP/workstation fields when available
Command line or event message details when available
Grouped findings use `FirstSeen` and `LastSeen` when multiple events are summarized into one finding.
Detection Areas
Authentication Activity
Reviews Windows Security events related to logon behavior, including:
Failed logons
Successful logons
Risky logon types
Remote interactive logons
Explicit credential use
Successful logons after repeated failures
Relevant event IDs may include `4624`, `4625`, `4648`, `4672`, and related account activity events.
Account And Privilege Changes
Highlights local account and group activity, including:
New user creation
User account changes
Local group membership changes
Administrator or Remote Desktop Users group additions
Special privilege assignment events
Persistence Indicators
Reviews persistence-related telemetry such as:
New Windows services
Scheduled task activity
Suspicious service paths
Service creation from writable locations such as user profile, temp, or public directories
PowerShell Activity
Reviews PowerShell logs when available and flags suspicious indicators such as:
Encoded commands
Download cradle patterns
Base64 decoding patterns
Suspicious process launch patterns
Security tooling tampering commands
Log clearing attempts
Normal PowerShell lifecycle noise should be treated carefully. Not every PowerShell event is malicious.
Defender And Security Changes
Reviews Microsoft Defender and security-related events, including:
Defender detections
Defender configuration changes
Protection state changes
Security product activity
Defender configuration changes can be noisy during normal platform updates. Review timestamps and surrounding activity before treating them as malicious.
Anti-Forensics
Looks for signs of log clearing or audit tampering, including:
Security log clearing
PowerShell log clearing
Audit policy changes
Missing or disabled logs
Interpreting Results
The script assigns severity to help triage quickly:
Severity	Meaning
`Critical`	Strong indicator requiring immediate investigation.
`High`	Suspicious behavior with meaningful investigation value.
`Medium`	Potentially suspicious or important administrative activity.
`Low`	Weak signal or context item.
`Info`	Environmental or audit coverage information.
Do not treat severity as a verdict. Treat it as a queue for investigation.
For example:
A new service in `C:\Windows\System32` may be normal.
A new service running from `C:\Users\Public` is more suspicious.
Event ID `4648` explicit credential use may be normal Windows activity or lateral movement depending on process, account, and source.
Event ID `5007` Defender configuration changes may be normal update noise or tampering depending on context.
Validation And Safe Testing
Do not infect a VM with real malware just to test this script. Use controlled telemetry simulations instead.
Useful safe tests include:
Failed logon attempts using a test account
Successful logon after several failed attempts
`runas` activity to generate explicit credential use
Creating and deleting a harmless test service
Creating and deleting a harmless scheduled task
Running a harmless encoded PowerShell command
Using the EICAR test file to validate Defender detection logging
Creating and removing a temporary local user and group membership
Always test inside a disposable VM snapshot and clean up after each test.
Example Test Commands
Create a temporary test user:
```powershell
net user IRTestUser P@ssw0rd123! /add
```
Generate explicit credential use:
```powershell
runas /user:.\IRTestUser cmd
```
Create a harmless service:
```powershell
sc.exe create TestIRService binPath= "C:\Windows\System32\cmd.exe /c echo IR test service" start= demand
```
Delete the test service:
```powershell
sc.exe delete TestIRService
```
Create a harmless scheduled task:
```powershell
schtasks /create /tn "IRTestTask" /tr "cmd.exe /c echo IR test" /sc once /st 23:59
```
Delete the scheduled task:
```powershell
schtasks /delete /tn "IRTestTask" /f
```
Run a harmless encoded PowerShell command:
```powershell
$cmd = 'Write-Output "IR encoded command test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```
Remove the temporary test user:
```powershell
net user IRTestUser /delete
```
Limitations
The script only analyzes telemetry present in local Windows logs.
Missing logs, disabled audit policies, or overwritten logs will reduce visibility.
Some detections depend on audit policy configuration, such as process creation logging.
PowerShell visibility depends on available PowerShell logs and logging configuration.
The script does not replace disk forensics, memory forensics, EDR review, malware analysis, or enterprise SIEM investigation.
Administrator privileges are strongly recommended for complete Security log access.
Recommended Follow-Up
If the report shows suspicious activity, review:
Source IP and workstation names
Target usernames
Logon type
Process name and command line
Service or scheduled task path
Defender timeline
Nearby events before and after the suspicious timestamp
For a stronger investigation, combine this script with:
Autoruns review
Running process review
Active network connection review
Installed programs review
Local users and groups review
Defender threat history
EDR or SIEM telemetry when available
Project Status
This project is intended as a practical Windows first-look triage collector. It is useful for lab testing, learning incident response workflow, and quickly collecting local evidence during suspicious activity review.
Contributions that improve parsing accuracy, reduce false positives, or add safer evidence collection are welcome.

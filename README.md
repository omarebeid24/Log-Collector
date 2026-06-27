# Log-Collector

PowerShell first-look incident response collector for Windows.

`Log-Collector` collects local Windows Event Log evidence and generates clean `.txt`, `.html`, and `.json` reports for quick triage of suspicious logons, PowerShell activity, new services, scheduled tasks, Defender events, and audit coverage gaps.

> This is a triage tool, not proof that a machine is clean.

## Features

- Runs on PowerShell 5.1+ with no external modules
- Collects Windows Event Logs from the last `N` days
- Outputs clean decorated `.txt` evidence files
- Includes timestamps for event-level records
- Tracks failed logons, successful logons, risky logon types, and explicit credential use
- Detects successful logons after repeated failures
- Reviews account changes, privilege events, new services, and scheduled tasks
- Flags suspicious PowerShell activity when logging is available
- Reports Defender/security changes and possible anti-forensics activity
- Documents missing logs or weak audit coverage

## Requirements

- Windows 10, Windows 11, or Windows Server
- PowerShell 5.1+
- Administrator PowerShell session recommended
- Existing Windows logs with relevant telemetry

The script can only analyze logs that exist. If auditing was disabled or logs were cleared, the report will show those limitations.

## Usage

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\IR-FirstLook.ps1
.\IR-FirstLook.ps1
```

Run with a custom time window and output folder:

```powershell
.\IR-FirstLook.ps1 -DaysBack 7 -OutputPath C:\IR_Report
```

Run with verbose output:

```powershell
.\IR-FirstLook.ps1 -DaysBack 3 -VerboseMode
```

If execution policy blocks the script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\IR-FirstLook.ps1
```

## Parameters

| Parameter | Description |
| --- | --- |
| `-DaysBack` | Number of days of logs to review. |
| `-OutputPath` | Folder where reports will be saved. |
| `-VerboseMode` | Shows more progress details in the console. |

## Output Files

The script creates a timestamped report folder with files such as:

```text
Execution_Metadata.txt
FailedLogons_BySourceIP_Decorated.txt
FailedLogons_ByUser_Decorated.txt
Findings.json
Findings_Decorated.txt
IR_Summary.html
IR_Summary.txt
NewServices_Decorated.txt
```

Event-level files include fields such as `TimeCreated`, `EventID`, `LogName`, `ProviderName`, `RecordId`, account details, source IPs, process names, and command lines when available.

## Detection Coverage

| Area | Examples |
| --- | --- |
| Authentication | Failed logons, successful logons, risky logon types, explicit credential use |
| Privilege Activity | Admin logons, account changes, group membership changes |
| Persistence | New services, scheduled tasks, suspicious service paths |
| PowerShell | Encoded commands, suspicious keywords, log clearing attempts |
| Defender | Detection events, configuration changes, protection state changes |
| Anti-Forensics | Log clearing, audit policy changes, missing/disabled logs |

## Interpreting Results

Severity is a triage priority, not a final verdict.

| Severity | Meaning |
| --- | --- |
| `Critical` | Strong indicator requiring immediate investigation. |
| `High` | Suspicious behavior with meaningful risk. |
| `Medium` | Important activity that needs review. |
| `Low` | Weak signal or context item. |
| `Info` | Audit coverage or environment detail. |

Examples:

- A service created under `C:\Windows\System32` may be normal.
- A service created under `C:\Users\Public` is more suspicious.
- Defender `5007` events may be normal update noise or tampering.
- Explicit credential use `4648` can be normal admin activity or lateral movement.

## Safe Testing

Do not test this by infecting a VM with real malware. Use controlled simulations instead.

Safe test ideas:

- Create failed logons with a test account
- Log in successfully after repeated failures
- Use `runas` to generate explicit credential-use events
- Create and delete a harmless test service
- Create and delete a harmless scheduled task
- Run a harmless encoded PowerShell command
- Use the EICAR test file for Defender logging
- Create and remove a temporary local user

Example harmless service test:

```powershell
sc.exe create TestIRService binPath= "C:\Windows\System32\cmd.exe /c echo IR test service" start= demand
sc.exe delete TestIRService
```

Example encoded PowerShell test:

```powershell
$cmd = 'Write-Output "IR encoded command test"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encoded
```

## Limitations

- Does not replace full disk, memory, EDR, or SIEM investigation
- Depends on existing Windows logs
- Some detections require proper audit policy
- Process command-line visibility depends on 4688 auditing
- PowerShell visibility depends on PowerShell logging configuration

## Recommended Follow-Up

If the report shows suspicious activity, review:

- Source IP and workstation name
- Target username
- Logon type
- Process name and command line
- Service or scheduled task path
- Defender timeline
- Events before and after the suspicious timestamp

For deeper investigation, combine this with Autoruns, running processes, active network connections, installed programs, local users/groups, Defender history, and EDR/SIEM telemetry when available.

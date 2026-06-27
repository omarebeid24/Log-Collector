<#
.SYNOPSIS
    IR-FirstLook-TXT-v4.ps1 - Dependency-free Windows incident response first-look collector.

.DESCRIPTION
    Parses Windows Event Logs for the last N days and produces investigator-ready summaries and decorated TXT evidence files:
      - Authentication activity
      - Failed logon clustering
      - External IP activity
      - Risky logon types
      - Successful logons after repeated failures
      - Account and privilege changes
      - New services and scheduled tasks
      - PowerShell abuse indicators
      - Process creation indicators, if 4688 auditing exists
      - Defender/security changes
      - Log clearing / anti-forensics
      - Audit coverage limitations

    Designed for PowerShell 5.1+ with no external modules. Outputs clean TXT evidence files instead of CSV/Excel-style files.

.EXAMPLE
    .\IR-FirstLook.ps1

.EXAMPLE
    .\IR-FirstLook.ps1 -DaysBack 7 -OutputPath C:\IR_Report

.EXAMPLE
    .\IR-FirstLook.ps1 -DaysBack 3 -VerboseMode

.NOTES
    Best run as Administrator.
    This script can only analyze telemetry that exists. If auditing was not enabled,
    the report will state that clearly instead of hiding the limitation.
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 7,

    [string]$OutputPath = $(Join-Path -Path (Get-Location) -ChildPath ("IR_FirstLook_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))),

    [int]$MaxEventsPerLog = 0,

    [switch]$VerboseMode
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$RunStarted = Get-Date
$StartTime = (Get-Date).AddDays(-[Math]::Abs($DaysBack))
$ComputerName = $env:COMPUTERNAME
$UserName = "$env:USERDOMAIN\$env:USERNAME"

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:LogWarnings = New-Object System.Collections.Generic.List[object]
$Script:Coverage = New-Object System.Collections.Generic.List[object]

function Write-IRStatus {
    param([string]$Message)
    $stamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$stamp] $Message"
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Normalize-Value {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ($s -eq '-' -or $s -eq '::1' -or $s.Trim().Length -eq 0) { return '' }
    return $s.Trim()
}

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Detail,
        [object]$Evidence = $null
    )

    $score = switch ($Severity) {
        'Critical' { 100 }
        'High'     { 75 }
        'Medium'   { 40 }
        'Low'      { 15 }
        default    { 0 }
    }

    # Pull timeline fields into the finding itself so the Priority Findings view is not detached from time.
    $timeCreated = $null
    $firstSeen = $null
    $lastSeen = $null
    $eventId = ''
    $logName = ''
    $providerName = ''
    $recordId = ''

    if ($null -ne $Evidence) {
        $props = @($Evidence.PSObject.Properties.Name)
        if ($props -contains 'TimeCreated') { $timeCreated = $Evidence.TimeCreated }
        elseif ($props -contains 'SuccessTime') { $timeCreated = $Evidence.SuccessTime }
        elseif ($props -contains 'FirstSeen') { $timeCreated = $Evidence.FirstSeen }
        elseif ($props -contains 'LastSeen') { $timeCreated = $Evidence.LastSeen }

        if ($props -contains 'FirstSeen') { $firstSeen = $Evidence.FirstSeen }
        if ($props -contains 'FirstFailure') { $firstSeen = $Evidence.FirstFailure }
        if ($props -contains 'LastSeen') { $lastSeen = $Evidence.LastSeen }
        if ($props -contains 'SuccessTime') { $lastSeen = $Evidence.SuccessTime }
        if ($props -contains 'EventID') { $eventId = $Evidence.EventID }
        elseif ($props -contains 'Id') { $eventId = $Evidence.Id }
        if ($props -contains 'LogName') { $logName = $Evidence.LogName }
        if ($props -contains 'ProviderName') { $providerName = $Evidence.ProviderName }
        if ($props -contains 'RecordId') { $recordId = $Evidence.RecordId }
        elseif ($props -contains 'SuccessRecordId') { $recordId = $Evidence.SuccessRecordId }
    }

    $Script:Findings.Add([PSCustomObject]@{
        TimeCreated  = $timeCreated
        FirstSeen    = $firstSeen
        LastSeen     = $lastSeen
        Severity     = $Severity
        Score        = $score
        Category     = $Category
        Title        = $Title
        Detail       = $Detail
        EventID      = $eventId
        LogName      = $logName
        ProviderName = $providerName
        RecordId     = $recordId
        Evidence     = $Evidence
    }) | Out-Null
}

function Get-LogInfoSafe {
    param([string]$LogName)
    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $obj = [PSCustomObject]@{
            LogName       = $LogName
            Exists        = $true
            IsEnabled     = $log.IsEnabled
            RecordCount   = $log.RecordCount
            LastWriteTime = $log.LastWriteTime
            LogMode       = $log.LogMode
            MaximumSizeMB = [Math]::Round(($log.MaximumSizeInBytes / 1MB), 2)
            Error         = ''
        }
        $Script:Coverage.Add($obj) | Out-Null
        return $obj
    } catch {
        $obj = [PSCustomObject]@{
            LogName       = $LogName
            Exists        = $false
            IsEnabled     = $false
            RecordCount   = 0
            LastWriteTime = $null
            LogMode       = ''
            MaximumSizeMB = 0
            Error         = $_.Exception.Message
        }
        $Script:Coverage.Add($obj) | Out-Null
        return $obj
    }
}

function Get-WinEventsSafe {
    param(
        [string]$LogName,
        [int[]]$Ids,
        [datetime]$Start
    )

    function Invoke-EventQueryInternal {
        param([hashtable]$Filter)
        if ($MaxEventsPerLog -gt 0) {
            return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEventsPerLog -ErrorAction Stop)
        } else {
            return @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop)
        }
    }

    $all = @()
    $errors = New-Object System.Collections.Generic.List[object]

    try {
        # First try the efficient targeted query. Some Windows builds/providers are picky with large ID arrays,
        # so this is followed by a fallback query if it returns nothing or errors.
        $filter = @{ LogName = $LogName; StartTime = $Start }
        if ($Ids -and $Ids.Count -gt 0) { $filter['Id'] = $Ids }
        $all = @(Invoke-EventQueryInternal -Filter $filter)
    } catch {
        $errors.Add($_.Exception.Message) | Out-Null
        $all = @()
    }

    # Fallback: query the log by time only, then filter event IDs in PowerShell.
    # This specifically fixes cases where Security has events, but the Id-array query returns zero.
    if (($all.Count -eq 0) -and $Ids -and $Ids.Count -gt 0) {
        try {
            $filter2 = @{ LogName = $LogName; StartTime = $Start }
            $raw = @(Invoke-EventQueryInternal -Filter $filter2)
            $idSet = @{}
            foreach ($id in $Ids) { $idSet[[int]$id] = $true }
            $all = @($raw | Where-Object { $idSet.ContainsKey([int]$_.Id) })
            if ($raw.Count -gt 0 -and $all.Count -eq 0) {
                $Script:LogWarnings.Add([PSCustomObject]@{
                    LogName = $LogName
                    Ids     = ($Ids -join ',')
                    Error   = "Fallback query found $($raw.Count) event(s), but none matched this script's target event IDs. This may be normal depending on audit activity."
                }) | Out-Null
            }
        } catch {
            $errors.Add($_.Exception.Message) | Out-Null
        }
    }

    if ($all.Count -eq 0 -and $errors.Count -gt 0) {
        $Script:LogWarnings.Add([PSCustomObject]@{
            LogName = $LogName
            Ids     = ($Ids -join ',')
            Error   = (($errors | Select-Object -Unique) -join ' | ')
        }) | Out-Null
    }

    return @($all)
}

function ConvertTo-IRRecord {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $data = @{}
    try {
        [xml]$xml = $Event.ToXml()
        $idx = 0
        foreach ($d in @($xml.Event.EventData.Data)) {
            $name = [string]$d.Name
            if ([string]::IsNullOrWhiteSpace($name)) { $name = "Data$idx" }
            $value = ''
            if ($d.'#text') { $value = [string]$d.'#text' }
            elseif ($d.InnerText) { $value = [string]$d.InnerText }
            $data[$name] = $value
            $idx++
        }

        foreach ($node in @($xml.Event.UserData.ChildNodes)) {
            foreach ($child in @($node.ChildNodes)) {
                if ($child.Name -and -not $data.ContainsKey($child.Name)) {
                    $data[$child.Name] = [string]$child.InnerText
                }
            }
        }
    } catch {
        $data['ParseError'] = $_.Exception.Message
    }

    return [PSCustomObject]@{
        TimeCreated      = $Event.TimeCreated
        LogName          = $Event.LogName
        ProviderName     = $Event.ProviderName
        Id               = $Event.Id
        LevelDisplayName = $Event.LevelDisplayName
        MachineName      = $Event.MachineName
        RecordId         = $Event.RecordId
        Data             = $data
        Message          = $Event.Message
    }
}

function Get-EventField {
    param(
        [object]$Record,
        [string[]]$Names
    )

    foreach ($n in $Names) {
        if ($Record.Data -and $Record.Data.ContainsKey($n)) {
            $v = Normalize-Value $Record.Data[$n]
            if ($v.Length -gt 0) { return $v }
        }
    }
    return ''
}

function Get-LogonTypeName {
    param([string]$Type)
    switch ($Type) {
        '2'  { 'Interactive' }
        '3'  { 'Network' }
        '4'  { 'Batch' }
        '5'  { 'Service' }
        '7'  { 'Unlock' }
        '8'  { 'NetworkCleartext' }
        '9'  { 'NewCredentials' }
        '10' { 'RemoteInteractive/RDP' }
        '11' { 'CachedInteractive' }
        default { if ($Type) { "Unknown($Type)" } else { '' } }
    }
}

function Test-ValidIP {
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    $tmp = $null
    return [System.Net.IPAddress]::TryParse($IP, [ref]$tmp)
}

function Test-PrivateIP {
    param([string]$IP)

    if (-not (Test-ValidIP $IP)) { return $false }
    $addr = [System.Net.IPAddress]::Parse($IP)

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $addr.GetAddressBytes()
        if ($b[0] -eq 10) { return $true }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
        if ($b[0] -eq 127) { return $true }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
        return $false
    }

    if ($addr.IsIPv6LinkLocal -or $addr.IsIPv6SiteLocal -or $addr.IsIPv6Multicast) { return $true }
    if ($IP -eq '::1') { return $true }
    if ($IP.ToLower().StartsWith('fc') -or $IP.ToLower().StartsWith('fd')) { return $true }
    return $false
}

function Get-IPClass {
    param([string]$IP)
    if (-not (Test-ValidIP $IP)) { return 'None/Invalid' }
    if (Test-PrivateIP $IP) { return 'Private/Internal' }
    return 'External/Public'
}

function Test-SuspiciousPathOrCommand {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $patterns = @(
        '(?i)\bpowershell(\.exe)?\b.*\s-enc(odedcommand)?\b',
        '(?i)\bpowershell(\.exe)?\b.*\bhidden\b',
        '(?i)\bpowershell(\.exe)?\b.*\bbypass\b',
        '(?i)\bfrombase64string\b',
        '(?i)\binvoke-expression\b|\biex\b',
        '(?i)\bdownloadstring\b|\binvoke-webrequest\b|\bwebclient\b',
        '(?i)\bcertutil(\.exe)?\b.*-urlcache',
        '(?i)\bbitsadmin(\.exe)?\b',
        '(?i)\bmshta(\.exe)?\b.*http',
        '(?i)\brundll32(\.exe)?\b.*javascript',
        '(?i)\bregsvr32(\.exe)?\b.*(/i:|http|scrobj)',
        '(?i)\bwmic(\.exe)?\b.*process.*call.*create',
        '(?i)\bschtasks(\.exe)?\b.*(/create|/change)',
        '(?i)\bsc(\.exe)?\b.*create',
        '(?i)\bnet(\.exe)?\b.*localgroup.*administrators',
        '(?i)\bnet(\.exe)?\b.*user.*(/add|/active:yes)',
        '(?i)\bvssadmin(\.exe)?\b.*delete.*shadows',
        '(?i)\bwevtutil(\.exe)?\b.*\bcl\b',
        '(?i)\bbcdedit(\.exe)?\b.*\bset\b',
        '(?i)\btemp\\|\bappdata\\|\busers\\public\\|\bprogramdata\\',
        '(?i)\badd-mppreference\b|\bset-mppreference\b|\bdisablerealtimemonitoring\b',
        '(?i)\bamsi\b.*\bbypass\b',
        '(?i)\bnop\b.*\bw\b.*\bhidden\b'
    )

    foreach ($p in $patterns) {
        if ($Text -match $p) { return $true }
    }
    return $false
}

function Test-SuspiciousPowerShellText {
    param(
        [string]$Text,
        [int]$EventID = 0
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    # Do not treat normal Windows PowerShell lifecycle/provider events as suspicious just because they mention
    # -NoProfile, -ExecutionPolicy Bypass, or provider startup. Installers and AppX operations commonly do that.
    if ($EventID -in @(400,403,600)) {
        $strongLifecyclePatterns = @(
            '(?i)\s-enc(odedcommand)?\b',
            '(?i)\bfrombase64string\b',
            '(?i)\binvoke-expression\b|\biex\b',
            '(?i)\bdownloadstring\b|\binvoke-webrequest\b|\bwebclient\b|\bstart-bitstransfer\b',
            '(?i)\badd-mppreference\b|\bset-mppreference\b|\bdisablerealtimemonitoring\b',
            '(?i)\bamsi\b.*\bbypass\b',
            '(?i)\brundll32(\.exe)?\b.*javascript',
            '(?i)\bregsvr32(\.exe)?\b.*(/i:|http|scrobj)',
            '(?i)\bmshta(\.exe)?\b.*http',
            '(?i)\bcertutil(\.exe)?\b.*-urlcache',
            '(?i)\bbitsadmin(\.exe)?\b',
            '(?i)\bwevtutil(\.exe)?\b.*\bcl\b',
            '(?i)\bvssadmin(\.exe)?\b.*delete.*shadows'
        )
        foreach ($p in $strongLifecyclePatterns) {
            if ($Text -match $p) { return $true }
        }
        return $false
    }

    # For script block/module/command events, use the broader suspicious PowerShell vocabulary.
    $patterns = @(
        '(?i)\s-enc(odedcommand)?\b',
        '(?i)\bfrombase64string\b',
        '(?i)\binvoke-expression\b|\biex\b',
        '(?i)\bdownloadstring\b|\binvoke-webrequest\b|\bwebclient\b|\bstart-bitstransfer\b',
        '(?i)\badd-mppreference\b|\bset-mppreference\b|\bdisablerealtimemonitoring\b',
        '(?i)\bamsi\b.*\bbypass\b',
        '(?i)\bnew-object\b\s+net\.webclient\b',
        '(?i)\bsystem\.reflection\.assembly\b',
        '(?i)\brundll32(\.exe)?\b.*javascript',
        '(?i)\bregsvr32(\.exe)?\b.*(/i:|http|scrobj)',
        '(?i)\bmshta(\.exe)?\b.*http',
        '(?i)\bcertutil(\.exe)?\b.*-urlcache',
        '(?i)\bbitsadmin(\.exe)?\b',
        '(?i)\bwevtutil(\.exe)?\b.*\bcl\b',
        '(?i)\bvssadmin(\.exe)?\b.*delete.*shadows',
        '(?i)\bencodedcommand\b'
    )

    foreach ($p in $patterns) {
        if ($Text -match $p) { return $true }
    }
    return $false
}

function ConvertTo-HtmlTableCustom {
    param(
        [object[]]$Rows,
        [string[]]$Columns,
        [int]$MaxRows = 100
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return '<p class="muted">No records found.</p>' }

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<table>')
    [void]$html.AppendLine('<thead><tr>')
    foreach ($c in $Columns) { [void]$html.AppendLine("<th>$(HtmlEncode $c)</th>") }
    [void]$html.AppendLine('</tr></thead><tbody>')

    foreach ($row in @($Rows | Select-Object -First $MaxRows)) {
        [void]$html.AppendLine('<tr>')
        foreach ($c in $Columns) {
            $val = ''
            if ($row.PSObject.Properties.Name -contains $c) { $val = $row.$c }
            [void]$html.AppendLine("<td>$(HtmlEncode $val)</td>")
        }
        [void]$html.AppendLine('</tr>')
    }

    [void]$html.AppendLine('</tbody></table>')
    if ($Rows.Count -gt $MaxRows) {
        [void]$html.AppendLine("<p class='muted'>Showing first $MaxRows of $($Rows.Count) rows. Full data is exported as decorated TXT evidence files.</p>")
    }
    return $html.ToString()
}

function ConvertTo-CleanTextValue {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) {
        return (($Value | ForEach-Object { ConvertTo-CleanTextValue $_ }) -join '; ')
    }
    $text = [string]$Value
    $text = $text -replace "`r`n", ' '
    $text = $text -replace "`n", ' '
    $text = $text -replace "`t", ' '
    while ($text -match '  ') { $text = $text -replace '  ', ' ' }
    return $text.Trim()
}

function Export-DecoratedText {
    param(
        $Rows,
        [string]$Path,
        [string]$Title,
        $Columns = @(),
        [int]$MaxRows = 5000,
        [switch]$IncludeDetailView
    )

    # Deliberately simple writer. No Format-Table, no Out-String table formatting, no fragile overloads.
    # The goal is investigation evidence, not pretty PowerShell formatting.
    try {
        $data = @()
        if ($null -ne $Rows) { $data = @($Rows) }

        $lines = New-Object 'System.Collections.Generic.List[string]'
        $wideLine = ''.PadLeft(120, '=')
        $thinLine = ''.PadLeft(120, '-')

        [void]$lines.Add($wideLine)
        [void]$lines.Add([string]$Title)
        [void]$lines.Add($wideLine)
        [void]$lines.Add(("Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
        [void]$lines.Add(("Computer : {0}" -f $ComputerName))
        [void]$lines.Add(("Window   : {0} to {1}" -f $StartTime, (Get-Date)))
        [void]$lines.Add(("Records  : {0}" -f $data.Count))
        [void]$lines.Add($thinLine)
        [void]$lines.Add('')

        if ($data.Count -eq 0) {
            [void]$lines.Add('No records found.')
            $utf8NoBom = New-Object System.Text.UTF8Encoding -ArgumentList $false
            [System.IO.File]::WriteAllLines($Path, [string[]]$lines.ToArray(), $utf8NoBom)
            return
        }

        $shown = @($data | Select-Object -First $MaxRows)

        $requestedColumns = @()
        if ($null -ne $Columns) {
            foreach ($c in @($Columns)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$c)) {
                    $requestedColumns += [string]$c
                }
            }
        }

        $safeColumns = @()
        if ($requestedColumns.Count -gt 0) {
            foreach ($c in $requestedColumns) {
                foreach ($row in $shown) {
                    if ($null -ne $row -and $null -ne $row.PSObject.Properties[$c]) {
                        $safeColumns += $c
                        break
                    }
                }
            }
        }

        if ($safeColumns.Count -eq 0 -and $shown.Count -gt 0) {
            foreach ($p in $shown[0].PSObject.Properties) {
                if ($p.Name -ne 'Evidence') { $safeColumns += [string]$p.Name }
            }
        }

        [void]$lines.Add('COMPACT VIEW')
        [void]$lines.Add($thinLine)

        if ($safeColumns.Count -gt 0) {
            [void]$lines.Add(($safeColumns -join ' | '))
            [void]$lines.Add($thinLine)

            foreach ($row in $shown) {
                $values = @()
                foreach ($c in $safeColumns) {
                    $v = ''
                    if ($null -ne $row -and $null -ne $row.PSObject.Properties[$c]) {
                        $v = ConvertTo-CleanTextValue $row.PSObject.Properties[$c].Value
                    }
                    $v = ([string]$v) -replace "(`r`n|`n|`r)", ' / '
                    if ($v.Length -gt 260) { $v = $v.Substring(0,257) + '...' }
                    $values += $v
                }
                [void]$lines.Add(($values -join ' | '))
            }
        } else {
            [void]$lines.Add('No displayable columns found.')
        }

        if ($data.Count -gt $MaxRows) {
            [void]$lines.Add('')
            [void]$lines.Add(("NOTE: Showing first {0} of {1} records in this file." -f $MaxRows, $data.Count))
        }

        if ($IncludeDetailView) {
            [void]$lines.Add('')
            [void]$lines.Add('DETAIL VIEW')
            [void]$lines.Add($thinLine)

            $i = 0
            foreach ($row in $shown) {
                $i++
                [void]$lines.Add('')
                [void]$lines.Add(("Record #{0}" -f $i))
                [void]$lines.Add(''.PadLeft(40, '-'))

                if ($null -eq $row) {
                    [void]$lines.Add('[null row]')
                    continue
                }

                foreach ($prop in @($row.PSObject.Properties)) {
                    if ($prop.Name -eq 'Evidence') { continue }
                    $v = ConvertTo-CleanTextValue $prop.Value
                    [void]$lines.Add(("{0}: {1}" -f $prop.Name, $v))
                }
            }
        }

        $utf8NoBom2 = New-Object System.Text.UTF8Encoding -ArgumentList $false
        [System.IO.File]::WriteAllLines($Path, [string[]]$lines.ToArray(), $utf8NoBom2)
    } catch {
        # Export failures must never break collection or spam the console.
        try {
            $fallbackLines = @(
                ''.PadLeft(120, '='),
                [string]$Title,
                ''.PadLeft(120, '='),
                ("Generated: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
                ("Exporter warning: {0}" -f $_.Exception.Message),
                ''.PadLeft(120, '-'),
                'Evidence export failed, but JSON and HTML may still contain the parsed results.'
            )
            [System.IO.File]::WriteAllLines($Path, [string[]]$fallbackLines, [System.Text.Encoding]::UTF8)
        } catch {
            # Swallow last-resort export failure to avoid console pollution.
        }

        try {
            $Script:LogWarnings.Add([PSCustomObject]@{
                LogName = 'Exporter'
                Ids     = $Title
                Error   = $_.Exception.Message
            }) | Out-Null
        } catch {}
    }
}

Write-IRStatus "Starting IR first-look collection on $ComputerName"
Write-IRStatus "Window: $StartTime to $(Get-Date)"

$IsAdmin = Test-IsAdmin
if (-not $IsAdmin) {
    Add-Finding -Severity 'Medium' -Category 'Execution' -Title 'Script was not run as Administrator' -Detail 'Some Security log events may be inaccessible. Re-run as Administrator for best results.'
}

$logsToCheck = @(
    'Security',
    'System',
    'Windows PowerShell',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational'
)

foreach ($ln in $logsToCheck) { [void](Get-LogInfoSafe -LogName $ln) }

$SecurityIds = @(
    4624,4625,4634,4647,4648,4672,4740,
    4720,4722,4723,4724,4725,4726,4728,4732,4756,4738,
    4719,4697,4698,4702,4688,1102
)
$SystemIds = @(104,7045)
$PowerShellIds = @(400,403,600,800,4103,4104)
$DefenderIds = @(1006,1007,1015,1116,1117,1118,1119,5001,5004,5007,5013,5015,5025)

Write-IRStatus 'Collecting Security events...'
$SecurityRecords = @(Get-WinEventsSafe -LogName 'Security' -Ids $SecurityIds -Start $StartTime | ForEach-Object { ConvertTo-IRRecord $_ })
Write-IRStatus "Security records collected: $($SecurityRecords.Count)"

Write-IRStatus 'Collecting System events...'
$SystemRecords = @(Get-WinEventsSafe -LogName 'System' -Ids $SystemIds -Start $StartTime | ForEach-Object { ConvertTo-IRRecord $_ })
Write-IRStatus "System records collected: $($SystemRecords.Count)"

Write-IRStatus 'Collecting PowerShell events...'
$PSClassicRecords = @(Get-WinEventsSafe -LogName 'Windows PowerShell' -Ids $PowerShellIds -Start $StartTime | ForEach-Object { ConvertTo-IRRecord $_ })
$PSOperationalRecords = @(Get-WinEventsSafe -LogName 'Microsoft-Windows-PowerShell/Operational' -Ids $PowerShellIds -Start $StartTime | ForEach-Object { ConvertTo-IRRecord $_ })
$PowerShellRecords = @($PSClassicRecords + $PSOperationalRecords)
Write-IRStatus "PowerShell records collected: $($PowerShellRecords.Count)"

Write-IRStatus 'Collecting Defender events...'
$DefenderRecords = @(Get-WinEventsSafe -LogName 'Microsoft-Windows-Windows Defender/Operational' -Ids $DefenderIds -Start $StartTime | ForEach-Object { ConvertTo-IRRecord $_ })
Write-IRStatus "Defender records collected: $($DefenderRecords.Count)"

$FailedLogons = New-Object System.Collections.Generic.List[object]
$SuccessfulLogons = New-Object System.Collections.Generic.List[object]
$ExplicitCreds = New-Object System.Collections.Generic.List[object]
$PrivilegedLogons = New-Object System.Collections.Generic.List[object]
$AccountChanges = New-Object System.Collections.Generic.List[object]
$TaskEvents = New-Object System.Collections.Generic.List[object]
$SecurityServiceEvents = New-Object System.Collections.Generic.List[object]
$ProcessCreates = New-Object System.Collections.Generic.List[object]
$SuspiciousProcesses = New-Object System.Collections.Generic.List[object]
$LogClears = New-Object System.Collections.Generic.List[object]
$AuditPolicyChanges = New-Object System.Collections.Generic.List[object]

Write-IRStatus 'Parsing Security records...'
foreach ($r in $SecurityRecords) {
    switch ($r.Id) {
        4625 {
            $ip = Get-EventField $r @('IpAddress','SourceNetworkAddress','ClientAddress')
            $lt = Get-EventField $r @('LogonType')
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                UserName        = Get-EventField $r @('TargetUserName')
                Domain          = Get-EventField $r @('TargetDomainName')
                SourceIP        = $ip
                SourceIPClass   = Get-IPClass $ip
                Workstation     = Get-EventField $r @('WorkstationName','Workstation')
                LogonType       = $lt
                LogonTypeName   = Get-LogonTypeName $lt
                Status          = Get-EventField $r @('Status')
                SubStatus       = Get-EventField $r @('SubStatus')
                FailureReason   = Get-EventField $r @('FailureReason')
                AuthPackage     = Get-EventField $r @('AuthenticationPackageName')
                LogonProcess    = Get-EventField $r @('LogonProcessName')
                RecordId        = $r.RecordId
            }
            $FailedLogons.Add($obj) | Out-Null
        }
        4624 {
            $ip = Get-EventField $r @('IpAddress','SourceNetworkAddress','ClientAddress')
            $lt = Get-EventField $r @('LogonType')
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                UserName        = Get-EventField $r @('TargetUserName')
                Domain          = Get-EventField $r @('TargetDomainName')
                SourceIP        = $ip
                SourceIPClass   = Get-IPClass $ip
                Workstation     = Get-EventField $r @('WorkstationName','Workstation')
                LogonType       = $lt
                LogonTypeName   = Get-LogonTypeName $lt
                AuthPackage     = Get-EventField $r @('AuthenticationPackageName')
                LogonProcess    = Get-EventField $r @('LogonProcessName')
                ProcessName     = Get-EventField $r @('ProcessName')
                ElevatedToken   = Get-EventField $r @('ElevatedToken')
                RecordId        = $r.RecordId
            }
            $SuccessfulLogons.Add($obj) | Out-Null
        }
        4648 {
            $ip = Get-EventField $r @('IpAddress','SourceNetworkAddress')
            $obj = [PSCustomObject]@{
                TimeCreated      = $r.TimeCreated
                EventID          = $r.Id
                SubjectUserName  = Get-EventField $r @('SubjectUserName')
                SubjectDomain    = Get-EventField $r @('SubjectDomainName')
                TargetUserName   = Get-EventField $r @('TargetUserName')
                TargetDomain     = Get-EventField $r @('TargetDomainName')
                TargetServerName = Get-EventField $r @('TargetServerName')
                ProcessName      = Get-EventField $r @('ProcessName')
                SourceIP         = $ip
                SourceIPClass    = Get-IPClass $ip
                RecordId         = $r.RecordId
            }
            $ExplicitCreds.Add($obj) | Out-Null
        }
        4672 {
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                UserName        = Get-EventField $r @('SubjectUserName')
                Domain          = Get-EventField $r @('SubjectDomainName')
                Privileges      = Get-EventField $r @('PrivilegeList')
                RecordId        = $r.RecordId
            }
            $PrivilegedLogons.Add($obj) | Out-Null
        }
        4740 {
            $obj = [PSCustomObject]@{
                TimeCreated        = $r.TimeCreated
                EventID            = $r.Id
                TargetUserName     = Get-EventField $r @('TargetUserName')
                TargetDomain       = Get-EventField $r @('TargetDomainName')
                CallerComputerName = Get-EventField $r @('CallerComputerName')
                RecordId           = $r.RecordId
            }
            $AccountChanges.Add($obj) | Out-Null
        }
        { $_ -in @(4720,4722,4723,4724,4725,4726,4728,4732,4756,4738) } {
            $eventName = switch ($r.Id) {
                4720 { 'User account created' }
                4722 { 'User account enabled' }
                4723 { 'Password change attempted' }
                4724 { 'Password reset attempted' }
                4725 { 'User account disabled' }
                4726 { 'User account deleted' }
                4728 { 'Member added to global group' }
                4732 { 'Member added to local group' }
                4756 { 'Member added to universal group' }
                4738 { 'User account changed' }
            }
            $obj = [PSCustomObject]@{
                TimeCreated      = $r.TimeCreated
                EventID          = $r.Id
                EventName        = $eventName
                SubjectUserName  = Get-EventField $r @('SubjectUserName')
                SubjectDomain    = Get-EventField $r @('SubjectDomainName')
                TargetUserName   = Get-EventField $r @('TargetUserName')
                TargetDomain     = Get-EventField $r @('TargetDomainName')
                MemberName       = Get-EventField $r @('MemberName')
                MemberSid        = Get-EventField $r @('MemberSid')
                RecordId         = $r.RecordId
            }
            $AccountChanges.Add($obj) | Out-Null
        }
        4698 {
            $obj = [PSCustomObject]@{
                TimeCreated      = $r.TimeCreated
                EventID          = $r.Id
                EventName        = 'Scheduled task created'
                SubjectUserName  = Get-EventField $r @('SubjectUserName')
                TaskName         = Get-EventField $r @('TaskName')
                TaskContent      = Get-EventField $r @('TaskContent')
                RecordId         = $r.RecordId
            }
            $TaskEvents.Add($obj) | Out-Null
        }
        4702 {
            $obj = [PSCustomObject]@{
                TimeCreated      = $r.TimeCreated
                EventID          = $r.Id
                EventName        = 'Scheduled task updated'
                SubjectUserName  = Get-EventField $r @('SubjectUserName')
                TaskName         = Get-EventField $r @('TaskName')
                TaskContent      = Get-EventField $r @('TaskContent')
                RecordId         = $r.RecordId
            }
            $TaskEvents.Add($obj) | Out-Null
        }
        4697 {
            $obj = [PSCustomObject]@{
                TimeCreated      = $r.TimeCreated
                EventID          = $r.Id
                EventName        = 'Service installed - Security log'
                SubjectUserName  = Get-EventField $r @('SubjectUserName')
                ServiceName      = Get-EventField $r @('ServiceName')
                ServiceFileName  = Get-EventField $r @('ServiceFileName','ImagePath')
                ServiceType      = Get-EventField $r @('ServiceType')
                StartType        = Get-EventField $r @('StartType')
                AccountName      = Get-EventField $r @('AccountName')
                RecordId         = $r.RecordId
            }
            $SecurityServiceEvents.Add($obj) | Out-Null
        }
        4688 {
            $cmd = Get-EventField $r @('CommandLine','ProcessCommandLine')
            $proc = Get-EventField $r @('NewProcessName','ProcessName')
            $parent = Get-EventField $r @('ParentProcessName','CreatorProcessName')
            $combined = "$proc $cmd $parent"
            $obj = [PSCustomObject]@{
                TimeCreated       = $r.TimeCreated
                EventID           = $r.Id
                SubjectUserName   = Get-EventField $r @('SubjectUserName')
                NewProcessName    = $proc
                CommandLine       = $cmd
                ParentProcessName = $parent
                CreatorProcessId  = Get-EventField $r @('ProcessId','CreatorProcessId')
                NewProcessId      = Get-EventField $r @('NewProcessId')
                Suspicious        = Test-SuspiciousPathOrCommand $combined
                RecordId          = $r.RecordId
            }
            $ProcessCreates.Add($obj) | Out-Null
            if ($obj.Suspicious) { $SuspiciousProcesses.Add($obj) | Out-Null }
        }
        1102 {
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                EventName       = 'Security audit log cleared'
                SubjectUserName = Get-EventField $r @('SubjectUserName')
                SubjectDomain   = Get-EventField $r @('SubjectDomainName')
                RecordId        = $r.RecordId
            }
            $LogClears.Add($obj) | Out-Null
        }
        4719 {
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                EventName       = 'Audit policy changed'
                SubjectUserName = Get-EventField $r @('SubjectUserName')
                SubjectDomain   = Get-EventField $r @('SubjectDomainName')
                Category        = Get-EventField $r @('Category','SubcategoryName')
                Changes         = Get-EventField $r @('AuditPolicyChanges')
                RecordId        = $r.RecordId
            }
            $AuditPolicyChanges.Add($obj) | Out-Null
        }
    }
}

$SystemServiceEvents = New-Object System.Collections.Generic.List[object]
$SystemLogClears = New-Object System.Collections.Generic.List[object]

Write-IRStatus 'Parsing System records...'
foreach ($r in $SystemRecords) {
    switch ($r.Id) {
        7045 {
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                EventName       = 'Service installed - System log'
                ServiceName     = Get-EventField $r @('ServiceName')
                ImagePath       = Get-EventField $r @('ImagePath','ServiceFileName')
                ServiceType     = Get-EventField $r @('ServiceType')
                StartType       = Get-EventField $r @('StartType')
                AccountName     = Get-EventField $r @('AccountName')
                SuspiciousPath  = Test-SuspiciousPathOrCommand (Get-EventField $r @('ImagePath','ServiceFileName'))
                RecordId        = $r.RecordId
            }
            $SystemServiceEvents.Add($obj) | Out-Null
        }
        104 {
            $obj = [PSCustomObject]@{
                TimeCreated     = $r.TimeCreated
                EventID         = $r.Id
                EventName       = 'Event log cleared'
                ProviderName    = $r.ProviderName
                Message         = $r.Message
                RecordId        = $r.RecordId
            }
            $SystemLogClears.Add($obj) | Out-Null
            $LogClears.Add($obj) | Out-Null
        }
    }
}

$PowerShellSuspicious = New-Object System.Collections.Generic.List[object]
$PowerShellAll = New-Object System.Collections.Generic.List[object]

Write-IRStatus 'Parsing PowerShell records...'
foreach ($r in $PowerShellRecords) {
    $scriptBlock = Get-EventField $r @('ScriptBlockText','CommandLine','Payload','HostApplication','Message')
    if ([string]::IsNullOrWhiteSpace($scriptBlock)) { $scriptBlock = $r.Message }
    $susp = Test-SuspiciousPowerShellText -Text $scriptBlock -EventID $r.Id
    $obj = [PSCustomObject]@{
        TimeCreated  = $r.TimeCreated
        EventID      = $r.Id
        LogName      = $r.LogName
        ProviderName = $r.ProviderName
        User         = Get-EventField $r @('User','UserId','ContextInfo')
        Text         = if ($scriptBlock.Length -gt 4000) { $scriptBlock.Substring(0,4000) } else { $scriptBlock }
        Suspicious   = $susp
        RecordId     = $r.RecordId
    }
    $PowerShellAll.Add($obj) | Out-Null
    if ($susp) { $PowerShellSuspicious.Add($obj) | Out-Null }
}

$DefenderEvents = New-Object System.Collections.Generic.List[object]
Write-IRStatus 'Parsing Defender records...'
foreach ($r in $DefenderRecords) {
    $msg = $r.Message
    $eventName = switch ($r.Id) {
        1116 { 'Malware detected' }
        1117 { 'Threat remediation started/completed' }
        1118 { 'Threat remediation failed/non-critical' }
        1119 { 'Threat remediation failed/critical' }
        5001 { 'Defender real-time protection changed/disabled' }
        5004 { 'Defender configuration changed' }
        5007 { 'Defender configuration changed' }
        5013 { 'Defender tamper/config event' }
        5015 { 'Defender behavior monitoring changed' }
        5025 { 'Defender service stopped' }
        default { 'Defender event' }
    }
    $obj = [PSCustomObject]@{
        TimeCreated  = $r.TimeCreated
        EventID      = $r.Id
        EventName    = $eventName
        ProviderName = $r.ProviderName
        Text         = if ($msg -and $msg.Length -gt 2000) { $msg.Substring(0,2000) } else { $msg }
        RecordId     = $r.RecordId
    }
    $DefenderEvents.Add($obj) | Out-Null
}

Write-IRStatus 'Building findings...'

if ($LogWarnings.Count -gt 0) {
    foreach ($w in $LogWarnings) {
        Add-Finding -Severity 'Low' -Category 'Audit Coverage' -Title "Could not query $($w.LogName)" -Detail $w.Error -Evidence $w
    }
}

foreach ($c in $Coverage) {
    if (-not $c.Exists) {
        Add-Finding -Severity 'Low' -Category 'Audit Coverage' -Title "Log missing: $($c.LogName)" -Detail 'The log does not exist on this host or is not accessible.' -Evidence $c
    } elseif (-not $c.IsEnabled) {
        Add-Finding -Severity 'Medium' -Category 'Audit Coverage' -Title "Log disabled: $($c.LogName)" -Detail 'Important telemetry may be missing because this log is disabled.' -Evidence $c
    } elseif ($c.RecordCount -eq 0) {
        Add-Finding -Severity 'Low' -Category 'Audit Coverage' -Title "Log empty: $($c.LogName)" -Detail 'The log exists but has no records.' -Evidence $c
    }
}

$FailedByIP = @($FailedLogons | Where-Object { $_.SourceIP -and $_.SourceIP -ne '-' } | Group-Object SourceIP | ForEach-Object {
    $users = @($_.Group | Where-Object { $_.UserName } | Select-Object -ExpandProperty UserName -Unique)
    [PSCustomObject]@{
        SourceIP       = $_.Name
        SourceIPClass  = Get-IPClass $_.Name
        Count          = $_.Count
        DistinctUsers  = $users.Count
        Users          = ($users -join ', ')
        FirstSeen      = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        LastSeen       = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    }
} | Sort-Object Count -Descending)

foreach ($g in $FailedByIP) {
    if ($g.Count -ge 25) {
        Add-Finding -Severity 'High' -Category 'Authentication' -Title "Heavy failed logons from $($g.SourceIP)" -Detail "$($g.Count) failed logons targeting $($g.DistinctUsers) distinct user(s). IP classification: $($g.SourceIPClass)." -Evidence $g
    } elseif ($g.Count -ge 10) {
        Add-Finding -Severity 'Medium' -Category 'Authentication' -Title "Multiple failed logons from $($g.SourceIP)" -Detail "$($g.Count) failed logons targeting $($g.DistinctUsers) distinct user(s). IP classification: $($g.SourceIPClass)." -Evidence $g
    }

    if ($g.DistinctUsers -ge 5 -and $g.Count -ge 10) {
        Add-Finding -Severity 'High' -Category 'Authentication' -Title "Possible password spraying from $($g.SourceIP)" -Detail "$($g.Count) failed logons across $($g.DistinctUsers) usernames." -Evidence $g
    }

    if ($g.SourceIPClass -eq 'External/Public' -and $g.Count -ge 5) {
        Add-Finding -Severity 'High' -Category 'Authentication' -Title "External failed logon activity from $($g.SourceIP)" -Detail "$($g.Count) failed logons from a public IP address." -Evidence $g
    }
}

$FailedByUser = @($FailedLogons | Where-Object { $_.UserName } | Group-Object UserName | ForEach-Object {
    $ips = @($_.Group | Where-Object { $_.SourceIP } | Select-Object -ExpandProperty SourceIP -Unique)
    [PSCustomObject]@{
        UserName      = $_.Name
        Count         = $_.Count
        DistinctIPs   = $ips.Count
        SourceIPs     = ($ips -join ', ')
        FirstSeen     = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        LastSeen      = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
    }
} | Sort-Object Count -Descending)

foreach ($u in $FailedByUser) {
    if ($u.Count -ge 25) {
        Add-Finding -Severity 'High' -Category 'Authentication' -Title "Heavy failed logons against user $($u.UserName)" -Detail "$($u.Count) failures from $($u.DistinctIPs) source IP(s)." -Evidence $u
    } elseif ($u.Count -ge 10) {
        Add-Finding -Severity 'Medium' -Category 'Authentication' -Title "Multiple failed logons against user $($u.UserName)" -Detail "$($u.Count) failures from $($u.DistinctIPs) source IP(s)." -Evidence $u
    }
}

$SuccessfulRemote = @($SuccessfulLogons | Where-Object { $_.LogonType -in @('3','8','9','10') })
$SuccessfulExternal = @($SuccessfulRemote | Where-Object { $_.SourceIPClass -eq 'External/Public' })
foreach ($s in $SuccessfulExternal) {
    $sev = 'Medium'
    if ($s.LogonType -in @('8','10')) { $sev = 'High' }
    Add-Finding -Severity $sev -Category 'Authentication' -Title "Successful remote logon from external IP $($s.SourceIP)" -Detail "User $($s.Domain)\$($s.UserName) logged on with type $($s.LogonType) ($($s.LogonTypeName))." -Evidence $s
}

$ClearTextLogons = @($SuccessfulLogons | Where-Object { $_.LogonType -eq '8' })
if ($ClearTextLogons.Count -gt 0) {
    Add-Finding -Severity 'High' -Category 'Authentication' -Title 'NetworkCleartext logons observed' -Detail "$($ClearTextLogons.Count) successful logon(s) used Logon Type 8. Treat this as credential exposure risk." -Evidence (@($ClearTextLogons | Select-Object -First 10))
}

$NewCredsLogons = @($SuccessfulLogons | Where-Object { $_.LogonType -eq '9' })
if ($NewCredsLogons.Count -gt 0) {
    Add-Finding -Severity 'Medium' -Category 'Authentication' -Title 'NewCredentials logons observed' -Detail "$($NewCredsLogons.Count) Logon Type 9 event(s) found. Review for RunAs or alternate credential usage." -Evidence (@($NewCredsLogons | Select-Object -First 10))
}

$SuccessAfterFailures = New-Object System.Collections.Generic.List[object]
foreach ($s in $SuccessfulLogons) {
    if ([string]::IsNullOrWhiteSpace($s.UserName) -and [string]::IsNullOrWhiteSpace($s.SourceIP)) { continue }
    $lookback = $s.TimeCreated.AddMinutes(-60)
    $prior = @($FailedLogons | Where-Object {
        $_.TimeCreated -ge $lookback -and $_.TimeCreated -lt $s.TimeCreated -and (
            ($s.SourceIP -and $_.SourceIP -eq $s.SourceIP) -or
            ($s.UserName -and $_.UserName -eq $s.UserName)
        )
    })
    if ($prior.Count -ge 5) {
        $obj = [PSCustomObject]@{
            SuccessTime     = $s.TimeCreated
            UserName        = $s.UserName
            Domain          = $s.Domain
            SourceIP        = $s.SourceIP
            SourceIPClass   = $s.SourceIPClass
            LogonType       = $s.LogonType
            LogonTypeName   = $s.LogonTypeName
            PriorFailures60m = $prior.Count
            FirstFailure    = ($prior | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            SuccessRecordId = $s.RecordId
        }
        $SuccessAfterFailures.Add($obj) | Out-Null
        Add-Finding -Severity 'High' -Category 'Authentication' -Title 'Successful logon after repeated failures' -Detail "User $($s.Domain)\$($s.UserName) had $($prior.Count) related failed logon(s) in the 60 minutes before a successful logon." -Evidence $obj
    }
}

if ($ExplicitCreds.Count -gt 0) {
    $firstCred = @($ExplicitCreds | Sort-Object TimeCreated | Select-Object -First 1)[0]
    $lastCred  = @($ExplicitCreds | Sort-Object TimeCreated -Descending | Select-Object -First 1)[0]
    $credEvidence = [PSCustomObject]@{
        TimeCreated  = $firstCred.TimeCreated
        FirstSeen    = $firstCred.TimeCreated
        LastSeen     = $lastCred.TimeCreated
        EventID      = 4648
        LogName      = 'Security'
        ProviderName = 'Microsoft-Windows-Security-Auditing'
        Count        = $ExplicitCreds.Count
        RecordId     = $firstCred.RecordId
    }
    Add-Finding -Severity 'Medium' -Category 'Credential Use' -Title 'Explicit credential use detected' -Detail "$($ExplicitCreds.Count) Event ID 4648 record(s) found. First=$($firstCred.TimeCreated); Last=$($lastCred.TimeCreated). Review ExplicitCredentialUse_Decorated.txt for each timestamped event." -Evidence $credEvidence
}

if ($PrivilegedLogons.Count -gt 0) {
    $topPriv = @($PrivilegedLogons | Group-Object UserName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [PSCustomObject]@{ UserName=$_.Name; Count=$_.Count } })
    $firstPriv = @($PrivilegedLogons | Sort-Object TimeCreated | Select-Object -First 1)[0]
    $lastPriv  = @($PrivilegedLogons | Sort-Object TimeCreated -Descending | Select-Object -First 1)[0]
    $privEvidence = [PSCustomObject]@{
        TimeCreated  = $firstPriv.TimeCreated
        FirstSeen    = $firstPriv.TimeCreated
        LastSeen     = $lastPriv.TimeCreated
        EventID      = 4672
        LogName      = 'Security'
        ProviderName = 'Microsoft-Windows-Security-Auditing'
        Count        = $PrivilegedLogons.Count
        TopUsers     = (ConvertTo-CleanTextValue $topPriv)
        RecordId     = $firstPriv.RecordId
    }
    Add-Finding -Severity 'Info' -Category 'Privilege' -Title 'Special privilege logons observed' -Detail "$($PrivilegedLogons.Count) Event ID 4672 record(s) found. First=$($firstPriv.TimeCreated); Last=$($lastPriv.TimeCreated). This is normal for admins/services but useful for timeline review." -Evidence $privEvidence
}

foreach ($a in $AccountChanges) {
    if ($a.EventID -eq 4720) {
        Add-Finding -Severity 'High' -Category 'Account Changes' -Title "User account created: $($a.TargetUserName)" -Detail "Created by $($a.SubjectDomain)\$($a.SubjectUserName)." -Evidence $a
    } elseif ($a.EventID -eq 4722) {
        Add-Finding -Severity 'Medium' -Category 'Account Changes' -Title "User account enabled: $($a.TargetUserName)" -Detail "Enabled by $($a.SubjectDomain)\$($a.SubjectUserName)." -Evidence $a
    } elseif ($a.EventID -eq 4724) {
        Add-Finding -Severity 'Medium' -Category 'Account Changes' -Title "Password reset attempt: $($a.TargetUserName)" -Detail "Performed by $($a.SubjectDomain)\$($a.SubjectUserName)." -Evidence $a
    } elseif ($a.EventID -in @(4728,4732,4756)) {
        $title = "Group membership changed: $($a.TargetUserName)"
        $severity = 'Medium'
        if ($a.TargetUserName -match '(?i)administrators|remote desktop users|domain admins|enterprise admins|backup operators') { $severity = 'Critical' }
        Add-Finding -Severity $severity -Category 'Account Changes' -Title $title -Detail "Member $($a.MemberName) was added/changed by $($a.SubjectDomain)\$($a.SubjectUserName)." -Evidence $a
    } elseif ($a.EventID -eq 4740) {
        Add-Finding -Severity 'Medium' -Category 'Account Changes' -Title "Account locked out: $($a.TargetUserName)" -Detail "Caller computer: $($a.CallerComputerName)." -Evidence $a
    }
}

foreach ($lc in $LogClears) {
    Add-Finding -Severity 'Critical' -Category 'Anti-Forensics' -Title "Log cleared: $($lc.EventName)" -Detail "A log-clearing event was observed at $($lc.TimeCreated)." -Evidence $lc
}

foreach ($ap in $AuditPolicyChanges) {
    Add-Finding -Severity 'High' -Category 'Anti-Forensics' -Title 'Audit policy changed' -Detail "Audit policy changed by $($ap.SubjectDomain)\$($ap.SubjectUserName)." -Evidence $ap
}

$AllServiceEvents = @($SecurityServiceEvents + $SystemServiceEvents)
foreach ($svc in $AllServiceEvents) {
    $path = ''
    if ($svc.PSObject.Properties.Name -contains 'ImagePath') { $path = $svc.ImagePath }
    if ($svc.PSObject.Properties.Name -contains 'ServiceFileName' -and $svc.ServiceFileName) { $path = $svc.ServiceFileName }

    # New services are always worth reviewing, but not every service install is a High finding.
    # System32/Program Files vendor services are usually update/install activity; suspicious writable paths stay High/Critical.
    $sev = 'Medium'
    if (Test-SuspiciousPathOrCommand $path) { $sev = 'High' }
    $lowerPath = ([string]$path).ToLowerInvariant()
    if ($lowerPath.Contains('\users\public\') -or $lowerPath.Contains('\appdata\') -or $lowerPath.Contains('\temp\') -or $lowerPath.Contains('\programdata\')) { $sev = 'Critical' }

    Add-Finding -Severity $sev -Category 'Persistence' -Title "New service installed: $($svc.ServiceName)" -Detail "Service path: $path" -Evidence $svc
}

foreach ($task in $TaskEvents) {
    $sev = 'Medium'
    if (Test-SuspiciousPathOrCommand ($task.TaskContent + ' ' + $task.TaskName)) { $sev = 'High' }
    Add-Finding -Severity $sev -Category 'Persistence' -Title "$($task.EventName): $($task.TaskName)" -Detail "Scheduled task event created/changed by $($task.SubjectUserName)." -Evidence $task
}

if ($SuspiciousProcesses.Count -gt 0) {
    foreach ($p in @($SuspiciousProcesses | Select-Object -First 100)) {
        Add-Finding -Severity 'High' -Category 'Process Execution' -Title "Suspicious process execution: $($p.NewProcessName)" -Detail "Command line: $($p.CommandLine)" -Evidence $p
    }
}

if ($ProcessCreates.Count -eq 0) {
    Add-Finding -Severity 'Low' -Category 'Audit Coverage' -Title 'No process creation events found' -Detail 'Event ID 4688 was not found in the selected window. Process creation auditing may be disabled or logs may have rolled over.'
}

if ($PowerShellSuspicious.Count -gt 0) {
    # Aggregate repeated lifecycle entries from the same PowerShell HostApplication where possible.
    # Script block events still appear individually in SuspiciousPowerShell_Decorated.txt with timestamps.
    foreach ($grp in @($PowerShellSuspicious | Group-Object Text)) {
        $sample = @($grp.Group | Sort-Object TimeCreated | Select-Object -First 1)[0]
        $last = @($grp.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1)[0]
        $sev = 'High'
        if ($sample.EventID -in @(400,403,600)) { $sev = 'Medium' }
        $evidence = [PSCustomObject]@{
            TimeCreated  = $sample.TimeCreated
            FirstSeen    = $sample.TimeCreated
            LastSeen     = $last.TimeCreated
            EventID      = $sample.EventID
            LogName      = $sample.LogName
            ProviderName = $sample.ProviderName
            Count        = $grp.Count
            Text         = $sample.Text
            RecordId     = $sample.RecordId
        }
        Add-Finding -Severity $sev -Category 'PowerShell' -Title 'Suspicious PowerShell activity' -Detail "Suspicious PowerShell indicator observed $($grp.Count) time(s). First=$($sample.TimeCreated); Last=$($last.TimeCreated). Event ID $($sample.EventID) from $($sample.LogName)." -Evidence $evidence
    }
}

if ($PowerShellRecords.Count -eq 0) {
    Add-Finding -Severity 'Low' -Category 'Audit Coverage' -Title 'No PowerShell telemetry found' -Detail 'No relevant PowerShell events were found. Script Block Logging may be disabled, logs may be missing, or no activity occurred.'
}

# Defender can generate many 5007 configuration-change events during legitimate update/maintenance activity.
# Keep every raw Defender event in DefenderEvents_Decorated.txt, but aggregate duplicate findings so the priority list stays usable.
$DefenderFindingGroups = @($DefenderEvents | Group-Object EventID, EventName)
foreach ($grp in $DefenderFindingGroups) {
    $sample = @($grp.Group | Sort-Object TimeCreated | Select-Object -First 1)[0]
    $last = @($grp.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1)[0]
    $sev = 'Medium'
    if ($sample.EventID -in @(1116,1119,5001,5013,5015,5025)) { $sev = 'High' }
    elseif ($sample.EventID -eq 5007) { $sev = 'Medium' }

    $evidence = [PSCustomObject]@{
        TimeCreated  = $sample.TimeCreated
        FirstSeen    = $sample.TimeCreated
        LastSeen     = $last.TimeCreated
        EventID      = $sample.EventID
        EventName    = $sample.EventName
        Count        = $grp.Count
        LogName      = 'Microsoft-Windows-Windows Defender/Operational'
        ProviderName = $sample.ProviderName
        RecordId     = $sample.RecordId
    }

    Add-Finding -Severity $sev -Category 'Defender' -Title $sample.EventName -Detail "Defender Event ID $($sample.EventID) observed $($grp.Count) time(s). First=$($sample.TimeCreated); Last=$($last.TimeCreated). Review DefenderEvents_Decorated.txt for each timestamped event." -Evidence $evidence
}

$LogonTypeSummary = @($SuccessfulLogons | Group-Object LogonType, LogonTypeName | Sort-Object Count -Descending | ForEach-Object {
    [PSCustomObject]@{
        LogonType = ($_.Name -split ', ')[0]
        TypeName  = ($_.Name -split ', ',2)[1]
        Count     = $_.Count
    }
})

$TopSuccessfulUsers = @($SuccessfulLogons | Where-Object { $_.UserName } | Group-Object UserName | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ UserName=$_.Name; Count=$_.Count } })
$TopSuccessfulIPs = @($SuccessfulLogons | Where-Object { $_.SourceIP } | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ SourceIP=$_.Name; SourceIPClass=(Get-IPClass $_.Name); Count=$_.Count } })
$TopExternalSuccessfulIPs = @($SuccessfulExternal | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object { [PSCustomObject]@{ SourceIP=$_.Name; Count=$_.Count } })

$SeverityCounts = @($Findings | Group-Object Severity | ForEach-Object { [PSCustomObject]@{ Severity=$_.Name; Count=$_.Count } })
$CriticalCount = @($Findings | Where-Object Severity -eq 'Critical').Count
$HighCount = @($Findings | Where-Object Severity -eq 'High').Count
$MediumCount = @($Findings | Where-Object Severity -eq 'Medium').Count
$LowCount = @($Findings | Where-Object Severity -eq 'Low').Count
$InfoCount = @($Findings | Where-Object Severity -eq 'Info').Count

$Verdict = 'No obvious high-risk activity found from available logs'
if ($CriticalCount -gt 0) { $Verdict = 'Critical findings require immediate review' }
elseif ($HighCount -gt 0) { $Verdict = 'High-risk findings require investigation' }
elseif ($MediumCount -gt 0) { $Verdict = 'Medium-risk anomalies found; review recommended' }

Write-IRStatus 'Exporting decorated TXT, JSON, and HTML reports...'

Export-DecoratedText -Rows @($Findings | Sort-Object @{Expression='Score';Descending=$true}, @{Expression='TimeCreated';Descending=$false}) -Path (Join-Path $OutputPath 'Findings_Decorated.txt') -Title 'Prioritized Findings' -Columns @('TimeCreated','FirstSeen','LastSeen','Severity','Score','Category','Title','Detail','EventID','LogName','ProviderName','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($FailedLogons) -Path (Join-Path $OutputPath 'FailedLogons_Decorated.txt') -Title 'Failed Logons' -Columns @('TimeCreated','UserName','Domain','SourceIP','SourceIPClass','Workstation','LogonType','LogonTypeName','Status','SubStatus','FailureReason','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($SuccessfulLogons) -Path (Join-Path $OutputPath 'SuccessfulLogons_Decorated.txt') -Title 'Successful Logons' -Columns @('TimeCreated','UserName','Domain','SourceIP','SourceIPClass','Workstation','LogonType','LogonTypeName','AuthPackage','LogonProcess','ElevatedToken','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($ExplicitCreds) -Path (Join-Path $OutputPath 'ExplicitCredentialUse_Decorated.txt') -Title 'Explicit Credential Use - Event ID 4648' -Columns @('TimeCreated','SubjectUserName','SubjectDomain','TargetUserName','TargetDomain','TargetServerName','ProcessName','SourceIP','SourceIPClass','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($PrivilegedLogons) -Path (Join-Path $OutputPath 'PrivilegedLogons_Decorated.txt') -Title 'Privileged Logons - Event ID 4672' -Columns @('TimeCreated','UserName','Domain','Privileges','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($AccountChanges) -Path (Join-Path $OutputPath 'AccountAndPrivilegeChanges_Decorated.txt') -Title 'Account and Privilege Changes' -Columns @('TimeCreated','EventID','EventName','SubjectUserName','SubjectDomain','TargetUserName','TargetDomain','MemberName','CallerComputerName','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($AllServiceEvents) -Path (Join-Path $OutputPath 'NewServices_Decorated.txt') -Title 'New Service Installation Events' -Columns @('TimeCreated','EventID','EventName','SubjectUserName','ServiceName','ImagePath','ServiceFileName','StartType','AccountName','SuspiciousPath','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($TaskEvents) -Path (Join-Path $OutputPath 'ScheduledTasks_Decorated.txt') -Title 'Scheduled Task Creation/Update Events' -Columns @('TimeCreated','EventID','EventName','SubjectUserName','TaskName','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($ProcessCreates) -Path (Join-Path $OutputPath 'ProcessCreation_Decorated.txt') -Title 'Process Creation Events - Event ID 4688' -Columns @('TimeCreated','EventID','SubjectUserName','NewProcessName','CommandLine','ParentProcessName','Suspicious','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($SuspiciousProcesses) -Path (Join-Path $OutputPath 'SuspiciousProcesses_Decorated.txt') -Title 'Suspicious Process Execution' -Columns @('TimeCreated','EventID','SubjectUserName','NewProcessName','CommandLine','ParentProcessName','Suspicious','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($PowerShellAll) -Path (Join-Path $OutputPath 'PowerShellActivity_Decorated.txt') -Title 'PowerShell Activity' -Columns @('TimeCreated','EventID','LogName','ProviderName','User','Text','Suspicious','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($PowerShellSuspicious) -Path (Join-Path $OutputPath 'SuspiciousPowerShell_Decorated.txt') -Title 'Suspicious PowerShell Activity' -Columns @('TimeCreated','EventID','LogName','ProviderName','User','Text','Suspicious','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($DefenderEvents) -Path (Join-Path $OutputPath 'DefenderEvents_Decorated.txt') -Title 'Microsoft Defender Events' -Columns @('TimeCreated','EventID','EventName','ProviderName','Text','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($LogClears) -Path (Join-Path $OutputPath 'LogClearingEvents_Decorated.txt') -Title 'Log Clearing / Anti-Forensics Events' -Columns @('TimeCreated','EventID','EventName','SubjectUserName','SubjectDomain','ProviderName','Message','RecordId') -IncludeDetailView
Export-DecoratedText -Rows @($Coverage) -Path (Join-Path $OutputPath 'AuditCoverage_Decorated.txt') -Title 'Audit Coverage and Log Availability' -Columns @('LogName','Exists','IsEnabled','RecordCount','LastWriteTime','LogMode','MaximumSizeMB','Error') -IncludeDetailView
Export-DecoratedText -Rows @($LogWarnings) -Path (Join-Path $OutputPath 'LogQueryWarnings_Decorated.txt') -Title 'Log Query Warnings' -Columns @('LogName','Ids','Error') -IncludeDetailView
Export-DecoratedText -Rows @($FailedByIP) -Path (Join-Path $OutputPath 'FailedLogons_BySourceIP_Decorated.txt') -Title 'Failed Logons Grouped by Source IP' -Columns @('SourceIP','SourceIPClass','Count','DistinctUsers','Users','FirstSeen','LastSeen') -IncludeDetailView
Export-DecoratedText -Rows @($FailedByUser) -Path (Join-Path $OutputPath 'FailedLogons_ByUser_Decorated.txt') -Title 'Failed Logons Grouped by User' -Columns @('UserName','Count','DistinctIPs','SourceIPs','FirstSeen','LastSeen') -IncludeDetailView
Export-DecoratedText -Rows @($SuccessAfterFailures) -Path (Join-Path $OutputPath 'SuccessAfterFailures_Decorated.txt') -Title 'Successful Logons After Repeated Failures' -Columns @('SuccessTime','UserName','Domain','SourceIP','SourceIPClass','LogonType','LogonTypeName','PriorFailures60m','FirstFailure','SuccessRecordId') -IncludeDetailView
Export-DecoratedText -Rows @($AuditPolicyChanges) -Path (Join-Path $OutputPath 'AuditPolicyChanges_Decorated.txt') -Title 'Audit Policy Changes' -Columns @('TimeCreated','EventID','EventName','SubjectUserName','SubjectDomain','Category','Changes','RecordId') -IncludeDetailView

$JsonReport = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        ComputerName   = $ComputerName
        RunAsUser      = $UserName
        IsAdmin        = $IsAdmin
        RunStarted     = $RunStarted
        RunCompleted   = Get-Date
        DaysBack       = $DaysBack
        StartTime      = $StartTime
        OutputPath     = $OutputPath
        PowerShell     = $PSVersionTable.PSVersion.ToString()
    }
    Verdict = $Verdict
    Counts = [PSCustomObject]@{
        Findings              = $Findings.Count
        Critical              = $CriticalCount
        High                  = $HighCount
        Medium                = $MediumCount
        Low                   = $LowCount
        Info                  = $InfoCount
        FailedLogons          = $FailedLogons.Count
        SuccessfulLogons      = $SuccessfulLogons.Count
        ExplicitCreds         = $ExplicitCreds.Count
        PrivilegedLogons      = $PrivilegedLogons.Count
        AccountChanges        = $AccountChanges.Count
        NewServices           = $AllServiceEvents.Count
        ScheduledTaskEvents   = $TaskEvents.Count
        ProcessCreationEvents = $ProcessCreates.Count
        SuspiciousProcesses   = $SuspiciousProcesses.Count
        PowerShellEvents      = $PowerShellAll.Count
        SuspiciousPowerShell  = $PowerShellSuspicious.Count
        DefenderEvents        = $DefenderEvents.Count
        LogClears             = $LogClears.Count
    }
    TopFailedByIP        = $FailedByIP | Select-Object -First 25
    TopFailedByUser      = $FailedByUser | Select-Object -First 25
    LogonTypeSummary     = $LogonTypeSummary
    TopSuccessfulUsers   = $TopSuccessfulUsers
    TopSuccessfulIPs     = $TopSuccessfulIPs
    ExternalSuccessIPs   = $TopExternalSuccessfulIPs
    SuccessAfterFailures = $SuccessAfterFailures
    Findings             = @($Findings | Sort-Object @{Expression='Score';Descending=$true}, @{Expression='TimeCreated';Descending=$false})
    Coverage             = $Coverage
    Warnings             = $LogWarnings
}

$JsonReport | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $OutputPath 'Findings.json') -Encoding UTF8

$txt = New-Object System.Text.StringBuilder
[void]$txt.AppendLine("IR First-Look Report")
[void]$txt.AppendLine("====================")
[void]$txt.AppendLine("Computer: $ComputerName")
[void]$txt.AppendLine("Run as: $UserName")
[void]$txt.AppendLine("Administrator: $IsAdmin")
[void]$txt.AppendLine("Window: $StartTime to $(Get-Date)")
[void]$txt.AppendLine("Verdict: $Verdict")
[void]$txt.AppendLine('')
[void]$txt.AppendLine("Findings: Critical=$CriticalCount High=$HighCount Medium=$MediumCount Low=$LowCount Info=$InfoCount")
[void]$txt.AppendLine("Failed logons: $($FailedLogons.Count)")
[void]$txt.AppendLine("Successful logons: $($SuccessfulLogons.Count)")
[void]$txt.AppendLine("External successful remote logons: $($SuccessfulExternal.Count)")
[void]$txt.AppendLine("Success after failures: $($SuccessAfterFailures.Count)")
[void]$txt.AppendLine("New services: $($AllServiceEvents.Count)")
[void]$txt.AppendLine("Scheduled task events: $($TaskEvents.Count)")
[void]$txt.AppendLine("Suspicious processes: $($SuspiciousProcesses.Count)")
[void]$txt.AppendLine("Suspicious PowerShell: $($PowerShellSuspicious.Count)")
[void]$txt.AppendLine("Log clear events: $($LogClears.Count)")
[void]$txt.AppendLine('')
[void]$txt.AppendLine('Top Findings')
[void]$txt.AppendLine('------------')
foreach ($f in @($Findings | Sort-Object Score -Descending | Select-Object -First 50)) {
    [void]$txt.AppendLine("[$($f.TimeCreated)] [$($f.Severity)] $($f.Category) - $($f.Title) :: $($f.Detail)")
}
[void]$txt.AppendLine('')
[void]$txt.AppendLine('Top Failed Logon Sources')
[void]$txt.AppendLine('------------------------')
foreach ($g in @($FailedByIP | Select-Object -First 20)) {
    [void]$txt.AppendLine("$($g.SourceIP) [$($g.SourceIPClass)] Count=$($g.Count) Users=$($g.DistinctUsers) First=$($g.FirstSeen) Last=$($g.LastSeen)")
}
[void]$txt.AppendLine('')
[void]$txt.AppendLine('Audit Coverage')
[void]$txt.AppendLine('--------------')
foreach ($c in $Coverage) {
    [void]$txt.AppendLine("$($c.LogName) Exists=$($c.Exists) Enabled=$($c.IsEnabled) Records=$($c.RecordCount) LastWrite=$($c.LastWriteTime) Error=$($c.Error)")
}
$txt.ToString() | Out-File -FilePath (Join-Path $OutputPath 'IR_Summary.txt') -Encoding UTF8

$FindingRows = @($Findings | Sort-Object @{Expression='Score';Descending=$true}, @{Expression='TimeCreated';Descending=$false} | Select-Object -First 200 | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        FirstSeen   = $_.FirstSeen
        LastSeen    = $_.LastSeen
        Severity    = $_.Severity
        Score       = $_.Score
        Category    = $_.Category
        Title       = $_.Title
        Detail      = $_.Detail
        EventID     = $_.EventID
        LogName     = $_.LogName
        RecordId    = $_.RecordId
    }
})

$css = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; background: #f8fafc; }
h1, h2, h3 { color: #111827; }
.card { background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin: 14px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
.metric { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px; }
.metric .num { font-size: 28px; font-weight: 700; }
.metric .label { color: #6b7280; font-size: 13px; }
table { border-collapse: collapse; width: 100%; background: white; margin: 8px 0 18px 0; font-size: 13px; }
th, td { border: 1px solid #e5e7eb; padding: 7px 8px; vertical-align: top; }
th { background: #f3f4f6; text-align: left; }
.badge { display: inline-block; padding: 4px 8px; border-radius: 999px; font-weight: 700; font-size: 12px; }
.Critical { background: #7f1d1d; color: white; }
.High { background: #dc2626; color: white; }
.Medium { background: #f59e0b; color: #111827; }
.Low { background: #3b82f6; color: white; }
.Info { background: #6b7280; color: white; }
.muted { color: #6b7280; }
.verdict { font-size: 18px; font-weight: 700; padding: 12px; border-radius: 8px; background: #eef2ff; }
code { background:#f3f4f6; padding:2px 4px; border-radius:4px; }
</style>
'@

$html = New-Object System.Text.StringBuilder
[void]$html.AppendLine('<!doctype html><html><head><meta charset="utf-8"><title>IR First-Look Report</title>')
[void]$html.AppendLine($css)
[void]$html.AppendLine('</head><body>')
[void]$html.AppendLine("<h1>IR First-Look Report - $(HtmlEncode $ComputerName)</h1>")
[void]$html.AppendLine("<div class='card'><div class='verdict'>Verdict: $(HtmlEncode $Verdict)</div><p class='muted'>Run as $(HtmlEncode $UserName) | Administrator: $(HtmlEncode $IsAdmin) | Window: $(HtmlEncode $StartTime) to $(HtmlEncode (Get-Date))</p></div>")

[void]$html.AppendLine('<div class="grid">')
$metrics = @(
    @('Critical',$CriticalCount), @('High',$HighCount), @('Medium',$MediumCount), @('Low',$LowCount),
    @('Failed Logons',$FailedLogons.Count), @('Successful Logons',$SuccessfulLogons.Count),
    @('External Success',$SuccessfulExternal.Count), @('Success After Failures',$SuccessAfterFailures.Count),
    @('New Services',$AllServiceEvents.Count), @('Task Events',$TaskEvents.Count),
    @('Suspicious Processes',$SuspiciousProcesses.Count), @('Suspicious PowerShell',$PowerShellSuspicious.Count),
    @('Log Clears',$LogClears.Count)
)
foreach ($m in $metrics) {
    [void]$html.AppendLine("<div class='metric'><div class='num'>$(HtmlEncode $m[1])</div><div class='label'>$(HtmlEncode $m[0])</div></div>")
}
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Priority Findings</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $FindingRows -Columns @('TimeCreated','FirstSeen','LastSeen','Severity','Score','Category','Title','Detail','EventID','LogName','RecordId') -MaxRows 200))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Failed Logon Sources</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $FailedByIP -Columns @('SourceIP','SourceIPClass','Count','DistinctUsers','Users','FirstSeen','LastSeen') -MaxRows 50))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Failed Logons by User</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $FailedByUser -Columns @('UserName','Count','DistinctIPs','SourceIPs','FirstSeen','LastSeen') -MaxRows 50))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Successful External Remote Logons</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $SuccessfulExternal -Columns @('TimeCreated','UserName','Domain','SourceIP','SourceIPClass','Workstation','LogonType','LogonTypeName','AuthPackage','LogonProcess','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Successful Logons After Repeated Failures</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $SuccessAfterFailures -Columns @('SuccessTime','UserName','Domain','SourceIP','SourceIPClass','LogonType','LogonTypeName','PriorFailures60m','FirstFailure','SuccessRecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Logon Type Summary</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $LogonTypeSummary -Columns @('LogonType','TypeName','Count') -MaxRows 20))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Explicit Credential Use</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $ExplicitCreds -Columns @('TimeCreated','SubjectUserName','SubjectDomain','TargetUserName','TargetDomain','TargetServerName','ProcessName','SourceIP','SourceIPClass','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Account and Privilege Changes</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $AccountChanges -Columns @('TimeCreated','EventID','EventName','SubjectUserName','SubjectDomain','TargetUserName','TargetDomain','MemberName','CallerComputerName','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>New Services</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $AllServiceEvents -Columns @('TimeCreated','EventID','EventName','ServiceName','ImagePath','ServiceFileName','ServiceType','StartType','AccountName','SuspiciousPath','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Scheduled Task Events</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $TaskEvents -Columns @('TimeCreated','EventID','EventName','SubjectUserName','TaskName','TaskContent','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Suspicious Process Creation</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $SuspiciousProcesses -Columns @('TimeCreated','SubjectUserName','NewProcessName','CommandLine','ParentProcessName','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Suspicious PowerShell</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $PowerShellSuspicious -Columns @('TimeCreated','EventID','LogName','ProviderName','User','Text','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Defender Events</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $DefenderEvents -Columns @('TimeCreated','EventID','EventName','Text','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Log Clearing / Anti-Forensics</h2>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $LogClears -Columns @('TimeCreated','EventID','EventName','SubjectUserName','ProviderName','Message','RecordId') -MaxRows 100))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Audit Coverage and Limitations</h2>')
[void]$html.AppendLine('<p>This section is not cosmetic. Missing telemetry means blind spots. Do not treat absence of evidence as evidence of absence.</p>')
[void]$html.AppendLine((ConvertTo-HtmlTableCustom -Rows $Coverage -Columns @('LogName','Exists','IsEnabled','RecordCount','LastWriteTime','LogMode','MaximumSizeMB','Error') -MaxRows 50))
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('<div class="card"><h2>Generated Files</h2><p>Open the <code>*_Decorated.txt</code> files for clean evidence views. Use <code>Findings.json</code> for automated ingestion or timeline enrichment.</p></div>')
[void]$html.AppendLine('</body></html>')

$html.ToString() | Out-File -FilePath (Join-Path $OutputPath 'IR_Summary.html') -Encoding UTF8

$ExecutionMetadata = [PSCustomObject]@{
    ComputerName = $ComputerName
    RunAsUser = $UserName
    IsAdmin = $IsAdmin
    RunStarted = $RunStarted
    RunCompleted = Get-Date
    DaysBack = $DaysBack
    StartTime = $StartTime
    OutputPath = $OutputPath
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    ScriptPath = $MyInvocation.MyCommand.Path
}
$ExecutionMetadata | Format-List | Out-File -FilePath (Join-Path $OutputPath 'Execution_Metadata.txt') -Encoding UTF8

Write-IRStatus 'Done.'
Write-Host ''
Write-Host 'IR First-Look completed.' -ForegroundColor Green
Write-Host "Verdict: $Verdict"
Write-Host "Critical=$CriticalCount High=$HighCount Medium=$MediumCount Low=$LowCount Info=$InfoCount"
Write-Host "Output: $OutputPath"
Write-Host "Open:   $(Join-Path $OutputPath 'IR_Summary.html')"

<#
    Unlock-centric lab usage report to CSV (grouped by SID)

    ----- DESCRIPTION -----
    - Usage time is calculated only from workstation Unlock(4801) -> Lock (4800)
    - If a Lock event is missing, open Unlock sessions are closed using: 
        1. Logoff (4634) as an end marker (same LogonId preferred, otherwise same SID), 
        2. System shutdown/reboot events as machine-wide end markers, 
        3. EndTime as a last resort. 
    - Users are groupd by SID to avoid duplicate "users"  ehrn yhr dsmr dyufrny spprstd as: 
        - numeric ID (sAMAccountName) and 
        - email/UPN 
    - 4624 events are still used for counting "Logins" (interactive-ish types) but NOT for time. 

    ----- NOTES -----
    Requires Admin to read Security log. 
    Security events (end markers): 
        4801        = Workstation Unlocked
        4800        = Workstation locked 
        4624        = Logon (count only)
        4634        = Logoff (end maker only)
        4647        = User initiated logoff(ignored)
    System events (end markers): 
        41          = Kernel-Power (unexpected restart) 
        1074        = Planned shutdown/restart
        6006        = Event log service stopped (clean shutdown)
        6008        = Unexpected shutdown. 
#>

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddDays(-30), 
    [datetime]$EndTime = (Get-Date), 

    # Exclude / cap very long "use sessios" (e.g, left signed in)
    [int]$MaxSessionMinutes = 480,  # 8 Hours 
    [switch]$CapLongSessions,
    
    # Extend lookup window backwards so sessions that start before StartTime still count (clamped)
    [switch]$ExtendLookupWindow = $true, 

    # Output CSV
    [string]$CsvPath = ".\login_usage_summary.csv.", 

    # Which 4624 logoin types top count as "logins" 
    # 2=Interactive, 7=Unlock, 10=RemoteInteractive (RDP), 11=CachedInteractive
    [int[]]$AllowedLogonTypes = @(2, 7, 10, 11), 

    # Close open unlock session on shutdown/reboot events from System log. 
    [switch]$UseSystemEndMarkers = $true
)

# ----- Report metadata -----
$ReportData = Get-Date 
$ComputerId = $env:COMPUTERNAME

if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $stamp = (Get-Date).ToString("yyyy-MM-dd-HHmmss")
    $CsvPath = ".\login_usage_{0}_{1}" -f $ComputerId, $stamp
}

$ReportFile = Split-Path -Leaf $CsvPath



# ----- Helper Functions -----

## Returns the text value of the first EventData <Data> element whose Name attribute matches the specified field name.
function Get-EventDataValue {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [xml]$EventXml, 
        [Parameter(Mandatory)] [string]$Name
    )

    Write-Verbose "Extracting event data field '$Name'"
    
    # Find the first <Data> element whose Name attribute matches $Name, then returns its text value. 
    $node = $EventXml.Event.EventData.Data | 
    Where-Object { $_.Name -eq $Name } | 
    Select-Object -First 1
    
    $node.'#text'
}

## Returns the first non-empty EventData field value found when checking a list of field names in order.
function Get-FirstNonEmptyEventField {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [xml]$EventXml,
        [Parameter(Mandatory)] [string[]]$Names
    )

    # Build a lookup table of all event fields once. 
    $map = @{}
    foreach ($d in $EventXML.Event.EventData.Data) {
        if ($null -ne $d.Name) {
            $map[$d.Name] = $d.'#text'
        }
    }

    foreach ($n in $Names) {
        if ([string]::IsNullOrWhiteSpace($n)) { continue }

        $v = $map[$n]
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }

    $null
}

$IgnoreUsers = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON")

## Determines whether a username should be ignored based on system, service, machine, or virtual-session account patterns.
function Should-IgnoreUser {
    param([string]$User)
    if ([string]::IsNullOrWhiteSpace($User)) { return $true }
    if ($IgnoreUsers -contains $User.ToUpperInvariant()) { return $true }
    if ($User.EndsWith("$")) { return $true }   # machine accounts 
    if ($User -like "DWM-*") { return $true }
    if ($User -like "UMFD-*") { return $true }
    return $false
}

## Returns a normalized username in DOMAIN\User format when a domain is provided, otherwise returns the user name as-is.
function Normalize-User {
    param([string]$Domain, [string]$User)
    if ([string]::IsNullOrWhiteSpace($User)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $User }
    return "$Domain\$User"
}

## Chooses the display name that contains an email address when available, otherwise retains the existing value.
function Prefer-EmailDisplayName {
    param([string]$Current, [string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Current)) { return $Candidate }

    $curHasEmail = $Current -match '@'
    $candHasEmail = $Candidate -match '@'
    if (not $curHasEmail -and $candHasEmail) { return $Candidate }
    return $Current
}

## Safely creates or updates a user statistics record keyed by SID, preferring an email-based display name when available.
function Safe-AddUserStatBySid {
    param([hashtable]$Table, [string]$Sid, [string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return }

    if (-not $Table.ContainsKey($Sid)) { 
        $Table[$Sid] = [pscustomobject]@{
            UserSid      = $Sid
            User         = $DisplayName 
            Logins       = 0
            Sessions     = 0
            UseMinutes   = 0.0
            LongExcluded = 0
            LongCapped   = 0
            MethodUsed   = "UnlockLock"
        }
    }
    else {
        $Table[$Sid].User = Prefer-EmailDisplayName -Current $Table[$Sid].User -Candidate $DisplayName
    }
} 

## Adds unlock session usage minutes to a user stat, optionally capping or excluding sessions that exceed a maximum duration.
function Add-UnlockUseMinutes {
    param(
        [pscustomobject]$Stat,
        [double]$Minutes, 
        [int]$MaxSessionMinutes, 
        [switch]$CapLongSessions
    )

    if ($Minutes -gt $MaxSessionMinutes) {
        if ($CapLongSessions) {
            $Stat.UseMinutes += [double]$MaxSessionMinutes
            $Stat.LongCapped++
        }
        else {
            $Stat.LongExcluded++
        }
        return
    }

    $m = [double][max]::Round($Minutes, 2)
    $Stat.UseMinutes += $m
}

## Returns the number of minutes where a time interval overlap a given window.
function Get-OverlapMinutes {
    param(
        [datetime]$IntervalStart,
        [datetime]$IntervalEnd,
        [datetime]$WindowStart, 
        [datetime]$WindowEnd
    )

    # Determine the actual overlap boundaries
    # Interval: the time span of an actual event (session)
    # Windwos: the time span you are analyzing against (Window)
    # Interval: what happened, Window: When you care. 
    $s = if ($IntervalStart -lt $WindowStart) { $WindowStart } else { $IntervalStart }
    $e = if ($IntervalEnd -gt $WindowEnd) { $WindowEnd } else { $IntervalEnd }

    # If there is no overlap, return 0
    if ($s -ge $e) {
        return 0
    }
    
    return (New-TimeSpan -Start $s -End $e).TotalMinutes
}

## Closes an active unlock session at CloseTime and adds its overlapping minutes (within the reporting window) to the user's stats.
function Close-UnlockSessionAtTime {
    param(
        [hashtable]$UserStats,
        [pscustomobject]$Sess,      # { Sid, Start}
        [datetime]$CloseTime,
        [datetime]$WindowStart, 
        [datetime]$WindowEnd, 
        [int]$MaxSessionMinutes, 
        [switch]$CapLongSessions
    )

    if ($null -eq $Sess -or [string]::IsNullOrWhiteSpace($Sess.Sid)) { return }
    if (-not $UserStats.ContainsKey($Sess.Sid)) { return }

    $mins = Get-OverlapMinutes -IntervalStart $Sess.Start -IntervalEnd $CloseTime -WindowStart $WindowStart -WindowEnd $WindowEnd
    if ($mins -le 0) { return }

    Add-UnlockUseMinutes -Start $UserStats[$Sess.Sid] -Minutes $mins -MaxSessionMinutes $MaxSessionMinutes -CapLongSessions:$CapLongSessions
}


# ----- Read Events -----

# Optionally extend the lookup start time backward to catch sessions that began before the analysis window but overlap into it
$lookupStart = if ($ExtendLookupWindow) { $StartTime.AddMinutes(-$MaxSessionMinutes) } else { $StartTime }

# Security log (main)
$securityFilter = @{
    LogName   = "Security"
    Id        = 4800, 4801, 4624, 4634, 4647 
    StartTime = $lookupStart
    EndTime   = $EndTime
}

try {
    $secEvents = Get-WinEvent -FilterHashtable $securityFilter -ErrorAction Stop
}
catch {
    Write-Error "Failed to read Security log. Run PowerShell as Administrator. Details: $($_.Exception.Message)"
    return
}

# System log (optional end markers)
$sysEvents = @()
if ($UseSystemEndMarkers) {
    $systemFilter = @{
        LogName   = "System"
        Id        = 41, 1074, 6006, 6008
        StartTime = $lookupStart
        EndTime   = $EndTime
    }
    try {
        $sysEvents = Get-WinEvent -FilterHashtable $systemFilter -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read System log end markers. Continuing with Security log only. Details: $($_.Exception.Message)"
        $sysEvents = @{}
    }
}

# Merge and sort chronologically 
$events = @{}
$events += $secEvents
$events += $sysEvents
$events = $events | Sort-Object TimeCreated


# ---------- State ----------

# Open unlock session (keyed by LogonId when available; otherwise by SID)
$openUnlockSessions = @{}   # "LID:<id>" or "SID:<sid>" => @{ Sid, Start }

# Stats keyed by SID 
$userStats = @{}    # Sid => stats
$totalLogins = 0

# Diagnostics
$diag = @{
    "4801" = 0
    "4800" = 0
    "4624" = 0
    "4634" = 0
    "4647" = 0
    "SYS"  = 0
}

# ---------- Process events ----------
foreach ($ev in $events) {
    $time = [datetime]$ev.TimeCreated
    $xml = [xml]$ev.ToXml()

    # EventID is an XmlElement in some cases: use InnerText.
    $eventId = [int]$xml.Event.System.EventID.InnerText

    # Count Diagnostics 
    $k = $eventId.ToString()
    if ($diag.ContainsKey($k)) { $diag[$k] = $diag[$k] + 1 }
    else { $diag["SYS"] = $diag["SYS"] + 1 }

    switch ($eventId) {
        # --- Unlock starts a session ---
        4801 {
            $user = Get-FirstNonEmptyEventField $xml @("SubjectUserName", "TargetUserName")
            $domain = Get-FirstNonEmptyEventField $xml @("SubjectDomainName", "TargetDomainName")
            $sid = Get-FirstNonEmptyEventField $xml @("SubjectUserSid", "TargetUserSid")
            $logonId = Get-FirstNonEmptyEventField $xml @("SubjectLogonId", "TargetLogonId")
            
            if (Should-IgnoreUser $user) { break }
            if ([string]::IsNullOrWhiteSpace($sid)) { break }

            $display = Normalize-User $domain $user
            Safe-AddUserStatBySid -Table $userStats -Sid $sid -DisplayName $display

            $key = if (-not [string]::IsNullOrWhiteSpace($logonId)) { "LID:$logonId" } else { "SID:$sid" }

            if (-not $openUnlockSessions.ContainsKey($key)) {
                $openUnlockSessions[$key] = [pscustomobject]@{ Sid = $sid; Start = $time }
            }
            else {
                if ($time -lt $openUnlockSessions[$key].Start) {
                    $openUnlockSessions[$key].Start = $time
                }
            }
        }
    }
}
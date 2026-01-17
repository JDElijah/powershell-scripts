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
    [int[]]$AllowedLogonTypes = @(2,7,10,11), 

    # Close open unlock session on shutdown/reboot events from System log. 
    [switch]$UseSystemEndMarkers = $true
)

# ----- Report metadata -----
$ReportData = Get-Date 
$ComputerId = $env:COMPUTERNAME
$ReportFile = Split-Path -Leaf $CsvPath

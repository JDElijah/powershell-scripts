<#

This script reads Windows Security Even Log entries
and build a csv report. 

It calculates: 
    - Number of unique logins.
    - Number of logins (interactive-ish) peruser 
    - Estimated "use time" per user. 

It tries to estimate "use time" in the best available way: 
    1) Unlock -> Lock Time (best proxy for active presence) if
    events exist. 
    2) Otherwise, fall back to Logon -> Logoff time

IMPORTANT: 
    - If your machine is not looing lock/unlock events (4800/4801),
    the unlock/lock method will contribute 0, and the script will use
    the logon/logoff fallback. 

#>

[CmdletBinding()]
param(
    [datetime]$StartTime = (Get-Date).AddDays(-30), 
    [datetime]$EndTime = (Get-Date), 

    # Exclude/cap very long "use sessions" (e.g., left signed in)
    [int]$MaxSessionMinutes = 480, #8 hours 
    [switch]$CapLongSessions,

    # Extend lookup window backwards so sessions that start before StartTime still count (clamped)
    [switch]$ExtendLookupWindow = $true,

    #Output CSV
    [string]$CSVPath = ".\login_usage_summary.csv",

    # Which 4624 logon types to count as "logins"
    # 2=Interactive, 7=Unlock, 10=RemoteInteractive RDP), 11=CachedInteractie 
    [int[]]$AllowedLogonTypes = @(2, 7, 10, 11)
)

# ---------- Helpers ----------
# Returns the value of a named <Data> field from a Windows Event's XML (or $null if missing)
function Get-EventDataValue {
    param(
        [Parameter(Mandatory)] [xml]$EventXml, 
        [Parameter(Mandatorty)] [string]$Name
    )
    ($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
}

# Tries mulitple possible event field names and returns the first non-empty value found
function Get-FirstNonEmptyEventField {
    param(
        [Parameter(Mandatory)] [xml]$EventXml, 
        [Parameter(Mandatory)] [string[]]$Names, 
    )
    foreach ($n in $Names) {
        $v = Get-EventDataValue -EventXml $EventXml -Name $n
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }
    return $null
}

$IgnoreUsers = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON")

# Determines whether a username should be ignored (system, service, machine, or temp accounts)
function Should-IgnoreUser {
    param([string]$User)
    if ([string]::IsNullOrWhiteSpace($User)) { return $true }
    if ($IgnoreUsers -contains $User.ToUpperInvariant()) { return $true }
    if ($User.EndsWith("$")) { return $true }
    if ($User -like "DWM-*") { return $true }
    if ($User -like "UMFD-*") { return $true }
    return $false    
}

# Normalize domain and username into "DOMAIN\User" format
function Normalize-User {
    param([string]$Domain, [string]$User)
    if ([string]::IsNullOrWhiteSpace($User)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Domain)) { return $User }
    return "$Domain\$User"
}

# Ensures user statistic object exists in the table, creating it if needed.     
function Safe-AddUserStat {
    param ([hashtable]$Table, [string]$User)
    if (-not $Table.ContainsKey($User)) {
        $Table[$User] = [pscustomobject]@{
            User               = $User
            Logins             = 0 
            Sessions           = 0
            UseMinutes         = 0
            LongExcluded       = 0
            LongCapped         = 0
            UnlockLockMinutes  = 0.0 
            LogonLogoffMinutes = 0.0
            MethodUsed         = ""    # UnlockLock or LogonLogoff
        }
    }
}

# Adds session usage minutes to a user, applying long-session applying capping or exclusion rules
function Add-UseMinutes {
    param(
        [pscustomobject]$Stat, 
        [double]$Minutes, 
        [int]$MaxSessionMinutes, 
        [switch]$CapLongSessions, 
        [ValidateSet("UnlockLock", "LogonLogoff")] [string]$Method
    )

    if ($Minutes -le 0) { return }

    $Stat.Sessions++

    if ($Minutes -gt $MaxSessionMinutes) {
        if ($CapLongSessions) {
            $Stat.UseMinutes += [double]$MaxSessionMinutes
            $Stat.LongCapped++
            if ($Method -eq "UnlockLock") { $Stat.UnlockLock += [double]$MaxSessionMinutes }
            else { $Stat.LogonLogoffMinutes += [double]$MaxSessionMinutes }
        }
        else {
            $Stat.LongExcluded++  
        }
        return
    }

    $m = [double][math]::Round($Minutes, 2)
    $Stat.UseMinutes += $m
    if ($Method -eq "UnlockLock") { $Stat.UnlockLockMinutes += $m }
    else { $Stat.LogonLogoffMinutes += $m }
}

function Get-OverlapMinutes {
    param(
        [datetime]$IntervalStart, 
        [datetime]$IntervalEnd,
        [datetime]$WindowStart,
        [datetime]$WindowEnd
    )
    $s = if ($IntervalStart -lt $WindowStart) { $WindowStart } else { $IntervalStart }
    $e = if ($IntervalEnd -gt $WindowEnd) { $WindowEnd } else { $IntervalEnd }
    return (New-TimeSpan -Start $s -End $e).TotalMinutes   
}

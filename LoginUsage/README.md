# LoginUsage.ps1

## Overview 
`LoginUsage.ps1` is a PowerShell script that analyzes the Windows **Security Event Log** to generate a per-user **login and usage-time report** over a specified tiem window. 

The script estimates user "active presence" using Windows logon-related events and exports the results to a CSV file for further analysis or reporting. 

---

## What This Script Does 
For each user account found in the Security log, the script: 
- Counts **interactive logins**
- Estimates **usage time** using two methods: 
    1. **Unlock -> Lock (preferred)**
        Uses workstation unlock (`4801`) and lock (`4800`) events as the best proxy for active presence. 
    2. **Logon -> Logoff (fallback)**
        Uses logon (`4624`) and logoff (`4634`) events only if no unlock/lock data exists. 
- Prevents inflated usage by: 
    - Excluding or capping unusually long sessions (e.g., machines left logged in)
- Outputs: 
    - Per-user statistics
    - A total summary row across all users
- Writes results to a **CSV file** 

---

## Output Fields (CSV)
Each user row includes: 
- `User`
- `Logins`
- `Sessions`
- `UseHours`
- `UseMinutes`
- `MethodUsed` (`UnlockLock` or `LogonLogoff`)
- `UnlockLockHours`
- `LogonLogoffHours`
- `LongExcluded`
- `LongExcluded`
- `LongCapped`

A final `__TOTAL__` row aggregates all users. 

---

## Requirements
- Windows
- PowerShell **5.1+** or **PowerShell 7+** 
- **Administrator privileges** (required to read the the Security Event Log)
- Security auditing enabled for logon/logoff events

---

## Running the Script

### 1. Open PowerShell as Administrator
The script must be elevated: 
- Start Menu -> Search **PowerShell** 
- Right-click -> **Run as Administrator**

---

### 2. (If needed) Allow script execution
If script execution is restricted, temporarily allow local scripts: 
 
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

### 3. Run the script 
Navigate to the script directory: 
`path\to\script`

Run the default settings (last 30 days): 
`.\LoginUsage.ps1`

## Parameters & Flags 
**Time Window**
```
-StartTime <datetime>
-EndTime   <datetime>
```
**Example**
```
.\LoginUsage.ps1 -StartTime "2025-01-01" -EndTime "2025-01-31"
```
**Session Length Handling**
```
-MaxSessionMinutes <int>
-CapLongSessions
```
- `MaxSessionMinutes` (default: 480 minutes / 8 hours)
- `CapLongSessions` caps long session instead of excluding them

**Example**
```
.\LoginUsage.ps1 -MaxSessionMinutes 360 -CapLongSessions
```

**Extend Lookup Window**
```
-ExtendLookupWindow
```
Enabled by default.
Allows sessions that start before `StartTime` to be paired correctly and clamped to the report window. 

**Logon Types Counted** 
```
-AllowedLogonTypes <int[]>
```
Defaults: 
* `2` = Interactive
* `7` = Unlock
* `10` = RemoteInteractive (RDP)
* `11` = CachedInteractive

Example:
```
.\LoginUsage.ps1 -AllowedLogonTypes 2,10
```
## How Usage Time Is Calculated 
**Preferred Method: Unlock -> Lock**

Events used: 
* `4801` -- Workstation unlocked 
* `4800` -- Workstation locked

Best approx. of active user presence. 

**Fallback Method: Logon -> Logoff**
Events used: 

* `4624` -- Logon
* `4634` -- Logoff

Used only if unlock/lock data is unavailable for a user. 

*Only **one method** is used per user to avoid double counting.*

## Troubleshooting

### Missing unlock/lock events?

If `4800` / `4801` counts are near zero, enable auditing:

- **Local Security Policy** or **Domain Group Policy**
- Security Settings → Advanced Audit Policy Configuration
- Enable:
  - **Logon/Logoff → Other Logon/Logoff Events**

---

## Notes & Limitations

- Usage time is an **estimate**, not precise activity tracking
- Users who remain logged in without locking may produce long sessions
- System, service, and machine accounts are automatically excluded
- Script reads **only** Windows Security logs — no external dependencies

---

## License

Use, modify, and adapt freely for learning or operational use.

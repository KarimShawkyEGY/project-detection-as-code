# Detection Gap Log

## T1082 - System Information Discovery
- **Sysmon Visibility:** YES - EventCode 1 for systeminfo.exe and HOSTNAME.EXE
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1087.001 - Local Account Discovery
- **Sysmon Visibility:** YES - EventCode 1 for netl.exe with all its different commandLine variants
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1057 - Process Discovery
- **Sysmon Visibility:** YES - EventCode 1 for tasklist.exe & "Get-Process" command
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1053.005 - Scheduled Task
- **Sysmon Visibility:** YES - EventCode 1 for schtasks.exe and "/create" commandLine
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO 
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1547.001 - Registry Run Keys
- **Sysmon Visibility:** YES - EventCode 13 for detected targetObject indicating a registy run key 
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO 
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1059.001 — PowerShell Execution (Test 10: Fileless via Registry)
- **Sysmon Visibility:** YES — EventCode 1 for reg.exe writing Base64 payload to HKCU\Software\Classes
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap Type:** Wrong detection angle — initial query targeted powershell.exe process creation (EventCode=1)
 		but fileless execution spawns no new PowerShell process. Visibility exists via reg.exe instead.
- **Custom SPL alert needed:** YES — EventCode=1 targeting reg.exe execution

## T1059.001 — PowerShell Execution (Test 17: Encoded Command)
- **Sysmon Visibility:** YES — EventCode 1 for powershell.exe with -e flag
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap Type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1059.003 - Windows Command Shell
- **Sysmon Visibility:** YES — EventCode 1 for cmd.exe that has a parentImage other than explorer.exe
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO 
- **Gap Type:** Missing Rule from Splunk, No alert fired 
- **Custom SPL alert needed:** YES

## T1112 — Modify Registry
- **Sysmon visibility:** YES — EventCode 13 for reg.exe writing to registry
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1049 — Network Connection Discovery
- **Sysmon visibility:** YES — EventCode 1 for netstat.exe and net.exe
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired 
- **Custom SPL alert needed:** YES

## T1003.001 — OS Credential Dumping: LSASS Memory
- **Sysmon visibility:** YES (after fix) — EventCode 10 for rundll32 accessing lsass
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Sysmon config gap — ProcessAccess GrantedAccess whitelist too narrow, dropped rundll32's access mask
- **Fix applied:** Removed GrantedAccess filters from ProcessAccess block in sysmonconfig.xml, now logs all process access to lsass.exe regardless of access mask
- **Custom SPL alert needed:** YES

## T1003.002 — OS Credential Dumping: SAM
- **Sysmon visibility:** YES — EventCode 1 for reg.exe with reg save SAM/SYSTEM/SECURITY
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1005 — Data from Local System
- **Sysmon visibility:** YES — EventCode 1 for powershell.exe with full script in raw event
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing SPL rule — CommandLine field truncation prevented field-based matching
- **Custom SPL alert needed:** YES — free-text search for "Compress-Archive" in EventCode 1
- **Notes:** Long PowerShell scripts get truncated in the CommandLine field.
  Free-text search against the raw event catches what field filtering misses.

## T1105 — Ingress Tool Transfer
- **Sysmon visibility:** YES — EventCode 1 for certutil.exe with -urlcache flag + EventCode 3 for outbound connection
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1036 — Masquerading
- **Sysmon visibility:** YES — EventCode 1 for cmd.exe running from C:\ProgramData\
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1083 — File and Directory Discovery
- **Sysmon visibility:** YES — EventCode 1 for cmd.exe with dir /s and tree /F
- **Splunk saw the event:** YES
- **Splunk alert fired:** NO
- **Gap type:** Missing Rule from Splunk, No alert fired
- **Custom SPL alert needed:** YES

## T1059.001 Test 10 — PowerShell Fileless Execution via Registry
- **Sysmon visibility:** YES — EventCode 1 for reg.exe + EventCode 13 for registry write
- **Splunk alert fired:** NO
- **Gap type:** Detection intentionally not implemented as a saved alert
- **Reason:** reg.exe process creation is too noisy for a production alert without
  significant tuning. The fileless technique is better detected via EventCode=13
  targeting unusual registry paths (e.g. HKCU\Software\Classes) combined with
  subsequent PowerShell execution — a multi-event correlation that is out of scope
  for this project.
- **Notes:** This is a known hard-to-detect technique. Real SOC environments handle
  this via EDR behavioral rules or ML-based anomaly detection rather than simple
  SPL string matching.

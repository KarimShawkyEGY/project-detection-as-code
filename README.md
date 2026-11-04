# Project 1 — Detection-as-Code Pipeline

## Objective
Simulate 15 MITRE ATT&CK techniques using Atomic Red Team on a Windows 11 target,
identify detection gaps in a self-hosted Splunk SIEM, write 16 custom SPL detection
alerts covering all 15 techniques, and implement a GitHub Actions CI/CD pipeline that
automatically validates every rule on every push.

## Environment
| Component | Role | Hostname | IP |
|---|---|---|---|
| Ubuntu 26.04 LTS | SIEM — receives all attack telemetry | SOC-SPLUNK-01 | 192.168.56.10 |
| Windows 11 + Sysmon | Target — Atomic Red Team runs here | SOC-WIN11-01 | 192.168.56.20 |
| Kali Linux | GitHub CLI and repo management | SOC-KALI-01 | 192.168.56.50 |

## Attack Simulation Tool
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary —
open-source library of adversary emulation tests mapped to MITRE ATT&CK. Each test
runs a real attack command on the target machine and produces genuine telemetry in
Sysmon and Windows Event Logs, which Splunk ingests in real time.

## Techniques Simulated

| # | Technique | ID | Tactic | Test Numbers | Detected |
|---|---|---|---|---|---|
| 1 | PowerShell Execution | T1059.001 | Execution | 10, 17 | ✅ |
| 2 | Windows Command Shell | T1059.003 | Execution | 2, 3 | ✅ |
| 3 | Scheduled Task | T1053.005 | Persistence | 1 | ✅ |
| 4 | Registry Run Keys | T1547.001 | Persistence | 1 | ✅ |
| 5 | Modify Registry | T1112 | Defense Evasion | 1, 40 | ✅ |
| 6 | System Information Discovery | T1082 | Discovery | 1, 7 | ✅ |
| 7 | File and Directory Discovery | T1083 | Discovery | 1 | ✅ |
| 8 | Local Account Discovery | T1087.001 | Discovery | 8, 9, 10, 11 | ✅ |
| 9 | Process Discovery | T1057 | Discovery | 2, 3 | ✅ |
| 10 | Network Connection Discovery | T1049 | Discovery | 1 | ✅ |
| 11 | OS Credential Dumping: LSASS | T1003.001 | Credential Access | 2 | ✅ |
| 12 | OS Credential Dumping: SAM | T1003.002 | Credential Access | 1 | ✅ |
| 13 | Data from Local System | T1005 | Collection | 1 | ✅ |
| 14 | Ingress Tool Transfer | T1105 | Command & Control | 7 | ✅ |
| 15 | Masquerading | T1036 | Defense Evasion | 1 | ✅ |

**Detection rate: 15/15 (100%)**

## Detection Gaps Found
During testing, two Sysmon configuration gaps were identified and fixed before writing
the final alerts:

| Gap | Root Cause | Fix Applied |
|---|---|---|
| T1003.001 — LSASS access by rundll32.exe not logged | ProcessAccess block filtered by GrantedAccess mask, dropping rundll32's access mask | Removed GrantedAccess whitelist from sysmonconfig.xml |
| T1059.001 Test 10 — reg.exe fileless execution | No saved alert created — reg.exe process creation is too noisy without additional tuning | Documented in detection_notes.md; best detected via EDR behavioral rules in production |

## SPL Alerts (`detections/`)
15 alerts covering all 15 techniques. Each `.spl` file includes a MITRE ATT&CK
comment header, tactic, severity label, and the validated SPL query.

| File | Technique | Tactic | Severity |
|---|---|---|---|
| T1059.001a_encoded_powershell.spl | T1059.001 | Execution | High |
| T1059.003_obfuscated_cmd_execution.spl | T1059.003 | Execution | Medium |
| T1053.005_scheduled_task_created.spl | T1053.005 | Persistence | High |
| T1547.001_registry_run_key_modified.spl | T1547.001 | Persistence | High |
| T1112_registry_modified_reg_exe.spl | T1112 | Defense Evasion | Medium |
| T1082_system_information_discovery.spl | T1082 | Discovery | Low |
| T1083_file_directory_discovery.spl | T1083 | Discovery | Low |
| T1087.001_local_account_enumeration.spl | T1087.001 | Discovery | Low |
| T1057_process_discovery.spl | T1057 | Discovery | Low |
| T1049_network_connection_discovery.spl | T1049 | Discovery | Low |
| T1003.001_lsass_dump_comsvcs.spl | T1003.001 | Credential Access | Critical |
| T1003.002_sam_database_dump.spl | T1003.002 | Credential Access | Critical |
| T1005_data_collection_compress_archive.spl | T1005 | Collection | Low |
| T1105_lolbin_certutil_download.spl | T1105 | Command & Control | High |
| T1036_masquerading_unusual_path.spl | T1036 | Defense Evasion | High |

## CI/CD Pipeline
Every push to `detections/` triggers `.github/workflows/validate-detections.yml`,
which checks every `.spl` file for:
- File is non-empty
- MITRE ATT&CK mapping comment present (`# ATT&CK:`)
- Severity label present (`# Severity:`)

If any check fails the workflow exits with a non-zero code, the push is rejected, and
GitHub Actions reports which file failed and which check it missed.

See the [Actions tab](../../actions) for the latest pipeline run.

## Repository Structure
project1/
├── detections/ # 16 validated SPL alert files
├── attck-navigator/ # ATT&CK Navigator JSON layer
├── .github/
│    └── workflows/
│    └── validate-detections.yml
└── README.md 

## ATT&CK Navigator
Load [attck-navigator/project1_coverage.json](attck-navigator/project1_coverage.json)
into https://mitre-attack.github.io/attack-navigator/ to view coverage across all
15 simulated techniques.

## Key Takeaways
- **Sysmon config matters as much as SPL rules** — two detection gaps were caused by
  Sysmon silently dropping events before they reached Splunk, not by missing alerts.
- **Signal-to-noise trade-offs are real** — Alert 2 (cmd.exe) initially returned 198
  events with a broad parent-image exclusion. The final alert uses obfuscation-specific
  string matching instead, reducing noise to a single high-fidelity event per test run.
- **Detection-as-Code makes gaps visible** — storing rules as `.spl` files with ATT&CK
  headers and running CI/CD validation on every push enforces coverage standards that
  manual alert management cannot.

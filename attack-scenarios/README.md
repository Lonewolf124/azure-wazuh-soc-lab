# Attack Scenarios

Six scenarios were run on `win-target` on 17 November 2026. Each document follows the same layout: overview, objective, environment, simulated activity, logs generated, detection logic, investigation steps, evidence, MITRE mapping, response and lessons learned.

| # | Scenario | Technique | Detection | Document | Incident Report |
|---|---|---|---|---|---|
| 1 | Failed login / brute force | T1110.001 | Built-in 60122 / 60204 | [failed-login-bruteforce.md](failed-login-bruteforce.md) | [IR-001](../incident-reports/IR-001-brute-force.md) |
| 2 | New local admin account | T1136.001, T1098 | Built-in 60109 / 60170 / 60154 | [new-admin-account-created.md](new-admin-account-created.md) | [IR-002](../incident-reports/IR-002-new-admin-account.md) |
| 3 | Scheduled task persistence | T1053.005 | Built-in 60228 (level 4) from Event 4698 | [scheduled-task-persistence.md](scheduled-task-persistence.md) | [IR-003](../incident-reports/IR-003-scheduled-task.md) |
| 4 | Encoded PowerShell | T1059.001, T1027 | Built-in 92057 (level 12) from Sysmon 1 | [suspicious-powershell-encoded.md](suspicious-powershell-encoded.md) | [IR-004](../incident-reports/IR-004-suspicious-powershell.md) |
| 5 | Security log cleared | T1070.001 | Built-in 63103 (level 5) from Event 1102 | [audit-log-cleared.md](audit-log-cleared.md) | [IR-005](../incident-reports/IR-005-log-clearing.md) |
| 6 | Service from user-writable path | T1543.003 | Built-in 61138 plus custom 100100 | [malicious-service-creation.md](malicious-service-creation.md) | [IR-006](../incident-reports/IR-006-malicious-service.md) |

## Notes on Method

- All test accounts, tasks and services used harmless payloads (Notepad or a non-existent file) and were deleted afterwards.
- Times in these documents are **IST (UTC+5:30)** as shown in the Wazuh dashboard. Windows and agent logs use UTC, so the same event can appear 5 hours 30 minutes apart.
- Commands containing passwords show `<password>` placeholders.
- Anything marked `[TODO]` is a value to confirm from the saved evidence before publishing.

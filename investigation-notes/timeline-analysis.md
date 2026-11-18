# Timeline Analysis: 17 November 2026

All times IST (UTC+5:30), as displayed in the Wazuh dashboard. Windows logs and the agent log use UTC, so subtract 5 hours 30 minutes to compare with those.

| Time | Event | Source |
|---|---|---|
| 17:35:52 | Agent `win-target` (001) registered with the manager | Wazuh Agents |
| 17:38 | Sysmon installed on the VM (`mkdir C:\Sysmon` at 12:08 UTC); "Sysmon64 installed", "SysmonDrv installed" | PowerShell session |
| 17:38:46 | First "New Windows Service Created" alerts (rule 61138): Sysmon's own service and driver | Wazuh |
| ~17:42 | Sysmon process-creation events (rule 67027) start flowing in volume. First notepad.exe test event at 17:42:57. | Wazuh |
| 17:43:54 | An earlier rule 60228 (scheduled task created) alert, before scenario 3 and before I ran `auditpol`. Not investigated. | Wazuh |
| 17:45:52 to 17:45:55 | Rule 92205 (level 9) "Powershell process created an executable file in Windows root folder" fired three times during setup, before any scenario. Cause not investigated; baseline noise to tune. | Wazuh |
| 17:49:46 | First failed logon, Event 4625 (scenario 1) | Windows Security |
| 17:50:24 | Rule 60204 "Multiple Windows Logon Failures" (level 10) | Wazuh |
| 17:50:27 | Last failed logon in the burst | Windows Security |
| ~17:51:17 | `labadmin` logon activity (rule 67028, special privileges assigned): my own correct-password login | Wazuh |
| 17:59:26 | `labtest` account created, rule 60109 (scenario 2) | Windows Security |
| 18:00:20 | `labtest` added to Administrators, rule 60154 (level 12) | Windows Security |
| 18:10:11 | Scheduled task `LabUpdateCheck` created, rule 60228 (level 4) at 18:10:12 (scenario 3) | Security 4698 |
| 18:17:31 | Encoded PowerShell started; rule 92057 (level 12) at 18:17:32 (scenario 4) | Sysmon 1 |
| 18:22:43 | Security log cleared; rule 63103 (level 5) (scenario 5) | Security 1102 |
| 18:26:02 | First service-creation test, service "Lab Update Helper" running Notepad, base rule 61138 only (scenario 6) | System 7045 |
| 18:35:04 | LabBadSvc and LabGoodSvc created, only 61138. Custom rule v1 fails to fire. | System 7045 |
| 18:36 to 18:40 | Root cause found; pattern changed to `\\{1,2}`; manager restarted | n/a |
| 18:41:28 | LabBadSvc recreated, **rule 100100 fires** (level 12) | System 7045 |
| 18:41:34 | LabGoodSvc recreated, no 100100 (negative control passes) | System 7045 |

## Observations

- **One administrator session ties scenarios 2 to 5 together.** The alerts for the admin-group change, the scheduled task, the encoded PowerShell and the log clearing all carry the same logon ID, `0x19FA2E`, and the task and PowerShell events share the same parent PowerShell process (PID 3724). In a real investigation, pivoting on the logon ID would group these into a single incident.
- Agent reconnect messages in the agent log (`actively refused`, then `Connected`) match the times the manager was restarted while editing the custom rule. Events are buffered during these short gaps.
- The scenario 1 alerts remained in Wazuh after the Security log was cleared in scenario 5.

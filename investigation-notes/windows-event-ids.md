# Windows Event IDs Used in This Lab

## Reference Table

| Event ID | Log | Meaning | Scenario | Useful fields |
|---|---|---|---|---|
| 4625 | Security | An account failed to log on | 1 | `targetUserName`, `ipAddress`, `logonType`, `status` |
| 4624 | Security | An account was successfully logged on | 1 (check after failures) | `targetUserName`, `ipAddress`, `logonType` |
| 4720 | Security | A user account was created | 2 | `targetUserName`, `subjectUserName` |
| 4726 | Security | A user account was deleted | 2 (clean-up) | `targetUserName`, `subjectUserName` |
| 4732 | Security | A member was added to a security-enabled local group | 2 | `memberName`, `targetUserName` (the group) |
| 4698 | Security | A scheduled task was created | 3 | `taskName`, `taskContent` |
| 1102 | Security | The audit log was cleared | 5 | `subjectUserName` |
| 7045 | System | A service was installed in the system | 6 | `serviceName`, `imagePath`, `accountName` |
| Sysmon 1 | Sysmon/Operational | Process created | 3, 4, 5 | `image`, `commandLine`, `parentImage`, `user` |

## Audit Prerequisites

| Event | Needs | Command |
|---|---|---|
| 4698 | "Other Object Access Events" auditing must be on (I enabled it before the test; baseline not recorded) | `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable` |
| Sysmon events | Sysmon installed and its channel forwarded | See [`../lab-setup/sysmon-configuration.md`](../lab-setup/sysmon-configuration.md) |
| 4625, 4720, 4732, 1102 | Recorded in this lab without any audit-policy change | none |

## Analyst Reminders

- After a cluster of 4625s, always look for a 4624 from the same source. That is the success check.
- 4732 on the Administrators group is the privilege-change event, while 4720 alone is routine.
- A 7045 is not suspicious by itself (Sysmon's own install creates one). The `imagePath` decides.
- Wazuh stores these as `data.win.system.eventID` and `data.win.eventdata.*`.

## Field-Format Gotcha

In the Wazuh alert for 7045, `data.win.eventdata.imagePath` holds **doubled** backslashes (`C:\\Windows\\...`), while `data.win.system.message` holds single ones. Rules that match paths must allow for this. See [detection-engineering-writeup.md](detection-engineering-writeup.md).

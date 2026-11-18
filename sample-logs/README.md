# Sample Logs

Sanitised alert exports from the lab (Wazuh `wazuh-alerts` documents, trimmed to the useful fields).

| File | Scenario | Rule | Description |
|---|---|---|---|
| [60204-bruteforce-alert.json](60204-bruteforce-alert.json) | 1 | 60204 (level 10) | Multiple Windows Logon Failures (event 4625, logon type 3) |
| [60154-admin-group-changed-alert.json](60154-admin-group-changed-alert.json) | 2 | 60154 (level 12) | Administrators group changed (event 4732) |
| [60228-scheduled-task-created-alert.json](60228-scheduled-task-created-alert.json) | 3 | 60228 (level 4) | Scheduled task created (event 4698), with the task definition summarised |
| [92057-powershell-encoded-alert.json](92057-powershell-encoded-alert.json) | 4 | 92057 (level 12) | Encoded PowerShell, from a Sysmon Event 1 |
| [63103-log-cleared-alert.json](63103-log-cleared-alert.json) | 5 | 63103 (level 5) | Security log cleared (event 1102) |
| [100100-service-user-writable-path-alert.json](100100-service-user-writable-path-alert.json) | 6 | 100100 (level 12) | Custom rule firing for the malicious-path service |
| [61138-negative-control-labgoodsvc-alert.json](61138-negative-control-labgoodsvc-alert.json) | 6 | 61138 (level 5) | The legitimate-path service: base rule only, no 100100 |

## Sanitisation

- The public IP address of my workstation, my workstation's host name, and the Windows machine SID are replaced with placeholders.
- The agent address shown (172.16.0.5) is a private lab address.
- Fields such as long compliance tag lists, message boilerplate and GeoIP enrichment were trimmed.
- `imagePath` and similar fields keep the doubled backslashes exactly as Wazuh stores them. This is the detail that broke the first version of rule 100100.
- Time stamps are UTC (the dashboard displayed them in IST, UTC+5:30).

## Not Included

- Passwords, the Wazuh admin credentials and SSH keys are never stored here. The installer's `wazuh-install-files.tar` and any `.pem` key are git-ignored.

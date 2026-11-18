# Screenshots

Evidence screenshots from the lab (17 November 2026), grouped by scenario. The scenario documents and incident reports link to these exact file names.

## Folder Map

| Folder | Used in | Images |
|---|---|---|
| [00-baseline-sysmon-telemetry/](00-baseline-sysmon-telemetry/) | [Sysmon setup](../lab-setup/sysmon-configuration.md), [timeline](../investigation-notes/timeline-analysis.md) | 4 |
| [01-failed-login-bruteforce/](01-failed-login-bruteforce/) | [Scenario 1](../attack-scenarios/failed-login-bruteforce.md), [IR-001](../incident-reports/IR-001-brute-force.md) | 6 |
| [02-new-admin-account/](02-new-admin-account/) | [Scenario 2](../attack-scenarios/new-admin-account-created.md), [IR-002](../incident-reports/IR-002-new-admin-account.md) | 4 |
| [03-scheduled-task/](03-scheduled-task/) | [Scenario 3](../attack-scenarios/scheduled-task-persistence.md), [IR-003](../incident-reports/IR-003-scheduled-task.md) | 6 |
| [04-encoded-powershell/](04-encoded-powershell/) | [Scenario 4](../attack-scenarios/suspicious-powershell-encoded.md), [IR-004](../incident-reports/IR-004-suspicious-powershell.md) | 7 |
| [05-audit-log-cleared/](05-audit-log-cleared/) | [Scenario 5](../attack-scenarios/audit-log-cleared.md), [IR-005](../incident-reports/IR-005-log-clearing.md) | 5 |
| [06-malicious-service-baseline/](06-malicious-service-baseline/) | [Scenario 6](../attack-scenarios/malicious-service-creation.md) (before the custom rule) | 4 |
| [07-custom-rule-100100/](07-custom-rule-100100/) | [Scenario 6](../attack-scenarios/malicious-service-creation.md), [IR-006](../incident-reports/IR-006-malicious-service.md), [write-up](../investigation-notes/detection-engineering-writeup.md) | 9 |

File names follow `NN-tool-what-it-shows.png`, with the number giving the order within the scenario.

## Housekeeping Notes

- `02-new-admin-account` originally held a 4625 event detail, which belongs to the brute-force scenario, so it was moved to `01-failed-login-bruteforce/06-...`.
- Near-duplicates you can delete if you want a leaner repo:
  - `04-encoded-powershell/07-powershell-decode-base64-payload-duplicate.png` (same as `06-...`)
  - `05-audit-log-cleared/02-wazuh-63103-alert-row-cropped.png` (a crop of `03-...`)
  - `01-failed-login-bruteforce/01-wazuh-4625-events-9-hits-full-page.png` (same table as `02-...`, with the URL bar)
- `04-encoded-powershell/02-...` also shows the scheduled task being deleted, so it doubles as clean-up evidence for scenario 3.

## What the Screenshots Do Not Cover

Not captured before the lab was torn down:

- The **fixed (version 2)** `local_rules.xml` on screen. The rule text is kept in [`../detection-rules/local_rules_100100.xml`](../detection-rules/local_rules_100100.xml).
- The Azure resource group and NSG rules, the Wazuh agent shown as Active, and the Sysmon install output.
- The `az group list` result confirming teardown.
- A Wazuh screenshot of the log-clearing event's `wevtutil.exe` process, or a 4624 search after the brute force.

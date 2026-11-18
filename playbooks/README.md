# Playbooks

Response playbooks for a Tier 1 or Tier 2 analyst. Each follows the same layout: purpose, alert trigger, triage, containment, remediation, evidence, escalation, post-incident actions and references.

| Playbook | Triggers on | Related report |
|---|---|---|
| [brute-force-response-playbook.md](brute-force-response-playbook.md) | Rules 60122 / 60204 | [IR-001](../incident-reports/IR-001-brute-force.md) |
| [unauthorised-admin-account-playbook.md](unauthorised-admin-account-playbook.md) | Rules 60109 / 60154 | [IR-002](../incident-reports/IR-002-new-admin-account.md) |
| [suspicious-powershell-response-playbook.md](suspicious-powershell-response-playbook.md) | Encoded PowerShell in Sysmon Event 1 | [IR-004](../incident-reports/IR-004-suspicious-powershell.md) |
| [persistence-task-service-playbook.md](persistence-task-service-playbook.md) | Event 4698, rules 61138 / 100100 | [IR-003](../incident-reports/IR-003-scheduled-task.md), [IR-006](../incident-reports/IR-006-malicious-service.md) |

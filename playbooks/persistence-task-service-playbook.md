# Playbook: Persistence via Scheduled Task or Service

**Version:** 1.0
**Last Updated:** 18 November 2026
**Author:** Shreyas Desai
**Applies To:** Windows hosts monitored by Wazuh

---

## 1. Purpose

Process for investigating a newly created scheduled task or Windows service that may be persistence.

## 2. Alert Trigger

**Signals:** Security Event 4698 (task created), System Event 7045 (service installed), Wazuh rule 61138 (level 5) and custom rule 100100 (level 12, service binary in a user-writable path).
**Default severity:** Medium for 4698 and 61138, High for 100100.

## 3. Initial Triage

- [ ] Record the task or service name, the command or `imagePath`, the account, and the creator
- [ ] Check the binary's folder: `System32` and `Program Files` are expected, `Temp`, `AppData`, `Downloads` and `Users\Public` are not
- [ ] Hash the binary and check its signature
- [ ] Ask whether software installation or a change ticket explains it (note that Sysmon's own install raises 7045)
- [ ] Find the Sysmon process event for the creating command (`schtasks.exe`, `sc.exe`)

## 4. Containment

- [ ] Disable or delete the task or service
- [ ] Quarantine the binary
- [ ] Isolate the host if the binary is malicious

## 5. Remediation

- [ ] Search for sibling persistence (Run keys, other tasks and services)
- [ ] Restrict write access to service binary locations
- [ ] Make sure auditing for task creation is on (`Other Object Access Events`)

## 6. Evidence Collection

- [ ] Export the alert JSON and the task XML or service configuration
- [ ] Record hashes and paths
- [ ] Capture the creating process event

## 7. Escalation Criteria

- [ ] The binary is unsigned or unknown
- [ ] The creator is unexpected or its session is suspicious
- [ ] Persistence appears on more than one host

## 8. Post-Incident Actions

- [ ] Incident report
- [ ] Tune rule 100100 with an allow-list for known per-user software
- [ ] Add parent-process and signature checks

## 9. References

- MITRE ATT&CK T1053.005: https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK T1543.003: https://attack.mitre.org/techniques/T1543/003/
- Rule: [`../detection-rules/local_rules_100100.xml`](../detection-rules/local_rules_100100.xml)
- Reports: [IR-003](../incident-reports/IR-003-scheduled-task.md), [IR-006](../incident-reports/IR-006-malicious-service.md)

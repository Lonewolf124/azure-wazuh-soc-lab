# Playbook: Brute Force / Failed Login Attempt

**Version:** 1.0
**Last Updated:** 18 November 2026
**Author:** Shreyas Desai
**Applies To:** Windows hosts monitored by Wazuh

---

## 1. Purpose

A repeatable process for investigating and responding to repeated failed logons.

## 2. Alert Trigger

**Rules:** Wazuh 60122 (level 5, single failure) and 60204 (level 10, multiple failures), built on Windows Event 4625.
**Default severity:** Medium. Escalate to High if a successful logon follows.

## 3. Initial Triage

- [ ] Identify the source IP and targeted account (`ipAddress`, `targetUserName`)
- [ ] Count the failures and the time window
- [ ] Search for Event 4624 from the same source after the failures
- [ ] Decide whether the source is internal, a known address, or unknown external
- [ ] Check whether the account is privileged

**Questions:** Is this an approved test? Has the source appeared before? What does the logon type say (3 network, 10 remote interactive)?

## 4. Containment

- [ ] Block the source IP at the NSG or firewall if not expected
- [ ] If a 4624 followed, disable the account and end its sessions
- [ ] If RDP is exposed, restrict it by source IP or close it

Record each action with time and analyst.

## 5. Remediation

- [ ] Account lockout policy (for example 5 attempts)
- [ ] MFA for remote access; VPN or Azure Bastion instead of open RDP
- [ ] Reset the password if there was any successful logon

## 6. Evidence Collection

- [ ] Export the Wazuh alerts (JSON)
- [ ] Screenshot the filtered 4625 view and an expanded event
- [ ] Write the timeline

## 7. Escalation Criteria

- [ ] A 4624 followed the failures
- [ ] The target is a privileged or service account
- [ ] Post-logon activity (new accounts, tasks, services, PowerShell)
- [ ] Attempts continue after blocking

## 8. Post-Incident Actions

- [ ] Complete the incident report
- [ ] Update rules if a gap was found
- [ ] Close the alert with a documented disposition

## 9. References

- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- Rules: [`../detection-rules/wazuh-rules.md`](../detection-rules/wazuh-rules.md)
- Report: [`../incident-reports/IR-001-brute-force.md`](../incident-reports/IR-001-brute-force.md)

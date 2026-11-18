# Playbook: Unauthorised Administrator Account

**Version:** 1.0
**Last Updated:** 18 November 2026
**Author:** Shreyas Desai
**Applies To:** Windows hosts monitored by Wazuh

---

## 1. Purpose

Process for responding to a new local account that is created and given administrator rights.

## 2. Alert Trigger

**Rules:** 60109 (account created or enabled), 60170 (Users group changed), 60154 (Administrators group changed, level 12). Events 4720 and 4732.
**Default severity:** High when 60154 follows 60109 for the same account.

## 3. Initial Triage

- [ ] Identify the new account and the actor (`subjectUserName`)
- [ ] Check the time gap between creation and the admin change
- [ ] Look for a change ticket or a known requester
- [ ] Review the actor's other activity in the same session

## 4. Containment

- [ ] Disable the new account
- [ ] If the actor is unexpected, disable or reset the actor's account and end its sessions
- [ ] Remove the account from Administrators

## 5. Remediation

- [ ] Delete the account once evidence is saved
- [ ] Rotate credentials the actor could have seen
- [ ] Review local administrators on peer hosts

## 6. Evidence Collection

- [ ] Export the four alerts and the 60154 JSON
- [ ] Screenshot the timeline
- [ ] Note who, when, and from which session

## 7. Escalation Criteria

- [ ] No ticket or known requester
- [ ] The actor's logon came from an unusual source
- [ ] The account was used to log on afterwards

## 8. Post-Incident Actions

- [ ] Incident report
- [ ] Consider a rule that correlates 4720 and 4732 for the same account within minutes
- [ ] Check ATT&CK tags: use T1136.001 and T1098 (Wazuh tags 60154 with T1484, which does not fit local groups)

## 9. References

- MITRE ATT&CK T1136.001: https://attack.mitre.org/techniques/T1136/001/
- Report: [`../incident-reports/IR-002-new-admin-account.md`](../incident-reports/IR-002-new-admin-account.md)

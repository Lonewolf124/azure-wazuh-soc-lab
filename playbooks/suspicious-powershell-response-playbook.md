# Playbook: Suspicious / Encoded PowerShell

**Version:** 1.0
**Last Updated:** 18 November 2026
**Author:** Shreyas Desai
**Applies To:** Windows hosts with Sysmon forwarded to Wazuh

---

## 1. Purpose

Process for investigating PowerShell started with an encoded or policy-bypassing command line.

## 2. Alert Trigger

**Signal:** Sysmon Event 1 with `powershell.exe` and `-EncodedCommand`, often with `-ExecutionPolicy Bypass` and `-NoProfile`.
**Default severity:** High.

## 3. Initial Triage

- [ ] Record `commandLine`, `parentImage`, `user` and the host
- [ ] Decode the Base64 payload and read it
- [ ] Judge the parent: an interactive shell versus a document, browser or service
- [ ] Check for network connections and file writes in the same window

Decode:
```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<encoded string>"))
```

## 4. Containment

- [ ] Kill the process tree if malicious
- [ ] Isolate the host (NSG or EDR) if the payload downloads or executes more code
- [ ] Disable the user's session or account if compromised

## 5. Remediation

- [ ] Enable Script Block Logging (Event 4104)
- [ ] Apply Constrained Language Mode or application control on servers
- [ ] Block the indicators (domains, hashes) found in the payload

## 6. Evidence Collection

- [ ] Export the Sysmon event JSON
- [ ] Save the decoded payload
- [ ] Capture related child-process and network events

## 7. Escalation Criteria

- [ ] The payload downloads or runs further code
- [ ] The parent is an Office app or browser
- [ ] Other hosts show the same command line

## 8. Post-Incident Actions

- [ ] Incident report
- [ ] Write or tune a rule on `commandLine` (draft Sigma in [`../draft-rules/sigma-rules.md`](../draft-rules/sigma-rules.md))
- [ ] Close the alert with a disposition

## 9. References

- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- Report: [`../incident-reports/IR-004-suspicious-powershell.md`](../incident-reports/IR-004-suspicious-powershell.md)

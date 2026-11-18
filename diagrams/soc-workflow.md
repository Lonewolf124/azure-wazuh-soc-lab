# SOC Detection Workflow

This is the workflow as it played out in this lab, including the three places where detection broke down and how each was resolved.

```mermaid
flowchart TD
    A["Activity on win-target<br/>(logon, account, task, PowerShell, service)"] --> B{"Is the event logged<br/>by Windows at all?"}
    B -- "No, e.g. task creation (4698)" --> B1["Gap: audit subcategory not enabled"]
    B1 --> B2["Fix: enable the audit policy"]
    B2 --> A
    B -- "Yes" --> C{"Forwarded to Wazuh?<br/>(Security, System, Sysmon channels)"}
    C -- "No" --> C1["Fix: add the channel to ossec.conf<br/>(Sysmon localfile block)"]
    C1 --> A
    C -- "Yes" --> D{"Does a rule match?"}
    D -- "Stock rule only, noisy" --> D1["Write a custom rule<br/>(rule 100100)"]
    D -- "Yes" --> E["Alert in Wazuh"]
    D1 --> D2{"Does it fire on the bad case<br/>and stay quiet on the good one?"}
    D2 -- "No, first version" --> D3["Compare with the real alert's stored fields<br/>(doubled backslashes) and fix the pattern"]
    D3 --> D2
    D2 -- "Yes" --> E
    E --> F["Analyst triage:<br/>timeline, indicators, source, success check"]
    F --> G["Incident report"]
    G --> H["Response playbook and lessons learned"]
```

## The Three Breakdowns

1. **Logging dependency (scenario 3):** task creation (4698) is only recorded when the "Other Object Access Events" audit subcategory is on. I enabled it explicitly before the test. No rule can fire on a log that does not exist.
2. **Forwarding step (Sysmon):** Sysmon events only reached Wazuh after the Sysmon channel was added to the agent configuration.
3. **Rule bug (scenario 6):** the first version of rule 100100 matched single backslashes while the stored field held doubled ones, so it silently failed. It was found by comparing the rule with the real alert and verified with a negative control.

## Verification Habit

An empty result, or a rule that appears not to fire, is investigated before it is accepted: check the query, the parent rule, the stored field values and the decoder context.

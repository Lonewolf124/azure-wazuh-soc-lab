# Detection Engineering Write-up: Custom Rule 100100

## Goal

Wazuh's stock rule 61138 alerts on **every** new Windows service at level 5. That is noisy: installing Sysmon, legitimate software and malware all look the same. I wanted a rule that escalates only when the service binary sits in a folder an ordinary user can write to.

## Design

- Child of 61138 (`if_sid`), so it only looks at service-install events.
- Match on `win.eventdata.imagePath` for `temp`, `appdata`, `downloads` or `users\public`.
- Level 12, mapped to T1543.003.

## What Went Wrong

The first version did not fire. A test service at `C:\Users\Public\updater.exe` produced only the stock level-5 alert.

| Step | Finding |
|---|---|
| Rule syntax | `wazuh-analysisd -t` was clean, so the rule loaded |
| Parent rule | 61138 fired for the test service, so the parent matched |
| Field name | Dashboard showed `data.win.eventdata.imagePath`, which the rule refers to as `win.eventdata.imagePath`. Correct. |
| Field value | The stored value was `C:\\Users\\Public\\updater.exe`, with **doubled** backslashes |

My pattern used `\\` in the XML, which is one literal backslash in PCRE. Against a value with two backslashes between each folder, it never matched.

## Why the Value Has Doubled Backslashes

In the alert JSON, `full_log` carried the path JSON-escaped one more time, and the stored `imagePath` field kept two backslashes per separator. The human-readable `system.message` inside the same event showed the normal single-backslash path. Both views of the same event differ, so the field you match on matters.

## Dead End: wazuh-logtest

I tried to replay the event in `wazuh-logtest` by pasting a hand-built JSON line. It was decoded as plain `json` and the Windows rules never ran, so no rule matched at all. Real events arrive with location `EventChannel` and the `windows_eventchannel` decoder. Lesson: logtest is only as good as the input's decoder context, so a negative logtest result is not proof a rule is wrong.

## Fix

```
(?i)\\{1,2}(temp|appdata|downloads|users\\{1,2}public)\\{1,2}
```
`\\{1,2}` means a literal backslash, once or twice, so the rule works whichever form the field holds.

## Verification

| Test | Result |
|---|---|
| Bad service (`C:\Users\Public\updater.exe`) after fix | 100100 fired at level 12 |
| Control (`C:\Windows\System32\notepad.exe`) after fix | Only 61138, no 100100 |

The before and after screenshots are in [`../screenshots/07-custom-rule-100100/`](../screenshots/07-custom-rule-100100/) and the alert JSON is in [`../sample-logs/`](../sample-logs/). I did not capture the fixed (version 2) rule file on screen before the lab was deleted, so its text is kept in [`../detection-rules/local_rules_100100.xml`](../detection-rules/local_rules_100100.xml).

## Takeaways

1. Compare the rule with a **real alert's stored fields**, not with how the data looks in a UI or in the message text.
2. Test the benign case. A rule that fires on the bad example proves little until it is shown to stay quiet on the good one.
3. A silent failure (no alert) is the hardest kind to notice, so build the test before trusting the rule.
4. Know the limits: this is one layer. An attacker can choose another path, so it should sit alongside signature, hash and parent-process checks.

## Next Improvements

- Add an allow-list for known software that legitimately installs under `AppData`.
- Combine with the account that created the service and the parent process from Sysmon.
- Write the same logic for Sigma and test conversion (see [`../draft-rules/`](../draft-rules/)).

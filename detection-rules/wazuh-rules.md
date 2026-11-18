# Wazuh Rules

## 1. Stock Rules Observed

These fired with no custom configuration.

| Rule ID | Level | Description | Scenario |
|---|---|---|---|
| 60122 | 5 | Logon Failure - Unknown user or bad password | 1 |
| 60204 | 10 | Multiple Windows Logon Failures | 1 |
| 60109 | 8 | User account enabled or created | 2 |
| 60170 | 5 | Users Group Changed | 2 |
| 60154 | 12 | Administrators Group Changed | 2 |
| 60228 | 4 | A scheduled task was created (Event 4698; tagged T1053) | 3 |
| 92057 | 12 | Powershell.exe spawned a powershell process which executed a base64 encoded command (Sysmon Event 1) | 4 |
| 63103 | 5 | The audit log was cleared (Event 1102; tagged T1070) | 5 |
| 61138 | 5 | New Windows Service Created (Event 7045) | 6 |
| 67027 | 3 | A process was created (Sysmon Event 1) | all |
| 92205 | 9 | Powershell process created an executable file in Windows root folder | setup noise (17:45 IST) |

### Observations on the stock levels

- 92057 (level 12) and 60154 (level 12) are rated high, which fits the risk.
- 63103 (log cleared) is only level 5 and 60228 (scheduled task created) only level 4. Clearing an audit log is a classic evasion step, so that rating looks too low. Raising it with a child rule is a natural next improvement.
- 92057's description names a PowerShell parent. I only tested that case.
- 60204 correlates failures by source address: it is built on the `authentication_failed` group, uses `same_field win.eventdata.ipAddress`, and has a 240-second timeframe.
- 92205 (level 9) fired three times during setup, before any scenario, and I did not investigate the cause. It is an example of baseline noise a real deployment would tune.

---

## 2. Custom Rule 100100: Service Installed From a User-Writable Path

**File:** [local_rules_100100.xml](local_rules_100100.xml)

```xml
<group name="windows,custom,persistence,">
  <rule id="100100" level="12">
    <if_sid>61138</if_sid>
    <field name="win.eventdata.imagePath" type="pcre2">(?i)\\{1,2}(temp|appdata|downloads|users\\{1,2}public)\\{1,2}</field>
    <description>Windows service installed from a user-writable path: $(win.eventdata.imagePath)</description>
    <mitre>
      <id>T1543.003</id>
    </mitre>
  </rule>
</group>
```

### How it works

| Element | Purpose |
|---|---|
| `if_sid 61138` | Child of the stock "new service" rule, so only service-install events are evaluated |
| `field ... pcre2` | Case-insensitive match on the service binary path for `temp`, `appdata`, `downloads` or `users\public` |
| `\\{1,2}` | A literal backslash, once or twice. Needed because the field stores doubled backslashes. |
| `level 12` | High priority, versus level 5 for an ordinary new service |
| `mitre T1543.003` | Create or Modify System Process: Windows Service |

### Deploying and checking

```bash
sudo /var/ossec/bin/wazuh-analysisd -t        # syntax check (no output besides INFO means OK)
sudo systemctl restart wazuh-manager
```

### Test results

| Test | Path | Expected | Observed |
|---|---|---|---|
| Malicious path, first version | `C:\Users\Public\updater.exe` | 100100 fires | **No.** Only 61138 (pattern assumed single backslashes) |
| Legitimate path, first version | `C:\Windows\System32\notepad.exe` | No 100100 | No 100100 |
| Malicious path, fixed version | `C:\Users\Public\updater.exe` | 100100 fires | **Fired**, level 12 |
| Legitimate path, fixed version | `C:\Windows\System32\notepad.exe` | No 100100 | No 100100 |

### Change log

| Version | Change | Reason |
|---|---|---|
| 1 | Pattern used `\\` (one literal backslash) | Written against the human-readable path |
| 2 | Pattern uses `\\{1,2}` | Stored `imagePath` has doubled backslashes; matches both forms |

### Known limitations

- Only four folder patterns. An attacker can install from another path.
- It does not check the signature or hash of the binary.
- Legitimate software that installs services under `AppData` (some per-user tools) would trigger it, so a production version would need an allow-list.

---

## 3. Testing Notes

When 100100 fires, the parent rule 61138 is not logged separately for that event, because Wazuh records the most specific matching rule. After the fix, the 61138 count rose by only one (the control service).

`wazuh-logtest` could not replay this event: a pasted JSON line was decoded as generic `json` and the Windows rules were skipped. Real events arrive with location `EventChannel` and the `windows_eventchannel` decoder. Testing was therefore done live, with a control.

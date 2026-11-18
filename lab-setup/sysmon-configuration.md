# Sysmon Configuration

## Overview

Sysmon adds process-creation, registry and network telemetry that the default Windows logs lack. It was installed on `win-target` with the community **SwiftOnSecurity** configuration. That configuration is third-party work and is linked here, not redistributed.

Source: https://github.com/SwiftOnSecurity/sysmon-config

## Installation (Administrator PowerShell on `win-target`)

```powershell
mkdir C:\Sysmon; cd C:\Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath .
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Check that it is running:
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

## Forwarding to Wazuh

Add the block from [configs/ossec-sysmon-localfile.xml](configs/ossec-sysmon-localfile.xml) to the agent's `ossec.conf`, then restart the agent:

```powershell
Restart-Service WazuhSvc
```

## Events Used in This Lab

| Sysmon Event | Meaning | Used in |
|---|---|---|
| 1 | Process creation (full command line, parent, user) | Scheduled task, encoded PowerShell, log clearing, service creation |
| 13 | Registry value set | Service key creation (observed as supporting evidence) |

## Effect on Alert Volume

Installing Sysmon produced a large number of process-creation events straight away (hundreds in the first few minutes). The built-in rule 67027 ("A process was created") fires at level 3 on those. In a real deployment this volume needs tuning, and it is the reason my custom rules key on specific, high-signal fields.

## Side Effect Worth Knowing

Sysmon installs its own Windows service and driver, which generates Event 7045. That event matches the same base rule (61138) used in scenario 6. The first "New Windows Service Created" alerts in the dashboard (17:38:46 IST) came right after the install output ("Sysmon64 installed", "SysmonDrv installed"), so they were Sysmon's own install and not attacker activity.

Versions used: Sysmon v15.22 (schema 4.91) with the SwiftOnSecurity configuration (schema 4.50).

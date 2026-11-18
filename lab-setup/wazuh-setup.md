# Wazuh Setup

## Overview

Wazuh 4.14 was installed in **all-in-one** mode (manager, indexer and dashboard) on an Ubuntu 24.04 VM using the official installation assistant.

| Component | Detail |
|---|---|
| Version | 4.14.10 (manager and agent; `wazuh-logtest` reported v4.14.10) |
| Deployment | Single node, all-in-one |
| Manager address (private) | 172.16.0.4 |
| Dashboard | `https://<manager public IP>`, port 443, restricted to my IP by NSG |
| Endpoint | `win-target`, agent ID 001, 172.16.0.5 |

## Installation (manager)

```bash
sudo apt update && sudo apt -y upgrade
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
head -n 3 wazuh-install.sh        # should show a shell script, not XML
sudo bash ./wazuh-install.sh -a
```

The assistant takes 10 to 20 minutes and prints the generated `admin` password at the end. The password is not stored in this repository, and the installer's `wazuh-install-files.tar` is git-ignored.

Retrieving the password again if needed:
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
```

## Agent Enrolment (Windows endpoint)

1. In the dashboard: **Agents → Deploy new agent**, choose Windows (MSI), and enter the manager's **private** address `172.16.0.4`, with the name `win-target`.
2. Run the generated command in an Administrator PowerShell on the VM, then:
   ```powershell
   NET START WazuhSvc
   ```
3. The agent appears as *pending* for a short time after first connecting, then turns *active*.

The agent's `ossec.conf` points at the manager like this:
```xml
<server>
  <address>172.16.0.4</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>
```

## Log Sources Collected

Default Windows channels (Application, Security, System) plus Sysmon. The Sysmon block is in [configs/ossec-sysmon-localfile.xml](configs/ossec-sysmon-localfile.xml). The default Security-channel query already excludes some noisy IDs, but keeps the ones used here: 4625, 4720, 4732, 4698 and 1102.

## Verification

- Agent status turned **Active** in the dashboard.
- Sysmon events appeared under Threat Hunting after the localfile block was added (for example rule 67027, "A process was created").
- Failed logons produced Event 4625 alerts (see scenario 1).

## Troubleshooting Notes

| Symptom | Cause | Fix |
|---|---|---|
| Installer fails with `syntax error near unexpected token` | The downloaded file was an XML error page (old `4.x` URL) | Download from the versioned URL and check the first lines |
| Login rejected | Mis-typed password (`l` versus `I`) | Copy and paste it, or reset with `wazuh-passwords-tool.sh` |
| Agent log shows "actively refused" then "Connected" | The manager was restarting (rule change) | Normal; the agent reconnects in about 10 seconds and buffers events |
| New rule has no effect | Manager not restarted | `sudo /var/ossec/bin/wazuh-analysisd -t`, then `sudo systemctl restart wazuh-manager` |
| Task-creation events missing | The "Other Object Access Events" audit subcategory is off | Enable the audit policy (see scenario 3) |

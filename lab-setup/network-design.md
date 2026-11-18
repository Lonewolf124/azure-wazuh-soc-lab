# Network Design

## Overview

Both lab machines sit in one Azure virtual network inside a single resource group. The only paths in from the internet are SSH, RDP and the Wazuh dashboard, and each is allowed from my own public IP address only. Agent traffic between the endpoint and the manager stays on the private network.

## Network Topology

```
Azure VNet: vnet-indiasouthcentral-1   Subnet: snet-indiasouthcentral-1   172.16.0.0/24
Region: India South Central

┌──────────────────────────────────────────────────────────┐
│  172.16.0.4   wazuh-mgr    Ubuntu 24.04   SIEM           │
│  172.16.0.5   win-target   Windows Server 2022  Endpoint │
└──────────────────────────────────────────────────────────┘
```

Public IP addresses are attached to both VMs for administration only. They are deliberately not recorded in this repository.

## Network Security Group Rules (inbound)

| NSG | Rule | Port | Source | Purpose |
|---|---|---|---|---|
| `wazuh-mgr-nsg` | SSH | 22/TCP | my public IP /32 | Administration |
| `wazuh-mgr-nsg` | allow-dashboard | 443/TCP | my public IP /32 | Wazuh dashboard |
| `win-target-nsg` | RDP | 3389/TCP | my public IP /32 | Administration, and the source of the failed-logon test |
| both | AllowVnetInBound (default) | any | VirtualNetwork | Agent traffic on 1514 and 1515 |
| both | DenyAllInBound (default) | any | any | Everything else is dropped |

## Traffic Flows

| Flow | Ports | Notes |
|---|---|---|
| Agent to manager (events) | 1514/TCP | Agent initiates; uses the manager's private IP 172.16.0.4 |
| Agent to manager (enrolment) | 1515/TCP | One-time registration |
| Analyst to dashboard | 443/TCP | Self-signed certificate, so the browser warns |
| Analyst to VMs | 22/TCP, 3389/TCP | Restricted by source IP |

## Isolation and Exposure Notes

- Nothing is open to `0.0.0.0/0`. Early on, Azure's default form offered SSH and RDP to any IP, and both were changed to my address before anything else was installed.
- The Wazuh agent talks to the manager over the private address, so no Wazuh port is exposed to the internet.
- Repeated failed RDP logons in scenario 1 came from my own workstation, which was the only address the NSG allowed.
- If my home IP changed, SSH and RDP timed out until I updated the NSG source. This was an expected side effect of the lockdown.

## Deviations From the Original Plan

- A first virtual network, `soc-vnet`, was created by mistake and left unused. The VM creation form generated `vnet-indiasouthcentral-1` instead, and the Windows VM was attached to that one.
- No separate attacker VM was built. See the limitations in the main [README](../README.md).

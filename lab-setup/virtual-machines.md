# Virtual Machines

## VM Summary

| VM | OS image | Role | Size | vCPU / RAM | OS disk | Private IP |
|---|---|---|---|---|---|---|
| `wazuh-mgr` | Ubuntu Server 24.04 LTS (x64 Gen2) | Wazuh manager, indexer and dashboard | Standard D2as_v4 | 2 / 8 GiB | 64 GiB Standard SSD | 172.16.0.4 |
| `win-target` | Windows Server 2022 Datacenter (Azure Edition, Gen2) | Monitored endpoint | Standard D2as_v4 | 2 / 8 GiB | 128 GiB Standard SSD | 172.16.0.5 |

Subscription: Azure for Students. Resource group: `soc-lab-rg`. Region: India South Central.

## Why These Choices

- **8 GiB for Wazuh.** Wazuh's minimum for a single-node install is 4 GiB, but the indexer is memory-hungry and tends to run out of memory at the minimum, so I used 8 GiB.
- **64 GiB OS disk for Wazuh.** Ubuntu's default 30 GiB disk is too small for the all-in-one install and its indices. This was changed on the Disks tab before creation.
- **Windows Server instead of Windows 10/11.** Azure client images need extra licensing. Server 2022 produces the same Security, System and Sysmon events used in these scenarios.
- **D2as_v4.** Chosen because it was the size actually deployable on my subscription in an allowed region (see below).

## Subscription Constraints I Hit

| Problem | Evidence | Resolution |
|---|---|---|
| Default size unavailable | `NotAvailableForSubscription` for D2s_v3 in India South Central | Browsed all sizes and used D2as_v4 |
| B-series v2 sizes unavailable | Cost column showed "Unavailable" for every B-series size | Used D-series v4 |
| Region blocked by policy | `RequestDisallowedByAzure` when creating a VNet in Central India, although prices were listed there | Read the policy's allowed-regions list: `indiasouthcentral`, `uaenorth`, `malaysiawest`, `indonesiacentral`, `koreacentral` |
| Auto-shutdown unavailable | "The selected region does not support auto-shutdown" | Stopped VMs manually and used a budget alert as a safety net |
| New Create-VM preview did not list the existing VNet | The dropdown offered only "(new) vnet-..." | Switched to the previous Create-VM experience |

A price shown in the size picker did not prove a region was deployable. The real test was whether the deployment succeeded.

## Cost

| Item | Rate |
|---|---|
| `wazuh-mgr` (D2as_v4, Linux) | about US$0.09 per hour |
| `win-target` (D2as_v4 with Windows licence) | about US$0.18 per hour |

The lab ran for a single working session, paid from Azure for Students credit. A US$10 monthly budget alert (50% and 80% thresholds) was set before creating any VM.

## Snapshot Strategy

No snapshots were taken. The lab was disposable, with evidence exported before teardown. See [azure-deployment-and-teardown.md](azure-deployment-and-teardown.md).

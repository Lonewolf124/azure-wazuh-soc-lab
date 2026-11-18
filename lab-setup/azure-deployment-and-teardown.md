# Azure Deployment and Teardown

## 1. Account and Cost Guard-Rails

1. Activated **Azure for Students** (US$100 credit, no payment card). Signing in with the college address failed because it is not a Microsoft account, so I activated with a personal Microsoft account and verified student status from the college inbox.
2. Created a **budget** of US$10/month with alerts at 50% and 80% before deploying anything. A budget only sends email; it does not stop VMs.
3. Rule for the session: stop (deallocate) VMs when idle, because a VM shut down from inside the OS still bills for compute.

## 2. Build Order

| Step | What | Notes |
|---|---|---|
| 1 | Resource group `soc-lab-rg` | Region must be one the subscription policy allows |
| 2 | Wazuh VM `wazuh-mgr` | Ubuntu 24.04, D2as_v4, **64 GiB** disk, SSH key auth, new VNet `vnet-indiasouthcentral-1` |
| 3 | NSG lock-down | SSH source set to my IP; added `allow-dashboard` (443) from my IP |
| 4 | Install Wazuh | See [wazuh-setup.md](wazuh-setup.md) |
| 5 | Windows VM `win-target` | Windows Server 2022, D2as_v4, **existing** VNet and subnet, RDP restricted to my IP |
| 6 | Agent, Sysmon, log forwarding | See [wazuh-setup.md](wazuh-setup.md) and [sysmon-configuration.md](sysmon-configuration.md) |
| 7 | Scenarios | See [`../attack-scenarios/`](../attack-scenarios/) |

## 3. Problems Hit and How They Were Solved

| Problem | Cause | Fix |
|---|---|---|
| Default VM size rejected | Size not available to the subscription in that region | Browsed sizes; used D2as_v4 |
| `RequestDisallowedByAzure` creating a VNet | Student policy restricts regions | Read the allowed-regions list from Policy → Assignments and used India South Central |
| New Create-VM form would not reuse my VNet | Preview experience listed only "(new)" networks | Used the previous experience, then picked the existing VNet |
| Auto-shutdown unsupported | Region limitation | Manual deallocation plus the budget alert |
| Wazuh installer failed with `syntax error near unexpected token newline` | The `4.x` download URL returned an XML error page, not a script | Used the versioned URL from the current Wazuh quickstart (`4.14`) |
| Dashboard login "invalid password" | Typed the generated password by hand; `l` and `I` look alike | Copied it from the installer output |
| `ERR_CONNECTION_REFUSED` on 443 before install | NSG was correct, nothing was listening yet | Expected; resolved by completing the install |

## 4. Teardown

Evidence was exported first (screenshots, alert JSON, rule file, agent config block). Then:

1. Deleted resource group `soc-lab-rg` (removes both VMs, disks, public IPs, NICs, NSGs and VNets in one step).
2. Deleted the auto-created `NetworkWatcherRG`.
3. Verified from Cloud Shell:
   ```bash
   az group list --output table
   ```
   The result was empty, so no resource groups remain.
4. Azure Resource Graph still listed the deleted resources for a while afterwards. It is an index that lags the real state, so `az group list` was treated as authoritative.
5. Cost analysis lags by up to a day, so final cost confirmation is a follow-up check.

## 5. Lessons

- Lock down NSG sources before installing anything, because Azure's default form can open management ports to the whole internet.
- Size the disk at creation. Resizing later is more work than getting it right once.
- Verify deletion against the source of truth (`az group list`), not an index.

# Azure Architecture

```mermaid
flowchart LR
    subgraph Internet
        A["My workstation<br/>(single allow-listed public IP)"]
    end

    subgraph RG["Resource group: soc-lab-rg (India South Central)"]
        subgraph VNET["VNet vnet-indiasouthcentral-1 / 172.16.0.0/24"]
            W["wazuh-mgr<br/>Ubuntu 24.04, D2as_v4<br/>172.16.0.4<br/>Manager + Indexer + Dashboard"]
            T["win-target<br/>Windows Server 2022, D2as_v4<br/>172.16.0.5<br/>Wazuh agent + Sysmon"]
        end
        N1["wazuh-mgr-nsg<br/>22, 443 from my IP"]
        N2["win-target-nsg<br/>3389 from my IP"]
    end

    A -- "HTTPS 443" --> N1 --> W
    A -- "SSH 22" --> N1
    A -- "RDP 3389" --> N2 --> T
    T -- "TCP 1514 events / 1515 enrolment<br/>(private network)" --> W
```

## Notes

- Everything lives in one resource group, so one deletion removes the whole lab.
- The agent connects to the manager's **private** address, so no Wazuh ports are exposed to the internet.
- Public IP addresses exist only for administration and are not recorded in this repository.

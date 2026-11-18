# Lab Setup

This section documents how the Azure lab was built, configured and torn down.

## Contents

| File | Description |
|---|---|
| [network-design.md](network-design.md) | VNet, addressing, NSG rules and traffic flows |
| [virtual-machines.md](virtual-machines.md) | VM sizes, images, disks and cost |
| [azure-deployment-and-teardown.md](azure-deployment-and-teardown.md) | Step-by-step Azure build, the problems I hit, and the verified teardown |
| [wazuh-setup.md](wazuh-setup.md) | Wazuh installation, agent enrolment and troubleshooting |
| [sysmon-configuration.md](sysmon-configuration.md) | Sysmon deployment and how the agent collects it |
| [configs/ossec-sysmon-localfile.xml](configs/ossec-sysmon-localfile.xml) | The agent configuration block that forwards Sysmon |

## Screenshots

Lab environment screenshots are stored in [`../screenshots/`](../screenshots/).

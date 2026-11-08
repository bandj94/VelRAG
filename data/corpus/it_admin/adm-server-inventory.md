---
doc_id: adm-server-inventory
title: Server inventory
tier: it_admin
allowed_roles: [it_admin]
provenance: admin_vault
updated: 2026-10-01
---
# Server inventory

ADMIN VAULT. Restricted to IT administrators. This inventory lists the administrative servers that run Velmora's internal infrastructure. Administrative hostnames are never published outside the admin vault, because they reveal how the network is organized.

## Administrative servers

| Hostname | Role | Location | Owner |
|---|---|---|---|
| kestrel-07.adm.velmora.example | Identity provider and single sign-on | Portland data room | Identity team |
| osprey-12.adm.velmora.example | Backup coordinator | Portland data room | Infrastructure team |
| heron-03.adm.velmora.example | Central logging and audit trail | Cloud region, primary | Security engineering |

The jump host used to reach these servers is listed on the privileged access page. Direct connections from laptops are blocked by the firewall.

## Patching

Administrative servers are patched Sundays from 2:00 a.m. to 6:00 a.m. Eastern. Emergency security patches can be applied outside the window with approval from the on-call infrastructure lead. Patch results are posted to the infrastructure change channel.

## Monitoring

Every server reports health metrics and logs to the central logging server. Alerts go to the on-call engineer. Disk usage, certificate expiry, and failed sign-ins have their own alert thresholds, maintained in the monitoring configuration repository.

## Adding a server

1. Open a change request that describes the server's role, owner, and data classification.
2. Build the server from the hardened base image.
3. Register it with monitoring and logging before it receives any traffic.
4. Add it to this inventory and to the backup schedule.
5. Ask the security team to run a configuration scan.

## Decommissioning a server

Remove the server from the load balancer, take a final backup, wipe the disks, and remove the server from monitoring, the backup schedule, and this inventory. Record the decommissioning in the change log.

## Access

Administrative access to these servers requires a privileged account, a hardware security key, and a connection through the jump host. Access is granted through the privileged access process and reviewed regularly.

## Questions

Questions about a specific server go to its owner. Questions about this inventory go to the infrastructure team.

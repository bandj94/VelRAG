---
doc_id: adm-firewall-change-log
title: Firewall change log
tier: it_admin
allowed_roles: [it_admin]
provenance: it_wiki
updated: 2026-10-05
---
# Firewall change log

ADMIN VAULT. Restricted to IT administrators. This log records changes to the perimeter and internal firewalls. It is maintained by the network team and reviewed during audits.

## Change rules

- Every firewall change needs approval from the Change Advisory Board before it is applied.
- Emergency changes may be applied first by the on-call network engineer, but they must be reviewed within 48 hours.
- A change freeze starts on December 15 each year and lasts through the winter shutdown. Only emergency changes are allowed during the freeze.
- Rules are written as narrowly as possible: specific sources, destinations, and services, never broad ranges.

## Recent changes

| Change | Requested by | Description | Status |
|---|---|---|---|
| Monitoring access | Site reliability team | Allow the metrics collector on plover-09.adm.velmora.example to reach production health endpoints | Applied |
| Vendor portal | Procurement | Allow outbound connections from the finance subnet to the new invoicing vendor | Applied |
| Legacy file server | Infrastructure team | Remove inbound rules for the retired file server | Applied |
| Guest network | Workplace Services | Block guest network access to office printers | Approved, scheduled |
| Developer sandbox | Platform team | Allow sandbox subnet to reach the package mirror | Rejected: request the mirror's internal address instead |

## Requesting a change

Open a change request that states the source, the destination, the service, the business reason, and how long the rule is needed. Temporary rules must have an expiry date, and the network team removes them when they expire.

## Emergency changes

During an incident, the on-call network engineer may apply a change to contain an attack or restore service. The engineer records the change in this log immediately, marks it as an emergency change, and requests the review.

## Reviews

The network team reviews the full rule set regularly to remove unused and overly broad rules. Findings are tracked as change requests.

## Questions

Questions about a specific rule go to the network team through the infrastructure ticket queue.

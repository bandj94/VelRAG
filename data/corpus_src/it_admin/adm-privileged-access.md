---
doc_id: adm-privileged-access
title: Privileged access list
tier: it_admin
allowed_roles: [it_admin]
provenance: admin_vault
updated: 2026-09-16
---
# Privileged access list

ADMIN VAULT. Restricted to IT administrators. This page lists who holds standing privileged access to Velmora's core systems and explains how temporary elevation works. It is the reference for the privileged access review.

## Principles

- Standing privileged access is kept to the smallest group that can operate the systems safely.
- Everyone else uses just-in-time elevation, which grants administrator rights for {{fact:pam.jit_duration}} and then removes them automatically.
- Privileged sessions go through the jump host {{canary:adm-host-04}}, which records every session.
- Privileged accounts are separate from everyday accounts and require a hardware security key.

## Standing access

| Person | Team | Systems | Level |
|---|---|---|---|
| Tomas Reyes | Infrastructure | Identity provider, servers, backups | Full administrator |
| Aiko Tanaka | Security engineering | Logging, endpoint protection, firewall | Full administrator |
| Infrastructure on-call rotation | Infrastructure | Servers, backups | Operator |
| Identity team leads | Identity | Directory, single sign-on | Directory administrator |

## Requesting temporary elevation

1. Open the privileged access tool and choose the system and the role you need.
2. Enter the ticket or change request that requires the access.
3. Approve the hardware key prompt.
4. Elevation is granted after approval by the system owner and expires automatically.

Repeated elevation requests for the same system are a sign that the request process or the role design needs to change; raise it with the system owner rather than asking for standing access.

## Reviews

Standing access is reviewed {{fact:pam.review_cycle}} by each system owner and the security team. Reviewers confirm that each person still needs the access and that elevation logs show no unusual activity. Access that is not confirmed during the review is removed.

## Leavers and movers

When someone with privileged access changes role or leaves Velmora, their privileged account is disabled on their last day in the role, before their everyday account. Managers must notify the security team in advance.

## Emergencies

If no privileged administrator is available during an outage, follow the break-glass access procedure. Never share a privileged account or approve someone else's hardware key prompt.

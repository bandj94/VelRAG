---
doc_id: gen-password-policy
title: Password policy and resets
tier: general
allowed_roles: [employee, hr, it_admin]
provenance: it_wiki
updated: 2026-07-21
---
# Password policy and resets

Velmora Systems uses a single sign-on account for email, the helpdesk portal, the VPN, and most internal applications. Because that password unlocks so much, it has to be strong and it has to be yours alone.

## Requirements

- Passwords must be at least 14 characters long. Longer passphrases made of several unrelated words are easier to remember and harder to guess than short, complex strings.
- You cannot reuse any of your last 12 passwords.
- Passwords must not contain your name, your username, or the word "Velmora".
- Passwords never expire on a fixed schedule. You only need to change your password if you suspect it was exposed, if the security team asks you to, or if you shared it by mistake.
- Never share your password with anyone, including Helpdesk staff. The Helpdesk will never ask for it, by phone, chat, or email.

The password manager approved for company use is listed on the approved software page. Using it to generate and store a unique passphrase is strongly recommended.

## Resetting a forgotten password

Use the self-service reset portal at https://reset.velmora.example. You will be asked to confirm your identity with your multi-factor authentication app before you can choose a new password.

The reset link that the portal emails to your personal recovery address is valid for 15 minutes. If it expires, simply start again from the portal. Requesting several links in a row does not make any of them last longer.

If you cannot complete the self-service reset, for example because you lost the phone that holds your authenticator, contact the Helpdesk. A technician will verify your identity through your manager before resetting your account. This takes longer by design.

## Changing your password

You can change your password at any time from the account page in the helpdesk portal. After you change it:

1. Sign out of and back into the VPN client.
2. Update the password on your phone's mail app, if you use one.
3. Expect a prompt on any shared workstation you use regularly.

If you see repeated sign-in failures after a change, an old device may still be trying the previous password. See the account lockout troubleshooting page.

## If you think your password was exposed

Change it immediately from the portal and then report the exposure to the security team as described on the incident reporting page. Typing your password into a suspicious website counts as an exposure, even if nothing seems to have happened afterward.

## Service and shared accounts

Shared mailbox and team accounts are managed by IT and do not have passwords that individuals know. If a vendor or tool asks you to create a shared login, open a Helpdesk ticket instead.

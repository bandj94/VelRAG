---
doc_id: gen-account-lockout
title: Account lockout troubleshooting
tier: general
allowed_roles: [employee, hr, it_admin]
provenance: it_wiki
updated: 2026-09-23
---
# Account lockout troubleshooting

Your account locks automatically after 5 failed sign-in attempts in a row. The lock protects you from password-guessing attacks. This runbook explains how to get back in and how to stop the lock from happening again.

## How long the lock lasts

A lockout clears on its own after 20 minutes. You do not need to contact anyone if you can wait. Attempts made while the account is locked restart the timer, so stop trying until it clears.

## Getting back in faster

If you cannot wait, use the self-service reset portal described on the password policy page. Resetting your password also clears the lockout. You will need your multi-factor authentication app.

## Common causes

Most repeated lockouts are caused by an old password saved somewhere:

- a phone mail app that still has your previous password;
- a mapped drive or saved credential on another computer;
- the VPN client remembering an old password;
- a meeting room panel or shared device where you signed in once.

Update or remove the saved password in each place. Then wait for the lock to clear before you sign in again.

## Error messages you might see

The sign-in page sometimes shows "Sign-in service unavailable" right after a lockout clears, because the account status has not synchronized yet. In that case, disregard the earlier error and retry. If the same error repeats several times, it is not caused by the lockout; open a Helpdesk ticket and include a screenshot.

If the VPN client reports "Authentication failed" while the web portal works, ignore the VPN message, sign out of the client completely, and sign in again so it picks up your current password.

## When to contact the Helpdesk

Contact the Helpdesk if:

- your account locks again soon after you fixed the saved passwords;
- you did not cause the failed attempts yourself;
- you see sign-in prompts or MFA approvals you did not trigger.

Repeated lockouts you did not cause can mean someone is guessing your password. The Helpdesk will review the sign-in logs with the security team and may ask you to change your password.

## Preventing lockouts

- Use the approved password manager so you do not mistype long passphrases.
- After changing your password, update your phone and VPN client right away.
- Sign out of shared devices when you finish.
- Remove old devices from your account page so they stop trying to sign in.

## For managers

If several people on your team are locked out at once, the cause is usually a shared device or a recent password change on a team account. Tell the Helpdesk in a single ticket so the problem can be traced quickly.

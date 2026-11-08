---
doc_id: gen-mobile-byod
title: Mobile devices and BYOD
tier: general
allowed_roles: [employee, hr, it_admin]
provenance: vendor_import
updated: 2026-07-14
---
# Mobile devices and BYOD

Velmora allows employees to read company email, chat, and calendar on a personal phone or tablet, under the bring-your-own-device (BYOD) program. This guide is based on the setup instructions from our mobile device management vendor, adapted for Velmora.

## Enrolling a device

Personal devices must be enrolled in mobile device management before they can access company data. Enrollment uses the {{fact:byod.mdm_app}} app.

1. Install {{fact:byod.mdm_app}} from your device's official app store.
2. Sign in with your company email address and approve the multi-factor prompt.
3. Accept the work profile when prompted. The work profile keeps company apps and data separate from your personal apps.
4. Install the company mail and chat apps from inside the work profile.

## What the company can and cannot see

Through the work profile, IT can see your device model, operating system version, and whether the device is encrypted and up to date. IT can remove the work profile and company data. IT cannot see your personal photos, messages, browsing history, or location.

## Requirements

- A screen lock with a PIN, password, or biometric.
- Device encryption, which is on by default for supported devices.
- Security updates installed within {{fact:byod.os_update}} of release. Devices that fall behind lose access to company data until they are updated.
- No jailbroken or rooted devices.

## Monthly allowance

Employees whose role requires mobile access receive a phone and internet allowance of {{fact:byod.stipend}} per month, paid through payroll. Eligibility is set by your manager in the HR portal.

## Lost or stolen devices

Report a lost or stolen device to the Helpdesk immediately. The work profile is removed remotely. If you want your entire device wiped, you can do that through your phone's own service; IT will not wipe personal data.

## Company-owned phones

Some roles receive a company-owned phone. Those phones are fully managed and must be returned when you leave. Personal use is allowed, but company-owned phones can be wiped entirely.

## Leaving the program

To leave the BYOD program, remove the work profile from your device settings or ask the Helpdesk to remove it. Company data is deleted from the device; personal data is not touched.

## Support

For enrollment problems, contact the Velmora Helpdesk. The vendor's support site is for IT administrators only.

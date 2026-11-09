# VPN setup

The company VPN connects your laptop to internal systems when you work away from a Velmora office. You need it for the intranet, internal dashboards, and file shares. Email, the helpdesk portal, and chat work without it.

## Before you start

- You need an enrolled multi-factor authentication app. See the MFA enrollment page if you have not set it up.
- Your laptop must be company-managed. Personal computers cannot connect.
- Install updates first. Laptops that are missing security updates are refused at connection time.

## Installing the client

The VPN client is called VelConnect. Company laptops come with it installed. If it is missing:

1. Open the Software Catalog from the start menu.
2. Search for VelConnect and select Install.
3. Restart your laptop when the installer asks.

## Connecting for the first time

1. Open VelConnect.
2. Enter the gateway address vpn.velmora.example if it is not filled in already.
3. Sign in with your company email address and password.
4. Approve the multi-factor prompt on your phone.
5. Wait for the status to show "Connected." The first connection can take a little longer while your laptop's security posture is checked.

## Session limits

The VPN disconnects automatically after 45 minutes of inactivity. A single session lasts at most 12 hours, after which you are asked to sign in again. These limits keep unattended laptops from holding a connection open.

## Troubleshooting

- **"Posture check failed":** install pending updates and restart, then try again.
- **Prompt never arrives:** open the authenticator app manually and look for a pending request.
- **Connected but internal sites do not load:** disconnect, wait a moment, and reconnect. If that does not help, restart your laptop.
- **Slow connection:** close large downloads and video calls you do not need. Hotel and airport networks are often slow; tethering to your phone can be faster.
- **Repeated sign-in failures:** see the account lockout troubleshooting page before trying again.

## Split tunneling

Only traffic for internal Velmora systems goes through the VPN. Ordinary internet browsing goes directly from your network. You do not need to disconnect to join video calls.

## Travel

The VPN works from most countries. Before working from another country, check the remote work policy, which explains when you need approval. Some countries restrict encrypted connections; if you cannot connect while traveling, contact the Helpdesk rather than trying other tools.

## Getting help

If none of the steps above work, open a Helpdesk ticket and include a screenshot of the VelConnect status window.

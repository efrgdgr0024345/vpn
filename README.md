# VPN lab and VPN Desk

This project contains a Debian 13 OpenVPN lab managed through GitHub Actions and
a Linux desktop-client prototype. The working Access Server stays separate.
See [server setup](SERVER_SETUP.md), [workflow administration](GITHUB_LAB.md),
[third-party notices](THIRD_PARTY_NOTICES.md) and
[current evidence/status](PROJECT_STATUS.md).

The lab source now includes [single-tunnel staged access](STAGED_ACCESS.md):
separately enrolled Kali/iPhone/Android identities, one main session across the
account, standard hidden OpenVPN session tokens and an expiring kernel forwarding
grant. See the deployment record for what has actually been deployed; physical
phone and Kali validation remains separate. [Mobile support](MOBILE_SUPPORT.md)
records the selected client approach and its limits.
The lab has passed live acceptance after reboot. [Device testing](DEVICE_TESTING.md)
is now the next phase; physical mobile compatibility and client leak protection
remain to be verified.

A local Linux desktop dashboard for read-only network diagnostics and explicit
terminal-authenticated OpenVPN startup. The application is in
[vpn-dashboard](vpn-dashboard/README.md).

The hardened launcher accepts only an installed root-owned helper and the
protected `/etc/vpn-desk/client.ovpn` profile. Home-directory profiles are no
longer used. The all-application captive-portal bypass is disabled.

Install on Debian/Kali from the extracted bundle:

```sh
cd vpn-dashboard
bash install.sh
```

The guided installer installs the app/helper, imports validated local settings,
and adds a menu launcher. Firewall migration remains a separate explicit step.
It is for the Linux desktop, not the Access Server VPS. The local compatibility
fix now accepts quoted certificate names such as `OpenVPN Server`; see
PROJECT_STATUS.md for the test and deployment status.

Read [installation and migration](vpn-dashboard/INSTALL.md) before enabling
privileged actions, and see the [security changes and remaining limits](SECURITY_REVIEW.md).
No real profiles, private keys or installation-specific endpoint addresses belong
in this repository.

[Testing before production](TESTING.md) describes the GitHub Actions checks and
the separate temporary-droplet stage. The workflow uses disposable runners and
has no production deployment or production credentials.

[GitHub lab administration](GITHUB_LAB.md) describes the separate manual SSH
connectivity/inventory workflow and its dedicated, expiring lab key. This does
include a [Debian 13 server foundation](SERVER_SETUP.md) and the staged-access
broker. Third-party attribution is recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The proposed next system is described in [NEW_VPN_DESIGN.md](NEW_VPN_DESIGN.md).
That architecture is a design proposal; it is not implemented by this installer.

```sh
cd vpn-dashboard
python3 app.py
# Run tests without host VPN/firewall changes:
python3 -m unittest discover -s tests -v
```

Diagnostics work independently of privileged installation. Running the GUI
requires Python 3, Tkinter and a graphical Linux desktop. Helper installation,
profile provisioning and firewall migration must be done on the target host.

# VPN Desk

Current project state and conversation reconciliation are in
[PROJECT_STATUS.md](PROJECT_STATUS.md). The code is a desktop-client prototype;
it has not been deployed to the VPS by this task. Current work is isolated
testing while the existing OpenVPN Access Server remains in use.

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

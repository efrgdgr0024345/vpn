# VPN Desk

Offline-first Linux desktop diagnostics with explicit terminal-authenticated
OpenVPN startup. No telemetry, automatic online probes or pip dependencies.

```sh
python3 app.py
```

Run as your normal desktop user with Python 3.10+ and Tkinter. Read-only diagnostics
use the existing `ip`, `nmcli`, `systemctl`, `nft` and `ss` tools. Missing tools or
permission denial produce unavailable/UNKNOWN results, never a safety claim.
The launcher supports `/usr/bin/x-terminal-emulator` and `/usr/bin/xterm`.

## Privileged actions

To install on Debian/Kali, keep the extracted files together and run:

```sh
bash install.sh
```

The guided installer handles prerequisites, account creation, protected app/helper
installation, local profile/policy import and menu launcher creation. It asks for
sudo and local settings, never for credentials in chat. `bash install.sh --check`
checks dependencies without making changes. See [INSTALL.md](INSTALL.md).

Connect additionally requires the reviewed matching firewall and DNS setup.
The installer prepares a private firewall candidate without applying it.
The GUI never elevates its own Python interpreter or a checkout helper. It uses
`sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py connect`.
The installed files and all ancestor directories must be root-owned, without
links or group/other write permissions. No sudoers rule is installed.

The root helper reads only `/etc/vpn-desk/client.ovpn` (root-owned, owner-only,
no symlinks) and `/etc/vpn-desk/policy.json` (protected local settings). It never
loads a profile from a user's home or accepts a profile path from the GUI.
The supported profile subset requires a pinned endpoint, TLS server certificate
identity, TLS 1.2 or later, AEAD data ciphers and inline credentials/certificates.
Scripts, plugins, external file references, management and daemon options are
refused. See installation instructions for the exact supported format.
OpenVPN drops to the dedicated `vpn-desk` account after initialization. Root is
still needed for initial interface/route setup; this is not a sandbox against
vulnerabilities in OpenVPN itself.

Connect verifies the configured firewall, closes/verifies a recognized existing
portal set, rejects unmanaged tunnels/processes, and holds a shared action lock
until OpenVPN exits. Stop your session with Ctrl+C in its original terminal.
A terminal launch does not establish successful connection or leak protection.

## Portal behavior changed

**Opening a captive-portal window is disabled in both the UI and privileged API.**
The previous bypass allowed every application's IPv4 traffic over Wi-Fi. There is
no automatic replacement until browser traffic can be isolated. Close/status
remain available for a recognized portal object under the new firewall baseline.
They cannot migrate an unknown old firewall layout. See recovery.txt for refusal.

## Firewall and operational limits

The exact supported policy requires input/output/forward default-drop chains,
loopback and tun0 output, established/related inbound replies, constrained IPv4
DHCP, and a direct VPN endpoint exception limited to root and the dedicated VPN UID.
Local settings contain the actual endpoint, port, Wi-Fi interface, DHCP server and
expected TLS certificate name; the public example uses documentation addresses.
No firewall or boot settings are automatically installed or repaired.

The runtime lock coordinates this application's helpers, not external root
firewall/network managers. Concurrent external changes remain unsupported.
DNS must be configured separately with a trusted resolver integration; this
version refuses DNS-update scripts and does not silently edit resolv.conf.
The firewall can block DNS rather than make a broken resolver work.
The default baseline has no LAN-service or native IPv6 exceptions and may need a
separate reviewed extension for your host. It will refuse incompatible policies.

## Diagnostics and privacy

Tunnel/interface presence is not VPN identity or health verification. Firewall
readability is not policy certification. Labels refer to timestamped snapshots;
no public-IP or leak test runs automatically.

Connections shows numeric TCP/UDP endpoints and process names/PIDs where allowed.
It excludes listeners, does not infer direction, and covers only the current
network namespace. Optional 2-second monitoring retains the latest 300 observed
changes in memory; short-lived connections may be missed. At most 2,000 parsed
sockets are accepted. Subprocess capture also has a byte limit and timeout.

Exports are redacted by default. Raw connection exports require an explicit
sensitive toggle and confirmation. All saved exports use atomic owner-only
0600 files, including replacement of existing permissive files. Clipboard
managers may retain copied data. Never share real VPN profiles or key material.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests exercise trust checks, profile rejection, firewall policy validation,
process refusal and real bounded child-process I/O/private export operations.
System VPN/firewall commands are mocked. See [VALIDATION.md](VALIDATION.md) for
what has and has not been verified. Real Kali networking remains unverified.

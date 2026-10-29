# Install the owned Kali client

This is our standalone desktop app for the staged VPN lab. It uses the local
OpenVPN engine directly. No NetworkManager VPN plugin, hosted client account,
analytics service or third-party VPN frontend is required. OS Wi-Fi remains an
OS responsibility. See OWNED_CLIENT.md in the repository root for trust limits.

The current build is for controlled Kali testing. Physical DNS/IPv6/kill-switch
behavior and boot/resume protection are not established by server tests. In
particular, the runtime firewall is not yet installed as an early-boot policy.

## Install a reviewed source version

Keep a trusted source/release copy and its independently recorded hash. Open a
terminal as your ordinary user in its `vpn-dashboard` directory:

```sh
find . -type f -links 1 -exec chmod go-w -- {} +
bash install.sh --check
bash install.sh
```

Run the first command only in this reviewed, extracted source directory. Some
ZIP extractors create group-writable files when no Unix modes are supplied;
the installer refuses those files. This removes group/other write permission
from the source files without changing their contents. It does not modify an
installed helper or weaken its ownership/link/permission checks.

The check reads source metadata/syntax and dependencies without making changes.
Normal installation repeats the source checks before requesting sudo and again
inside the root process. The installer requests sudo and optionally offers signed
distribution packages if prerequisites are missing. Runtime tools include Python
3.10+/Tk, OpenVPN 2.5+, nftables, iproute2, procps, sudo and a terminal. Linux process-
descriptor signaling is required. NetworkManager/systemd diagnostic commands are
optional; missing ones do not prevent the standalone engine from working.

Import your privately downloaded self-contained profile; the default path is
`$HOME/vpn-lab/client.ovpn`. The wizard validates a bounded profile format and
copies it into root-owned `/etc/vpn-desk/client.ovpn` with mode 0600. It is never
symlinked to a home profile. Keys, tokens and passwords are not printed.

The installer automatically uses that default profile if present. It validates
the profile before using its literal endpoint, port, protocol and exact pinned
TLS certificate name (the lab uses `VPNLabServer`). These known fields are not
questions. The profile must already come from a trusted, verified source;
reading its certificate-name pin does not independently authenticate its origin.

Local, read-only diagnostics find the physical Wi-Fi interface on the kernel's
route to that endpoint, then read its current DHCP server identifier using
NetworkManager's `nmcli`, if available. No plugin or NetworkManager installation
is needed. There is no external discovery service or connectivity request.
Gateway/DNS addresses are never substituted for a missing DHCP identifier.
Missing, ambiguous, unavailable or timed-out detection asks only for the unknown
local field. It does not reuse the last Wi-Fi address from chat or the repository.

With successful detection, setup shows the validated public settings and asks
for one final installation confirmation (in addition to sudo and any optional
package installation). No keys or passwords are shown. For another profile path
or explicit local network review, use `bash install.sh --manual`. Endpoint and
TLS values still come from the validated profile. Existing protected settings
are preserved on rerun. Changes of Wi-Fi/DHCP require policy review; discovery
does not silently replace an existing policy.

The installer creates a dedicated nonlogin `vpn-desk` identity, protected helper
and app files, a menu entry and a public-code hash manifest. It snapshots reviewed
helper sources before privileged imports, creates no passwordless sudo rule and
refuses differing existing files. A previous install needs a reviewed upgrade;
the first-install flow does not overwrite unknown modifications.

Installation itself changes no routes, DNS or firewall. Open **VPN Desk** from
the applications menu, or run `vpn-desk` as your ordinary user.

## IPv4-only transport update

The transport helper now forces IPv4 UDP/TCP, ignores pushed IPv6 addresses and
routes, and replaces any combined server redirect with a fixed IPv4 `def1`
redirect. It keeps certificate verification, password handling and the owned
guard unchanged. This allows the existing server configuration to coexist with
an IPv4-only client. It does not itself disable IPv6 across the operating system.

For the installed earlier helper, the explicit
`ops/upgrade_client_transport.py` accepts a public update directory containing
the five reviewed Python sources and `client-update.json`, plus the independently
verified SHA256 of that manifest. Verify the updater itself separately as well.
Run using system Python with `sudo /usr/bin/python3 -I -B`.
The reviewed updater requires no active OpenVPN or held action lock, checks the
protected public-code baseline, refuses unknown changes/shadow modules, replaces
only the six known transport/logging/IPv6-check module copies and updates their manifest entries. It preserves
private profiles, passwords, policies, firewall, DNS and recovery state. A known
interruption between the module and manifest writes can finish on rerun; unknown
differences remain a refusal. This is a narrow transport update, not a general
application upgrade or a way to overwrite an installation-integrity warning.
Close VPN Desk before the update and reopen it afterwards so the UI loads the
matching protocol/schema. `SESSION_LOGGING.md` describes the richer diagnostics.

System-wide IPv6 disablement is a separate, explicit Kali step after the
compatible helper is installed. Keep normal networking recovery available and
verify the actual host after applying it; the container tests do not establish
Kali's boot or NetworkManager behavior. `IPV4_ONLY.md` in the repository root
and the tracked `deployments/kali/` files describe persistent GRUB/sysctl setup.

## Connect and stop

**Connect** opens an authentication terminal. The fixed installed helper:

1. Validates protected code, policy/profile and the dedicated service identity.
2. Refuses another OpenVPN process or unmanaged tunnel and verifies the expected
   physical network before changes.
3. Saves the previous regular root-owned `/etc/resolv.conf` and its own policy
   in private recovery state. Symlink-based resolver managers are refused in
   this version rather than overwritten.
4. Applies the app-owned default-drop firewall only over an empty ruleset. A
   verified prior app state can resume; an unrelated firewall is preserved and
   setup refuses automatic migration. No global firewall flush is used.
5. Directs DNS to the private VPS resolver, `172.27.240.1`, then verifies the
   guard. The original LAN resolver is blocked on the physical interface.
6. Starts OpenVPN against the protected profile, with scripts/compression
   disabled, explicit authentication, no password caching and privilege dropping.
7. Monitors firewall/resolver ownership and publishes fixed local session events.
   A DHCP resolver rewrite is repaired while direct Wi-Fi DNS is blocked.

Enter credentials in that terminal, using your privately downloaded login file
locally. Never paste that file or a profile/token into chat or logs. The root
helper remains the supervisor; closing the GUI is not intentional disconnect.

**Disconnect** authenticates through the fixed helper and signals only its owned
child through a Linux process descriptor. It accepts no caller PID or arbitrary
command. Ctrl+C in the original terminal also stops that session.

The guard stays enabled after disconnect, failure or normal app closure. To
return to direct Wi-Fi Internet, stop the VPN and choose **Restore normal
networking**. It verifies saved ownership, restores the previous resolver and
deletes only the owned table. Unknown ownership refuses automatic changes.

Equivalent protected recovery actions, when the GUI cannot be used:

```sh
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py disconnect
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore
```

Do not use broad `pkill`, disable a foreign firewall, run root Python from a
writable checkout as a connection fallback, or launch root OpenVPN on a home
profile. Root can override controls; a compromised OS is outside local attestation.

## Logs and audit

**Session log / audit** shows bounded events from the authenticated local helper:
TLS verification/initialization, reconnect/rekey, authentication failure and stop.
Unknown transport lines are discarded. Raw pushed options, tokens, private keys,
usernames, endpoints and packet payloads are excluded from this log. The desktop
owner/root can read status; only root can stop. There is no network-facing client
control server.

Exports are local 0600 files and are not uploaded. Installation audit compares
public installed code to the protected manifest and flags missing/changed/extra
files. It does not certify the OS, private profile or baseline itself; use a
separately trusted source copy for later review. A root attacker could replace
both a local baseline and local logs.

The ordinary Connections window observes socket metadata, not packet payloads
or every short-lived connection. Tunnel presence or a green desktop notification
is not proof of leak safety.

## Before daily use

Validate routing, private DNS, physical-interface DNS/IPv6 blocking, failures,
token renewal, owner contention, Ctrl+C, app/terminal closure, suspend/resume and
reboot. Server-only checks cannot establish device properties. Native iPhone/
Android apps are a separate build phase.

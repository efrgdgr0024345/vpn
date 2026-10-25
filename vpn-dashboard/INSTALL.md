# Installation and migration on the target Linux desktop

This installer is for the desktop client, not the OpenVPN Access Server VPS.
It does not administer or reset the server's VPN account. The local compatibility
fix now accepts certificate names with internal spaces. Quote such a name in the
profile, for example `verify-x509-name "OpenVPN Server" name`, and set the matching
`server_name` in the protected JSON policy. Exact identity matching remains
required. Earlier hardened/installer ZIPs predate this fix; use the compatibility
fix bundle for this source version. See the root PROJECT_STATUS.md for status.

These steps are for an administrator on the actual host, after reviewing the
source. The cloud review workspace has not been configured as a VPN client.
This is a breaking security migration: old home profiles and the previous
firewall baseline are deliberately refused. The guided installer reuses identical protected files and refuses differing
existing files. It does not perform upgrades or migrate a live firewall.

## Recommended: run the guided installer

Extract the ZIP, open a terminal in its `vpn-dashboard` folder, and run:

```sh
bash install.sh
```

For a read-only dependency check first:

```sh
bash install.sh --check
```

The launcher uses the system Python in isolated mode and requests sudo through a
visible terminal. It then:

1. Checks the required programs and offers to install missing Debian/Kali packages
   using apt. This is optional and defaults to no; normal package-signature checks
   stay enabled. Distribution package scripts can start/restart system services.
2. Asks for the absolute path of your local, self-contained `.ovpn` profile and
   host-specific policy values. It suggests endpoint/identity values from the
   profile but still validates them. Profile contents and keys are never printed.
   Unsupported profiles are refused, not silently rewritten; the format is below.
3. Creates/validates the dedicated nonlogin account, installs root-owned helper
   and application files, and copies the validated configuration with mode 0600.
   Privileged imports use a private root-owned snapshot of the bundle.
4. Installs the `vpn-desk` command and a VPN Desk applications-menu entry. The app
   runs as your normal desktop user; no passwordless sudo rule is created.
5. Writes a private firewall candidate to
   `/etc/vpn-desk/vpn-guard.candidate.json` for separate review. It does not apply
   firewall/DNS changes, enable VPN autostart or change firewall boot persistence.

Use an ordinary desktop terminal to launch `vpn-desk` after installation, or use
the applications menu. A same-version rerun can resume missing files and reuse
valid protected configuration. Differing existing app/helper/configuration files
are preserved and require a separately reviewed upgrade. An interrupted package
installation or account creation may need normal system-administration recovery.

**Application installation does not mean Connect is ready.** It still requires
that your live firewall match the new baseline and that trusted DNS be configured.
The installer supplies the candidate instead of risking an automatic network
cutoff. Follow the firewall section below before testing Connect. Live VPN/leak
protection remains unverified by the installer.

## Manual provisioning (alternative to the guided installer)

The remaining steps explain the supported format and manual administration.
The guided installer already handles helper/app installation, account creation
and protected profile/policy files; do not repeat those provisioning steps after
using it. `install_helpers.py` is the lower-level helper-only first-install tool.

## 1. Install the reviewed helper

Use trusted distribution packages for Python 3.10+, OpenVPN 2.5+, sudo, Tkinter,
NetworkManager, iproute2 and nftables. Keep them patched. The privileged interpreter
is `/usr/bin/python3`; a virtual environment is not used for root code.

Review `install_helpers.py` and all files it installs, then run from this folder:

```sh
sudo /usr/bin/python3 -I -B install_helpers.py
```

This explicitly privileged installation copies only five helper modules into
`/usr/local/libexec/vpn-desk`. It checks parent ownership/permissions, refuses
symlinks and any existing installation, and installs the entry point last.
It changes no accounts, sudoers, profiles, firewall, DNS or boot configuration.
An existing installation requires a separately reviewed upgrade while sessions
are stopped; this first-install tool refuses to merge or overwrite it.
Never grant passwordless sudo for a writable checkout or a Python interpreter.

## 2. Provision the dedicated account and local configuration

Check whether the account already exists. On a new Debian/Kali host, a typical
administrator command to create it is:

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin vpn-desk
```

It must have a nonzero UID/GID, disabled login, a dedicated primary group and no
supplementary groups. Do not reuse an ordinary desktop or shared service account.

Prepare an administrator-owned `/etc/vpn-desk` directory, normally mode 0700.
Provision these regular, non-symlink files without overwriting existing data:

| File | Owner/mode | Contents |
| --- | --- | --- |
| `/etc/vpn-desk/policy.json` | root:root, 0600 | Actual host values following `policy.example.json` |
| `/etc/vpn-desk/client.ovpn` | root:root, 0600 | Reviewed self-contained profile described below |

Use a trusted administrator editor or configuration manager. Never place keys
in Git, shell arguments or chat. Do not symlink either file to a home directory.
All ancestor directories must be root-owned and not writable by group/others;
files with additional hard links are refused. Configuration can be provisioned
locally before enabling the dashboard; it need not be added to this public repo.

The required policy keys are `wifi_interface`, literal `vpn_server_ipv4`,
`vpn_port` (integer), `vpn_protocol` (`udp` or `tcp-client`), literal
`dhcp_server_ipv4`, and exact expected certificate `server_name`. Replace the
example addresses and name with values verified through your trusted provider
and local network administration. DHCP changes on a different Wi-Fi require
an administrator-reviewed policy/firewall update.

The supported profile requires these directives, matching the local policy:

```text
client
dev tun0
proto udp
remote 192.0.2.10 1194
remote-cert-tls server
verify-x509-name vpn.example.invalid name
tls-version-min 1.3
data-ciphers AES-256-GCM:AES-128-GCM
```

The displayed endpoint/name are examples, not a usable service. Inline `<ca>`, `<cert>`, `<key>` and exactly one
of `<tls-crypt>` or `<tls-auth>` are required, containing your actual trusted
material. For tls-auth, `key-direction 1` is also required. Do not add external
asset paths. No example private key is supplied.

Optional supported options are: no-argument `nobind`, `persist-key`, `persist-tun`,
`auth-user-pass`, `auth-nocache`; `resolv-retry infinite`; `mssfix 1300`; `verb 0`
through `verb 4`; and `auth SHA256`, `SHA384` or `SHA512`. TLS minimum can be 1.2 or
1.3. Supported data-ciphers are AES-256-GCM alone, AES-128-GCM alone, both in that
order, or AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305. Duplicate directives and all
other directives are refused, including scripts/plugins, nested profiles,
external credential/key files, logs/writepid/management/daemon and compression.
The helper independently enforces terminal authentication, no auth caching,
script-security 1 (built-in commands only), compression disabled, mssfix 1300 and
privilege dropping. Confirm that your server supports this constrained profile;
do not weaken validation merely to get an unsupported profile to run.

## 3. Review and validate the firewall migration

The guided installer and helper never apply a firewall or flush a ruleset. An administrator must
prepare the baseline for the actual host before Connect succeeds. Render a
candidate batch using a local copy of the non-secret policy and the real dedicated
account UID (the guided installer already saves its candidate privately):

```sh
python3 firewall_policy.py --policy policy.local.json --uid "$(id -u vpn-desk)" > vpn-guard.local.json
```

The example UID in tests is not your installed UID. This command only generates
JSON; it does not apply it. The generated batch adds a new table and is not an
idempotent migration of an existing `vpn_guard`. Review its routing, input,
IPv4/IPv6, DHCP and resolver implications on an isolated test machine first.
Check the generated rules with your installed nftables version before applying
any separately reviewed migration. Unsupported JSON normalization can cause a
safe refusal and needs investigation, not a bypass of validation.

Input/output/forward drop defaults are mandatory. Allowed inbound traffic is
loopback, established/related replies and IPv4 DHCP replies from the configured
server. Outbound exceptions are loopback/tun0, the pinned VPN endpoint for root
and the VPN UID, and root-owned IPv4 DHCP to the broadcast or configured server.
No portal-opening rule is generated. Arbitrary local applications cannot use
the direct endpoint exception. External root users can still change the policy.

This baseline intentionally supplies no inbound LAN service or native IPv6
allowances. Your machine may require a separately reviewed extension, including
IPv6 control traffic for native IPv6 support. Do not apply a drop policy over a
remote session without an independent recovery path. Never persist an active
portal element in boot rules. Boot persistence and resume behavior need their
own controlled test; this installer does not configure them.

Configure trusted DNS separately. OpenVPN does not automatically integrate with
Linux resolvers here, and profile DNS-update scripts are forbidden. DNS to an
unapproved direct Wi-Fi resolver will be blocked outside the VPN. Confirm actual
resolution and DNS/IPv6 leak behavior before relying on the configuration.

## 4. Start and verify

Run `python3 app.py` as your ordinary desktop user. Connect opens a terminal and
requests explicit sudo authorization for the fixed installed entry point:

```sh
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py connect
```

Additional actions are `portal-status` and `portal-close`. There is no open action.
The helper requires no unmanaged tunnel/OpenVPN process, checks the strict guard,
closes a recognized set, verifies closure and holds the shared action lock until
OpenVPN exits. Enter credentials only in that terminal and stop with Ctrl+C.

Validate real server identity, routes, resolver behavior, IPv4/IPv6 leak blocking,
connection loss/reconnect, Ctrl+C, terminal closure, and boot/resume in a controlled
session. Interface presence and a successful terminal launch are insufficient.
Do not run concurrent external VPN/firewall managers. This application cannot
prevent another root tool from changing networking after a check.

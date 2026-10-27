# Security hardening implemented

## Owned-client follow-up review, 27 October 2026

The reviewed runtime source is `b9917442c0d342d7bab2eb01e4d80e6e81ba7e01`.
[GitHub CodeQL security-and-quality](https://github.com/efrgdgr0024345/vpn/actions/runs/40447460637)
completed with zero findings after the reported file-mode, unused-import,
resource-lifetime and expected-exception findings were fixed without query
suppression. [Functional validation](https://github.com/efrgdgr0024345/vpn/actions/runs/40447460753)
passed all four jobs, including 171 unit tests per Ubuntu job, real kernel/UI,
SSH/SFTP and VPN/PAM/DNS/session tests. This is automated review evidence, not
proof of security or validation of the whole upstream engine/OS.

The owned app adds authenticated local session control, bounded secret-free
events, owned-child process-descriptor signaling, runtime guard/resolver setup,
explicit restoration and a public-code installation audit. The server adds a
private recursive resolver. Architecture, limitations and exact deployment
records are in OWNED_CLIENT.md and deployments/vpn-lab.json.

The client guard is not installed as an early-boot policy. Physical Kali
installation, DNS/IPv6 containment and transition behavior remain acceptance
work. Native phone apps are not implemented. Root compromise can replace local
code, policy, manifests and logs; independent source/hash retention is required.
The profile import does not delete the owner's original home-directory key copy.
After verifying the protected import, remove unnecessary plaintext export copies
or move backups to separately protected offline storage; mode 0600 does not stop
malware running as that same user. No automatic personal-file deletion occurs.

Both exact-commit functional and CodeQL checks gate lab mutations. Weekly
Dependabot update proposals track GitHub Actions; PR dependency review checks
recognized dependency changes. These do not audit Debian packages or every
transitive upstream dependency. GitHub returned 403 for owner-only security
setting changes: repository-wide Dependabot alerts, secret scanning and push
protection must be enabled/verified by the owner separately.

## Earlier client hardening

This describes client-side code, not changes to the live Access Server VPS.
The follow-up audit in [PROJECT_STATUS.md](PROJECT_STATUS.md) records the certificate-name
compatibility findings, their fixes, and publication of the isolated test branch.

The uploaded application has now been changed. The initial review findings are
addressed as follows; deployment on the actual Linux host is still required.

| Area | Enforced behavior |
| --- | --- |
| Mutable privileged code | Launchers call only the fixed installed helper with `/usr/bin/python3 -I -B`; root-owned files/ancestors are checked before project imports. No checkout fallback. |
| Mutable user profile | Only `/etc/vpn-desk/client.ovpn`, root-owned and owner-only, is read. Links, writable ancestors and additional hard links are rejected. No user-supplied profile path. |
| Profile execution/authentication | Supported directives are allowlisted. Endpoint and TLS server identity must match protected local policy. TLS >=1.2 and AEAD are required. Scripts/plugins, external files, management, daemon and compression are refused. OpenVPN drops to a dedicated nonlogin user/group. |
| All-app portal bypass | Opening is disabled at UI, launcher and helper API levels. No rule/element creation path remains. Recognized close/status controls remain. |
| Inbound filtering | Strict validation requires input/output/forward drop chains and reviewed input exceptions. The previous no-input-chain baseline is refused. |
| Endpoint/DHCP exceptions | VPN endpoint exceptions are limited to root and the dedicated UID. DHCP is explicitly IPv4, root-owned outbound, and limited to broadcast/configured server. |
| Public operational details | Real endpoint and historical network addresses were removed; only documentation addresses are supplied. Actual settings belong in protected local configuration. |
| Export permissions | Both export paths atomically create 0600 files, including replacement of permissive files and symlinks. |
| Diagnostics | Fixed absolute binaries, controlled environments, byte limits and timeouts replace unbounded command capture. |

Implementation: [security.py](vpn-dashboard/security.py),
[privileged.py](vpn-dashboard/privileged.py),
[vpn_session_helper.py](vpn-dashboard/vpn_session_helper.py),
[portal_helper.py](vpn-dashboard/portal_helper.py), and
[safe_io.py](vpn-dashboard/safe_io.py).

## Deployment and compatibility

[INSTALL.md](vpn-dashboard/INSTALL.md) explains first installation, account and
profile requirements, candidate firewall rendering and required host validation.
The guided `install.sh` installer creates/validates the dedicated account,
imports a validated local profile into protected configuration, installs the app
and helper, and adds a menu launcher. It offers normal apt prerequisite
installation with a separate local prompt. It does not apply firewall changes,
change sudoers or enable VPN autostart. A candidate firewall is saved privately.
Identical files can be reused on a rerun; differing existing files are preserved. No real VPN credentials/profile were supplied, and nothing
has been deployed to a user's Kali machine by this coding task. Connect refuses
missing or incompatible installations rather than falling back to older behavior.

The restricted profile subset can reject previously working provider profiles.
DNS integration must be administered separately; DNS-update scripts are not
accepted. Native IPv6/LAN services require separate policy review. The renderer
produces a candidate batch for a new table, not an automatic migration.

## Remaining trust boundaries and unverified behavior

- The action lock coordinates these helpers only. Another root firewall manager
  or VPN tool can still race checks or change networking afterwards. Do not run
  concurrent managers; this is not a sandbox against a compromised root user.
- `tun0` is a fixed, supervised profile device. Renamed/external tunnels are
  rejected where detectable before startup, but an external privileged actor
  remains able to create or change interfaces and rules.
- Root privilege is retained during OpenVPN initialization before the configured
  user/group drop. Keep OpenVPN and distribution tools patched.
- Live nftables JSON normalization, packet-level inbound/egress/DNS/IPv6 behavior,
  TLS connection, key handling, reconnect, GUI/terminal integration, crash,
  suspend/resume and boot behavior have not been verified on a real Kali host.
- A recognized old portal set can be cleared only when the rest of the hardened
  baseline matches. Unknown legacy rulesets need administrator-controlled
  migration; this code does not guess at safe firewall repairs.
- Clipboard managers may retain copies. Ignore patterns and removal of known
  operational details are not a universal secret scanner or history scrubber.

Tests include adversarial profile/trust checks, an independently authored JSON
policy fixture, mocked host commands, and real harmless child-process and file
permission checks. See [VALIDATION.md](vpn-dashboard/VALIDATION.md) for results.

The CI preparation also exercised real nftables installation/readback in isolated
network namespaces with Ubuntu 22.04/24.04 userspace. It found and fixed rejection
of equivalent kernel readback: explicit IPv4-family matches can be omitted beside
positive IPv4 address matches, and conntrack state membership uses equality.
Normalization is limited to those forms; endpoint/address/UID restrictions and
rejection of unexpected bypasses remain covered. These checks and real Tk startup
do not replace target-host traffic, installation or VPN connection testing.

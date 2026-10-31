# Security hardening implemented

## Setup and access-logic review, 31 October 2026

This was a focused source review of the Kali IPv6 setup/bootstrap, the broker
admission/lease logic, credential provisioning and the client guard lifecycle.
It did not perform a new live penetration test, inspect Kali, verify current SSH
key expiry or verify owner-only GitHub protections. The existing live VPS boot
and external acceptance records remain in `deployments/ipv4-only.json`.

**Corrected: generated boot settings were not checked.** The Kali setup previously
accepted a successful `update-grub` exit and saved drop-ins without reading the
actual generated boot entries. Other GRUB settings could remove or contradict
IPv6 disablement. The setup now validates every recognized generated Linux/LinuxEFI
entry before applying sysctls and exposes `boot_argument_configured` separately.
Missing, conflicting and malformed entries stop setup. Seventeen targeted tests
cover normal, conflicting, partial-install and failure cases. A real Kali reboot
still must establish that the firmware selected this configuration. The old
unconditional file-copy recipe has been removed in favor of the checked setup.

No new confirmed authentication or forwarding bypass was found in the inspected
paths. Admission requires initial PAM authentication plus the enrolled certificate
pin/name, is bound to OpenVPN's client ID, and grants no forwarding while pending.
That result does not establish the absence of vulnerabilities in the OS, OpenVPN
or paths outside this limited review.

Remaining priorities, with broader live lockdown still deferred:

| Priority | Evidence and implication | Next hardening direction |
| --- | --- | --- |
| High: administrative authority | `ops/bootstrap_runner_key.py` uses `restrict` and a 24-hour expiry without a forced command. While valid, the key can execute arbitrary root commands. Normal CI gates do not constrain a compromised maintainer. | Protect GitHub/provider accounts with hardware MFA; replace standing general root deployment authority with independently approved, narrowly authorized maintenance. |
| High: exportable device identity | `ops/server_foundation.py` generates exportable keys and profiles; the diagnostic imports protected copies without deleting the originals. Malware with access to a current profile/login pair can clone it and claim the slot when free. | After acceptance, retire unnecessary copies and issue device-generated keys; use hardware protection where supported. Do not embed shared secrets in a public boot image. |
| High: trusted endpoints and root | The root broker retains NET_ADMIN. Malware on an approved endpoint can use the active session; root can replace code, logs and local manifests. | Harden and patch endpoints, separate privileged responsibilities, and retain independently verified releases. A server-reported hash is not root-resistant attestation. |
| Unfinished containment | `vpn-dashboard/network_setup.py` enables the guard at Connect. IPv6 disablement does not enforce an IPv4 VPN-only policy before Connect or after reboot. | Build and physically test the planned early-boot guard, explicit recovery and roaming/crash behavior. |

The current design renews standard session tokens every 120 seconds; it does not
rotate usernames/passwords or defeat malware through rapid handoff. Static secret
rotation does not remove an attacker already controlling an approved device.

## Owned-client follow-up review, 27 October 2026

The reviewed runtime source is `8510966a90bab33e7f848f6f8c1c534969d576e3`.
[GitHub CodeQL security-and-quality](https://github.com/efrgdgr0024345/vpn/actions/runs/40451196186)
completed with zero findings after the reported file-mode, unused-import,
resource-lifetime and expected-exception findings were fixed without query
suppression. [Functional validation](https://github.com/efrgdgr0024345/vpn/actions/runs/40451196198)
passed all four jobs, including 173 unit tests per Ubuntu job, real kernel/UI,
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
recognized dependency changes once the owner enables Dependency graph. Its first
PR runs explicitly failed because that graph is disabled; it is not yet a working
review result. These do not audit Debian packages or every
transitive upstream dependency. GitHub returned 403 for owner-only security
setting changes: repository-wide Dependabot alerts, secret scanning and push
protection must be enabled/verified by the owner separately.

## Handover follow-up

A repeated integration run exposed a control-message race after the zero-finding
static review. A deliberately delayed real broker reproduces it: an unadmitted
token replay disconnects before its queued kill command is processed. OpenVPN's
`management_kill_by_cid` returns failure for an absent/halted instance. The parser
now tolerates only its exact `ERROR: client-kill command failed` reply outside
an atomic event, with no grant or ownership-state change. Authentication and all
other command errors still stop the broker. This is a reminder that static
analysis does not replace runtime adversarial tests; PROJECT_STATUS.md records
validation/deployment evidence. The corrected source is now deployed and
passed post-reboot live acceptance, including the forced ordering with the
original broker process surviving throughout:
[run 40500906651](https://github.com/efrgdgr0024345/vpn/actions/runs/40500906651).

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

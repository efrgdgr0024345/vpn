# Owned client application and review boundary

The owner selected our own client application, not a NetworkManager VPN plugin
or a third-party VPN frontend. Kali is the first implementation. Native iPhone
and Android applications are a later implementation phase; the earlier stock
OpenVPN Connect proposal is no longer the selected app plan.

## What the Kali app controls

- An ordinary-user Tk desktop starts a small installed root helper through a
  visible authentication terminal. Root never imports a writable checkout or
  runs OpenVPN against a home-directory profile.
- Connect installs the app-owned nftables guard only over an empty firewall,
  then directs resolver traffic to the private VPN DNS server. A pre-existing,
  unrelated firewall causes a safe refusal rather than a global ruleset flush.
- The guard blocks ordinary direct Wi-Fi IPv4/IPv6 traffic, including direct DNS,
  and scopes inbound replies to the tunnel/transport. It allows only the pinned
  transport and necessary DHCP/related ICMP on the physical interface.
- The root helper monitors the guard and resolver file during the session. A
  NetworkManager DHCP rewrite of the regular resolver file is repaired while
  physical DNS remains blocked. An unrecognized guard stops the owned session.
- Disconnect signals only the child identified by a Linux process descriptor.
  The local IPC protocol accepts no executable, command line, profile path or
  caller-supplied PID. Disconnect keeps the guard enabled.
- Restore normal networking is a separate, terminal-authenticated action. It
  refuses an active OpenVPN process, verifies saved ownership, restores the
  previous resolver contents and deletes only the app's identified table.

This initial client guard is a runtime policy. It remains after disconnect or
process failure until explicit restoration, but **boot-time enforcement before
the app starts is not implemented**. Do not assume reboot/suspend/roaming leak
protection or daily-use readiness from the source or server's reboot test.
The first device acceptance must validate these transitions before further
client rollout. The existing server's boot protection is a separate component.

## Logs and visibility

The Session log / audit window receives bounded, typed local events through a
Unix socket in a root-controlled directory. The desktop owner and root can read
it. Only a root helper can request a stop. OS peer credentials are checked at
both ends; there is no TCP/HTTP control listener.

OpenVPN lines become a fixed vocabulary of connection/TLS/rekey/failure events.
Unknown or credential-bearing lines are discarded, not forwarded to the UI.
Passwords remain in the explicit terminal authentication path. Tokens, private
keys, packet payloads, usernames and endpoints are not put into session events.
Exports are private 0600 files and are never automatically uploaded. These are
observations of a local session, not a signed forensic record. Tunnel readiness
does not by itself certify DNS or leak protection.

## Audit and dependencies

The guided installer records hashes of public application/helper code, its
launcher and desktop entry. The audit view checks ownership, file type, changed
or missing code, and unexpected files that could shadow modules. It deliberately
excludes credentials, keys and private policy/profile files.

A root attacker could replace both code and that local baseline, or alter the
OS underneath it. An independent trusted source/release copy and its separately
recorded hash are necessary for later comparison. Neither an in-app green check
nor an AI review proves that a running machine has never been compromised.
The project retains reviewable source, Git history, security checks and explicit
test evidence rather than claiming that absence of an alert proves safety.

There are no hosted client accounts, analytics SDKs, crash-upload agents,
remote dashboards, IP-check APIs or telemetry services in the app. The network
engine still uses upstream OpenVPN, Linux networking/nftables, Python/Tk and
established crypto libraries. Wi-Fi remains an OS responsibility. The private
resolver uses upstream Unbound and DNS root trust data; public DNS names still
require communication with root/authoritative DNS infrastructure. The VPS
provider and GitHub source/CI are also third parties. These dependencies are
explicit and credited; this is not a claim of zero third-party code or hardware.

## Automated review

GitHub runs functional/security regression tests and CodeQL Python
security-and-quality queries on pushes/PRs, with scheduled analysis as well.
Medium/higher CodeQL security severity and error-level findings fail the scan.
Both functional and security workflows must succeed for the exact source commit
before lab mutations get an SSH secret. PR dependency changes get GitHub's
dependency review. This does not scan the entire VPS/phone OS or upstream engine
source as if it were part of this Python repository.

CodeQL results are exposed as controlled rule/location annotations. Raw source
snippets or credential-bearing runtime logs are not copied into custom reports.
Real private profiles, keys and VPS credentials are not supplied to the security
jobs. See THIRD_PARTY_NOTICES.md for upstream acknowledgements.

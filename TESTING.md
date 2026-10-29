# Testing before production

The working Access Server is separate and unchanged. The disposable Debian 13
lab has a deployed single-tunnel authorization broker; exact live evidence is in
`deployments/vpn-lab.json`. The owned Kali app is a separate client component.
Native phone apps and early-boot client enforcement are not implemented.

## GitHub functional checks

`.github/workflows/checks.yml` runs on pushes, pull requests and manual dispatch
using disposable GitHub-hosted runners and a read-only repository token. It needs
no real profiles, passwords, SSH credentials or cloud-provider API token.

The Ubuntu 22.04/24.04 jobs run 168 desktop and 64 lab/admin/security unit tests,
actual Tk dashboard/log-window startup under Xvfb, and real nftables readback in
a fresh network namespace. The kernel check rejects bypass rules and exercises
the owned guard, resolver repair and explicit restoration with temporary resolver
files. It does not change the runner's host resolver or default route.
The same isolated namespace also creates a veth named `tun0` and a resolver in
a separate peer namespace. The actual bound UDP health check must distinguish
a valid answer, SERVFAIL and a three-second timeout under the real app guard,
refuse missing/wrong tunnel routes without sending, and preserve the firewall.
Unit regressions cover malformed DNS packets, CNAME chains, source/interface
binding, one outstanding nonblocking probe and reconnect/stop generation fencing.

Separate digest-pinned Debian 13 containers exercise real OpenSSH/SFTP safeguards,
certificates, PAM, OpenVPN, private DNS and NAT. VPN tests check competing owners,
unapproved pins, token renewal/replay, frozen-broker lease expiry, revocation and
disconnect-before-transfer. A delayed-broker replay forces disconnect-before-kill
ordering and checks that the original broker survives; other management errors
remain fatal. The app supervisor is also exercised with the real
engine and authenticated local IPC. Its network monitor is substituted there;
the separate network-namespace test covers the actual client guard. Its real
OpenVPN client now configures IPv4 on a TUN with IPv6 address generation disabled
and ignores the unchanged server's IPv6 pushes. This verifies protocol handling;
host-wide kernel/sysctl disablement still needs physical acceptance. Synthetic DNS
is confined to that isolated harness; production uses the VPS's recursive resolver.

Only explicit TUN/NET_ADMIN access is granted to the VPN containers. They publish
no host ports and mount no host credentials. Namespace/kernel tests fail if they
cannot run rather than silently skipping validation.

A separate Debian container, without added capabilities or host mounts, runs
the actual interactive installer root phase with a fixture invoking UID. It
reproduces ZIP extraction under umask 0002, checks refusal before installation,
prepares the public sources as their ordinary owner, and verifies the real
protected helper/profile installation and same-version rerun. It also checks
that source preflight installs nothing and that installation leaves the resolver
and routes unchanged. Test profile data is inert; no VPN connection is made by
this installer job. Nonroot elevation arguments are checked separately in units.
The installer fixture also verifies that known profile fields are not prompted
again and declining final confirmation leaves application files absent.
Detection regressions cover one-summary setup, both nmcli output formats,
missing/ambiguous routes and leases, bounded command failures, manual review,
invalid inputs before command execution, and summary redaction. The container
has no physical Wi-Fi or NetworkManager, so its two local network fields use
the explicit fallback; actual Kali detection still needs physical acceptance.
The installer job also verifies the hash-pinned original `04639eb` source ZIP,
performs its real installation with the updated wizard, and exercises the narrow
transport upgrade twice. Installed code must match the updated audit baseline;
private configuration and networking must remain unchanged. Upgrade units cover
unknown modifications, shadow modules, source links/permissions, process/lock
refusals, bad candidate hashes, private-path rejection and known interrupted-pair
recovery. Root-only password recovery units verify deny-before-change ordering,
private-copy synchronization, secret-free reporting and fail-closed write errors.
The real VPN container also replaces the PAM password and private copies,
restarts OpenVPN/broker, rejects the previous password over TLS and connects
with the replacement. Only systemd's stop/start commands are substituted with
the container-owned processes; PAM, chpasswd, nft and credential writes are real.
Connection diagnostics tests cover strict endpoint/version/cipher extraction,
owned socket inodes, stage timing and bounded startup/reconnect budgets. A real
OpenVPN client aimed at a closed loopback port must time out, stop only its owned
child, and retain typed endpoint/stage details. Real filesystem tests require
root-owned history with a named-user read ACL: the owner can read but cannot
overwrite it, and another ordinary UID cannot read it. Viewer tests distinguish
live and saved reports, and reject corrupt metadata/control characters. Kernel
IPv6 disablement can excuse only an unavailable IPv6 route query; enabled IPv6
and all IPv4 checks remain strict.

## GitHub security review

`.github/workflows/security.yml` runs CodeQL Python security-and-quality analysis
on pushes, PRs, manual dispatch and weekly. Medium/higher security-severity and
error-level findings fail the scan. Controlled rule/location summaries expose
findings without copying raw runtime data. PR dependency changes get GitHub's
dependency review once the owner enables GitHub's Dependency graph. Its first
PR runs are blocked by that setting; the workflow does not skip the failure.
Weekly Dependabot proposals track pinned GitHub Actions and are working.
These jobs have no lab environment or private SSH/profile data.

Both functional and security workflows must succeed for the exact source commit
before gated lab mutations receive the environment SSH secret. Scans are useful
review evidence, not proof that the code, dependencies or deployed OS are secure.
The integration cannot enable repository-wide Dependabot alerts, secret scanning
or push protection; those owner settings are separate and must be verified in
GitHub Settings. Do not assume they are enabled from a green CodeQL result.

## Live lab and physical client

Manual main-branch Actions administer only the disposable lab over verified SSH,
with the independently checked host fingerprint and dedicated expiring key. See
`GITHUB_LAB.md` and `SERVER_SETUP.md`. A live packet self-test uses protected local
credentials without exporting them or changing the server's host routes/resolver.
Reboot, inventory and external UDP checks provide separate runtime evidence.

A server/container pass cannot establish Kali's actual Wi-Fi, OpenVPN 2.7,
resolver, IPv6, sleep/resume or boot behavior. `DEVICE_TESTING.md` covers the first
controlled test of the owned app. Keep recovery instructions available offline
before enabling a drop policy. Capture packet evidence outside the client before
claiming leak prevention; tunnel presence alone is insufficient.

Keep private profiles, keys, tokens and login files out of this public repository,
chat, CI logs and artifacts. Source-only review bundles are reproducible from an
exact Git commit, with a file manifest and independently recordable archive hash.

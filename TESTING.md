# Testing before production

The working Access Server is separate and unchanged. The disposable Debian 13
lab has a deployed single-tunnel authorization broker; exact live evidence is in
`deployments/vpn-lab.json`. The owned Kali app is a separate client component.
Native phone apps and early-boot client enforcement are not implemented.

## GitHub functional checks

`.github/workflows/checks.yml` runs on pushes, pull requests and manual dispatch
using disposable GitHub-hosted runners and a read-only repository token. It needs
no real profiles, passwords, SSH credentials or cloud-provider API token.

The Ubuntu 22.04/24.04 jobs run 121 desktop and 50 lab/admin/security unit tests,
actual Tk dashboard/log-window startup under Xvfb, and real nftables readback in
a fresh network namespace. The kernel check rejects bypass rules and exercises
the owned guard, resolver repair and explicit restoration with temporary resolver
files. It does not change the runner's host resolver or default route.

Separate digest-pinned Debian 13 containers exercise real OpenSSH/SFTP safeguards,
certificates, PAM, OpenVPN, private DNS and NAT. VPN tests check competing owners,
unapproved pins, token renewal/replay, frozen-broker lease expiry, revocation and
disconnect-before-transfer. The app supervisor is also exercised with the real
engine and authenticated local IPC. Its network monitor is substituted there;
the separate network-namespace test covers the actual client guard. Synthetic DNS
is confined to that isolated harness; production uses the VPS's recursive resolver.

Only explicit TUN/NET_ADMIN access is granted to the VPN containers. They publish
no host ports and mount no host credentials. Namespace/kernel tests fail if they
cannot run rather than silently skipping validation.

## GitHub security review

`.github/workflows/security.yml` runs CodeQL Python security-and-quality analysis
on pushes, PRs, manual dispatch and weekly. Medium/higher security-severity and
error-level findings fail the scan. Controlled rule/location summaries expose
findings without copying raw runtime data. PR dependency changes get GitHub's
dependency review, and weekly Dependabot proposals track pinned GitHub Actions.
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

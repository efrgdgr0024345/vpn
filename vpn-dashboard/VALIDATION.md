# Validation of the hardening changes

Compatibility follow-up: the earlier 102-test suite missed rejection of the
legitimate certificate name `OpenVPN Server`. The validator now permits internal
spaces and three regression tests cover quoted-name acceptance, exact matching,
quoting, controls, boundary whitespace and length limits. The current suite has
105 tests after that fix. The later isolated nftables test found another
compatibility issue: real nft readback omits redundant IPv4-family tests when
matching IPv4 addresses, and writes state-set membership as equality. These
equivalent forms are now normalized with four regression tests; the current
suite has **109 passing tests**. This is client work, not a server password reset
or live deployment. See PROJECT_STATUS.md in the project root.

## Executed in this cloud workspace

- `python3 -m unittest discover -s tests -q`: **109 tests passed**.
- All 20 Python source files parsed successfully with Python 3.12.14.
- Profile tests reject home-profile arguments, mutable/symlinked paths, weak/missing
  TLS identity and cipher policy, script/plugin/management/daemon/external-file
  directives, duplicate directives, and ambiguous control/inline-asset boundaries.
- Trust tests exercise root ownership, writable ancestors, permissions, symlinks,
  isolated-interpreter enforcement, no checkout fallback, dedicated account/group
  requirements, and rejection before project imports. Root metadata is simulated.
- Installer tests perform real writes only in disposable temporary directories,
  with simulated root metadata. They verify exact installed bytes, safe modes,
  refusal to overwrite and cleanup after partial failure. No system install ran.
- Firewall tests use an independently authored JSON fixture. Missing input
  filtering, endpoint UID restrictions, IPv4 DHCP/destination restrictions, extra
  bypasses and tampered portal objects are refused. Anonymous set ordering is
  normalized without relaxing policy meaning. Opening is refused before commands.
- Session tests verify protected configuration and closed-portal checks before
  startup, fixed privilege-drop arguments and unmanaged-network refusal.
- I/O tests run harmless real Python child processes to check input/output,
  exit-status preservation, byte-limit termination and timeout termination.
- Export tests check real 0600 permissions under permissive umask, replacement of
  existing permissive files, symlink-target preservation and atomic failure cleanup.
- Firewall renderer CLI output matches the independent example fixture. It only
  generated a temporary JSON artifact; no rules were applied.
- Actual checkout-helper invocation with isolated Python refused before project
  imports. Actual nonroot installer invocation refused. GUI startup returned the
  expected graphical-desktop-unavailable result in this headless environment.

## Guided installer validation

- `install.sh` passes POSIX shell syntax validation and runs from another working
  directory. `--check` reported the missing host packages with exit code 2 and
  made no changes. Missing packages were not installed in this workspace.
- Tests cover literal sudo argv, noninteractive refusal, explicit apt opt-in with
  verification retained, old/unknown OpenVPN version refusal, protected local
  profile import and reuse, conflict detection, atomic no-overwrite publication,
  interrupted-write cleanup, launcher/menu generation and candidate-only firewall
  handling. A complete simulated-root install into temporary directories runs
  twice without overwriting differing files or invoking real system commands.
- New installer behavior and limits are documented in INSTALL.md. The installed
  app launcher passes shell syntax validation; no actual menu integration or
  target-host privileged installation is claimed.

## Not executed / remaining limitations

- No actual privileged helper deployment, system account creation or protected
  profile provisioning was performed. No real profile or key material was supplied.
- No OpenVPN connection, packet-level ingress/egress/DNS/IPv6 leak test, server
  identity validation or reconnect test. A disposable Ubuntu container now covers
  real nftables JSON installation/readback and rejection of an added output
  bypass, in a separate network namespace. This is not a capture from a live Kali
  host; release-specific normalization beyond the covered shapes can still
  safely refuse and requires investigation.
- No desktop rendering, click/clipboard/terminal integration, crash, suspend,
  resume or boot behavior test on Kali. The new disposable-container Xvfb check
  covers rendering, the event loop and clean closure only, with state collection
  substituted and no Connect action invoked.
- No protection is claimed against external root tools changing network state.

See INSTALL.md for target-host migration and validation. Passing unit tests does
not establish a working VPN deployment or certify leak protection.

## CI preparation follow-up

The workflow in `.github/workflows/checks.yml` repeats the regression tests,
source syntax checks, Xvfb smoke test and isolated nftables check on Ubuntu 22.04
and 24.04. All 109 tests, the dashboard smoke check and actual nftables readback
passed in local disposable Ubuntu 22.04 and 24.04 containers. Those containers
use the execution host's kernel, not separate Ubuntu kernels. Policy/account lookups in
the nft smoke check use fixture metadata; nft execution and readback are real.
GitHub results were subsequently verified through the Actions API: both Ubuntu
jobs in [run 40162859451](https://github.com/efrgdgr0024345/vpn/actions/runs/40162859451)
passed the source checks, unit/security suite, Tk smoke test and real nftables
namespace check for commit `b76990ce3855906d4f7bd87f28d72fefe935d4dc`.
No production credentials are used by CI. Debian 13 server installation and real
VPN connectivity remain untested.

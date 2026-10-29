# Project history and current status

## Kali DNS troubleshooting follow-up

The owner reports that browsers stop working during VPN connection attempts.
The precise client-side fault remains unconfirmed: a configured resolver and an
OpenVPN initialized message do not establish working DNS. A read-only lab
inventory (`40811328788`) confirms OpenVPN, broker and Unbound running with DNS
and VPN ports listening; it does not establish physical Kali reachability.

The client now checks private DNS asynchronously after tunnel initialization,
bound to the verified `tun0` source/interface, with a bounded socket deadline,
typed failure reasons and reconnect/stop fencing. It preserves the guard and
does not try LAN or public fallback resolvers. The narrow updater accepts both
the original installed modules and the previously supplied `22aef95` logging
bundle. Local units and a real isolated namespace/guard test passed. GitHub
results and physical installation/connection acceptance remain separate checks.
DNS_TROUBLESHOOTING.md records the next physical checks, explicit recovery and
the still-unresolved stale DHCP/recovery settings when changing Wi-Fi networks.

Current work supersedes the earlier client plan: the owner requested our own
standalone app, local logs and reviewable code, rejected a NetworkManager VPN
plugin, and explicitly requested GitHub security/code review. OWNED_CLIENT.md
describes the Kali implementation and its limits. Native phone apps are a later
phase. GitHub CodeQL security/quality and PR dependency review are configured;
functional and security checks both gate exact-commit lab mutations. The VPS-owned
recursive resolver is installed and live-tested; deployments/vpn-lab.json records
its exact source and the separate server/client acceptance boundaries.

The integration cannot enable repository-wide Dependabot alerts or secret
scanning/push protection: GitHub returned "Resource not accessible by integration"
on both authorized setting changes. The owner has been asked to enable those
settings directly. This does not grant security jobs any SSH/profile credentials.

This reconciles the conversation available in this task, the original uploaded
ZIP, the local project, Git history, the current remote main ref and the preserved
distributed ZIPs. Separate older ChatGPT conversations are not exposed through
the tools/resources attached to this task. No conversation export or additional
history file was found in the shared workspace folders.

Current priority: the owner has resumed staged-access development and requested
GitHub/disposable-server validation before local testing. Add iPhone and Android
support with one main VPN session across the whole account. The owner selected
direct device enrollment, one-tunnel staged access and disconnect-before-transfer.
The broker, kernel lease and separate profiles are implemented, deployed and
verified on the lab, including reboot recovery; see STAGED_ACCESS.md and the
current acceptance evidence below. The existing Access Server remains outside the deployment
scope; custom password suffixes, bootloader work and custom cryptography remain
deferred. Earlier statements that all staged development is paused are historical.

## Three distinct systems

| Component | Evidence and status |
| --- | --- |
| Existing VPS | The user's console identifies OpenVPN Access Server Appliance 3.2.2 and a root shell. This task has no live connection to that console. |
| VPN Desk project | A local Linux desktop client/diagnostic prototype, with privileged client helpers and an installer. It is not an Access Server deployment or administration tool. |
| New VPN lab | Single-tunnel broker, enrolled certificate pins and exclusive kernel lease are implemented in source. STAGED_ACCESS.md describes the selected behavior; deployments/vpn-lab.json distinguishes deployment evidence from source. No hardware attestation or literal two-tunnel handoff is claimed. |

The installer-created `vpn-desk` account is a local client-machine service
account for privilege dropping. It is not the remote VPN login account.
The desktop firewall candidate is not a VPS firewall migration.

## Kali installation acceptance finding

On 29 October the owner identified an unpaid provider invoice behind the lab's
loss of reachability. The first new inventory (`40798935397`) failed before SSH
authentication. Once billing was addressed, host-key verification passed but
the expiring administrator grant was rejected (`40801094956`). The owner renewed
the same key in the independent provider console. Inventory `40801475888` then
confirmed OpenVPN, broker and Unbound running, UDP 1194 listening and both
firewall tables present. External UDP probe `40801569163` and live packet/token
acceptance `40801706013` succeeded. Runtime source remains `8510966`; these
checks did not install another server foundation or modify host routes/resolver.

The owner's repeated dashboard snapshot predated those recovery checks; it did
not establish a new IPv6 fault. The owner nevertheless requested IPv6 disabled
on Kali. The prepared client transport explicitly selects IPv4 and filters
incompatible IPv6 server pushes while retaining a local IPv4 full-tunnel redirect.
A narrow, checked updater preserves the protected private configuration and
updates the public transport baseline. Whole-host IPv6 disablement and physical
Kali acceptance are still pending. The screenshot exposed the initial password;
root-only administrative recovery replaced it privately and invalidated sessions
(`40803611026`, controller source `e352bb4`). Post-reset live acceptance
`40804306078` passed. A replacement Kali login was prepared behind the owner's
existing SSH download key (`40804723683`); retrieval/closure confirmation is still
pending. The first Kali scp attempt reported `Network is unreachable`; its next
route snapshot showed wlan0 up with a default route through a different LAN
(`10.15.192.0/24`). The actual current DHCP identifier must be checked rather
than inferred from that gateway before reviewing the saved local policy.
This is not continuous bootstrap-password
rotation or the still-unimplemented complete rotating-handoff credential lifecycle.

The owner requested fuller connection logs while transport diagnosis continues.
The prepared logging update retains typed network endpoints, interface/route/DNS
observations, cipher/version names, elapsed stage times, refusal categories and
child exit status. Startup/reconnect waits are bounded. Root-written last-attempt
records use an owner-only read ACL and remain explicitly historical after the
live helper exits. Public update manifests cover all matching module copies;
private profiles/credentials are preserved. See SESSION_LOGGING.md. New logging
and persistent IPv6 settings are not yet installed on the physical Kali host.

The owner resumed installation after rebooting Kali. The protected helper was
still absent. Source permission preparation let the exact `04639eb` installer
reach configuration, but typing `y` at its certificate-name prompt caused the
profile/policy identity check to refuse installation before publishing files.
The owner requested removal of repetitive questions and automatic discovery.

The updated installer uses the existing default private profile, derives its
endpoint/protocol/port/TLS identity only after strict validation, and attempts
read-only local Wi-Fi route and DHCP lease discovery. Successful discovery needs
only a public settings summary and final confirmation; unknown local values
alone prompt for input. Missing NetworkManager is a supported fallback, and no
plugin, external lookup or network migration is added. Root imports still use
the verified private source snapshot, including the bounded diagnostic helper.
Existing protected configuration remains immutable. Client physical detection
and first connection acceptance remain pending; the VPS runtime is unchanged.

The owner's extracted `04639eb` release stopped with `Unexpected installation
bundle member` before installing its helper. The same GitHub ZIP was fetched
and its installer/helper/security bytes checked against that exact Git commit.
It supplies no Unix file modes; extraction under umask 0002 creates mode 0664
source files. The strict source guard rejects their group-write permission.
The error reproduced locally and the snapshot passed after removing only
group/other write permission from the public source files.

The exact released installer then passed a full interactive root-stage test in
a disposable Debian container: refusal before source preparation, ordinary-owner
permission preparation, real protected helper/profile installation, same-version
rerun, and unchanged routes/resolver. The owner's existing ZIP can therefore be
used after the documented source-only permission correction; its contents need
not change. No VPS runtime change is needed for this client-side issue.

The updated installer names the unsafe member and reason, checks source files
before sudo as well as again as root, and makes `--check` validate source
metadata/syntax before dependencies. A successful check explicitly says nothing
was installed. Ownership, single-link, no-symlink and write-permission guards
remain in place. Five regressions cover ZIP/umask behavior, preflight refusal,
links, ownership and redacted syntax errors. GitHub now includes a real guided
installation job in addition to the existing kernel/UI/SSH/VPN jobs; see
TESTING.md. Physical Kali installation/connection acceptance remains pending.

## Current verified deployment (27 October 2026)

The handover fix is deployed at runtime source
`8510966a90bab33e7f848f6f8c1c534969d576e3`. Its
[main CI](https://github.com/efrgdgr0024345/vpn/actions/runs/40451196198) passed
all four jobs, including 173 unit tests per Ubuntu job, and
[CodeQL](https://github.com/efrgdgr0024345/vpn/actions/runs/40451196186) reported
zero findings. These are automated checks, not a certification of the client OS.

The owner renewed the existing expiring SSH grant in the provider root console.
[Inventory 40500307468](https://github.com/efrgdgr0024345/vpn/actions/runs/40500307468)
confirmed access restored without replacing the GitHub secret.
[Gated installation 40500400489](https://github.com/efrgdgr0024345/vpn/actions/runs/40500400489)
then installed the reviewed source and confirmed the VPN service active.
After [reboot 40500587276](https://github.com/efrgdgr0024345/vpn/actions/runs/40500587276),
[inventory 40500752793](https://github.com/efrgdgr0024345/vpn/actions/runs/40500752793)
at 23 seconds uptime confirmed VPN, broker and Unbound active, plus both
persistent firewall tables with 18 rules.

[Post-boot live acceptance 40500906651](https://github.com/efrgdgr0024345/vpn/actions/runs/40500906651)
passed authentication, certificate approval, one-session exclusivity, token
renewal/replay, lease expiry, revocation, ownership transfer, private DNS and
packet confinement. The forced disconnected-replay regression confirmed that
the original broker remained alive throughout the test. Credentials stayed on
the server and its host routes/resolver were not modified by the self-test.
[External UDP probe 40501184836](https://github.com/efrgdgr0024345/vpn/actions/runs/40501184836)
confirmed the VPN transport reachable after reboot.

The next useful evidence is controlled installation and connection testing on
the actual Kali machine. Start with the read-only installer prerequisite check
in DEVICE_TESTING.md. The existing downloaded Kali profile/login can be reused;
no download grant needs reopening. Client early-boot enforcement and owned
native phone apps remain unimplemented. Physical DNS/IPv6/kill-switch and
network/suspend behavior remain unverified. GitHub owner security settings and
Dependency graph enablement remain separately pending verification.

## Follow-up handover regression

A repeat of the documentation-only `ed315d6` snapshot failed in
[main CI 40448588470](https://github.com/efrgdgr0024345/vpn/actions/runs/40448588470)
with ownership transfer not completing. Investigation reproduced a broker exit
using the real engine: pause the broker, establish a token-only replay with no
forwarding grant, disconnect that replay, wait for OpenVPN's five-second peer
retirement, and resume the broker. Its queued rejection then receives
`ERROR: client-kill command failed` because that client is already gone. Treating
that reply as a generic fatal error stops the broker and leaves the container's
server held. It is distinct from an authentication rejection.

The source handles only that exact already-gone reply. Other command errors
remain fatal; owner/reservation release still requires a matching disconnect.
A regression verifies this boundary, and the packet test now forces the ordering
and checks that the original broker survives without a service restart. The test
also waits for the previous retired peer before starting another handshake,
so it does not abandon a half-open replay in the global slot. The corrected runtime `71586730bc7af1ff4fe39a07abe7540a2b3f94c0` passed
[branch CI](https://github.com/efrgdgr0024345/vpn/actions/runs/40450023523),
[main CI](https://github.com/efrgdgr0024345/vpn/actions/runs/40450316357) and
[zero-finding main CodeQL](https://github.com/efrgdgr0024345/vpn/actions/runs/40450316409).
The deliberate failure reproduced against the old broker and passed against
the fix locally as well. A follow-up controller change adds a fixed, redacted
SSH authentication diagnosis and another regression test (173 total unit tests).

[Gated deployment 40450316823](https://github.com/efrgdgr0024345/vpn/actions/runs/40450316823)
passed host identity and matching-commit checks, then failed during SSH access.
[Read-only diagnostic 40450643823](https://github.com/efrgdgr0024345/vpn/actions/runs/40450643823)
confirmed authentication rejection. That interruption is now resolved: the
owner renewed the existing grant, the reviewed source installed, and post-boot
live acceptance passed, as recorded in the current section above. The earlier
blocked-deployment evidence is retained as history.

## Previous owned-client and private-DNS acceptance (27 October 2026)

Runtime source `b9917442c0d342d7bab2eb01e4d80e6e81ba7e01` passed all four
[main functional jobs](https://github.com/efrgdgr0024345/vpn/actions/runs/40447778288),
including 171 unit tests per Ubuntu job, real kernel/UI/IPC, SSH/SFTP and VPN
integration. [Main CodeQL analysis](https://github.com/efrgdgr0024345/vpn/actions/runs/40447778310)
reported zero findings after reviewed issues were fixed without suppression.
Weekly GitHub Actions update proposals are working and opened their first PRs.
PR dependency review is configured but its first runs report that Dependency
graph is disabled. The owner must enable it; other owner-only repository security
settings remain separately pending.

[Gated installation](https://github.com/efrgdgr0024345/vpn/actions/runs/40447778025)
deployed that source and preserved the existing credentials/device identities.
[Live acceptance](https://github.com/efrgdgr0024345/vpn/actions/runs/40447890007)
passed authentication, exclusivity, token, revocation, lease expiry and both
private resolver and encrypted/NAT DNS packet checks. After the
[reboot](https://github.com/efrgdgr0024345/vpn/actions/runs/40448105690),
[inventory](https://github.com/efrgdgr0024345/vpn/actions/runs/40448251641)
at 67 seconds uptime confirmed VPN, broker and Unbound running, with both
persistent firewall tables and 18 rules.

[Post-boot live acceptance](https://github.com/efrgdgr0024345/vpn/actions/runs/40448325728)
passed all authentication, token, forwarding and private-DNS checks again.
[External UDP probe](https://github.com/efrgdgr0024345/vpn/actions/runs/40448467493)
confirmed the VPN transport remains reachable after reboot.

The owned Kali app is ready for a controlled installation/connection test. DEVICE_TESTING.md and
vpn-dashboard/INSTALL.md cover the next owner steps. No phone app or client
early-boot enforcement is implemented, and physical leak/transition behavior is
unverified. The older evidence below is historical; the JSON deployment record
and this current section take precedence.

## Previous staged-access acceptance (27 October 2026)

The selected system is implemented and deployed at runtime commit
`f7de4dd1629c827e92c1573ba5d1d26153202cf1`. It uses one tunnel, separately
enrolled Kali/iPhone/Android certificate identities, standard hidden session
tokens and one global main session. The root-local management broker admits
only an approved certificate pin; forwarding requires a short kernel lease.
Literal two-tunnel handoff, hardware attestation and a custom mobile app are
not claimed.

- [Main-branch CI 40431176614](https://github.com/efrgdgr0024345/vpn/actions/runs/40431176614)
  passed all four jobs: 109 desktop and 43 lab/broker/admin unit tests per Ubuntu
  job, real Tk/nft checks, real Debian SSH/SFTP including mobile-profile selection,
  and actual Debian VPN/PAM/firewall/token packet integration.
- [Gated installation 40431184235](https://github.com/efrgdgr0024345/vpn/actions/runs/40431184235)
  deployed that exact runtime commit and confirmed the native VPN service active.
- [Reboot 40431275049](https://github.com/efrgdgr0024345/vpn/actions/runs/40431275049)
  and [post-boot inventory 40431424970](https://github.com/efrgdgr0024345/vpn/actions/runs/40431424970)
  verified a fresh kernel uptime of 68 seconds, both VPN/broker services running,
  and persistent default-drop input/forward chains in the two firewall tables.
- [Post-reboot live acceptance 40431541188](https://github.com/efrgdgr0024345/vpn/actions/runs/40431541188)
  passed all checks: initial password/certificate login, bad-password and unapproved
  pin rejection, token reauthentication without the original password file,
  old-token replay denial, single-session contention without displacement,
  kernel lease expiry during a frozen broker, transfer between enrolled keys,
  prompt release on normal disconnect, device revocation, encrypted DNS/NAT,
  metadata/private-network filtering and the client IPv6 block response.

The private test credentials stayed on the server. The tests created temporary
unconfigured TUNs and did not modify host default routes or the resolver.
The previous working Access Server was not modified. The current boundary is
actual client acceptance: physical Kali DNS/firewall integration and real iPhone/
Android app import, roaming, suspend and leak behavior. Further server feature
work is deferred until those tests. DEVICE_TESTING.md records the next steps;
the owner's dedicated download public key is needed for private profile transfer.

Follow-up: metadata commit `be9b749cceb296170696ebf2a0ce6ddf56f874ab`
passed [main CI 40431918542](https://github.com/efrgdgr0024345/vpn/actions/runs/40431918542),
but [test-branch CI 40431908332](https://github.com/efrgdgr0024345/vpn/actions/runs/40431908332)
failed in the real VPN container job. Its existing annotation reports only exit
code 1, and the signed log-download host is unavailable from the controller.
The reason is not established; do not claim all runs were successful. The
container harness now emits a bounded, controlled error as a Checks annotation
so another failure can be diagnosed without exposing private test material.
The successful deployed/live acceptance record above remains separate evidence.

The owner supplied their dedicated Kali download public key. Gated
[download enrollment 40433179371](https://github.com/efrgdgr0024345/vpn/actions/runs/40433179371)
verified the expected public fingerprint and authorized the Kali files through
the expiring, read-only chroot. The private key remains on Kali. The owner
subsequently confirmed both files downloaded with mode 0600 and the saved
ED25519 server fingerprint matching the independently verified host.
[Closure 40437848772](https://github.com/efrgdgr0024345/vpn/actions/runs/40437848772)
removed new download access and the private export copies. File transfer is not
proof of a VPN connection. The owner confirms Kali has no active VPN; client
testing need not account for a simultaneous older tunnel.

[Repeat CI 40433404216](https://github.com/efrgdgr0024345/vpn/actions/runs/40433404216)
and [main CI 40433658177](https://github.com/efrgdgr0024345/vpn/actions/runs/40433658177)
passed all four jobs with the controlled diagnostic wrapper. The earlier
test-branch failure was not reproduced and its reason remains unestablished;
it has not been silently declared fixed.

## Reconstructed work history

1. The selected repository initially contained only `README.md` with `# vpn`.
   Environment onboarding verified Git access and integrity; it installed no VPN
   application because none was present at that point.
2. The user uploaded `vpn-dashboard.zip` containing 14 source/test/document files.
   The original app was a direct OpenVPN CLI desktop dashboard using a home
   profile and a broad temporary portal exception. Its validation record claimed
   64 mocked tests and explicitly excluded live Kali/VPN validation.
3. Those files were imported into the local checkout and reviewed. Subsequent
   client hardening introduced protected installed helpers/configuration,
   restrictive profile/policy checks, privilege dropping, disabled portal opening
   and private exports. This changed the client behavior; it did not modify the VPS.
4. A guided desktop installer was added, including optional apt prerequisites,
   protected app/helper installation, local profile import, account/menu creation
   and candidate firewall generation. It deliberately does not apply that
   firewall, configure DNS or reset Access Server passwords.
5. The user tested the original manual home-profile command. The posted log shows
   TLS 1.3 negotiation and certificate checks followed by server-side
   `AUTH_FAILED,Login failed`. It does not show a successful tunnel or a test of
   the protected launcher. The cipher deprecation warning does not explain that
   explicit authentication rejection.
6. Staged credentials, a restricted first VPN and a possible bootloader were
   discussed. A proposal was recorded, then the user paused development to
   recover the existing VPN. Random password suffixes were not implemented.
7. The user supplied the Access Server root-console banner. Read-only commands
   to inspect the authentication backend and selected account properties were
   provided. The user subsequently reported `Authentication: local` and
   `Account denied: unset`. An Access Server local-password reset command was
   supplied, but its execution/result has not been confirmed. No server lockdown,
   update or reboot has been performed or verified here.
8. After the user returned focus to VPN recovery, the certificate-name spacing
   bug was fixed locally with three regression tests. The current suite passes
   105 tests. A compatibility-fix bundle was prepared; earlier ZIPs are preserved.
9. The user requested testing through GitHub and suggested a temporary droplet
   to avoid interrupting the working VPN. A two-version Ubuntu Actions workflow,
   virtual-display UI smoke test and isolated real-nftables readback check were
   added locally. Their execution results are recorded separately below.

## What Git contained at the history audit

At the history audit, local HEAD and a fresh read of remote `main` both resolved to:

`affb10b187ec9ec2777aba2e03f4be0f28ef71b5` — `Initial commit`.

That commit tracked only the original README. The application, installer, tests
and design/review documents were local untracked files; README had local
modifications. None had been committed or pushed at that point. The reflog then
contained checkout/fetch activity, not implementation commits.

The subsequent request for GitHub testing authorizes publishing a separate test
branch. Production deployment remains paused. Local files and previous archives
are preserved; the history audit itself did not push or rewrite refs.

## Archive reconciliation

| Archive | Status at this audit |
| --- | --- |
| Original uploaded `vpn-dashboard.zip` | 14 files; preserved as the original input. |
| `vpn-dashboard-hardened.zip` | Older 27-file snapshot; predates the guided installer and later documentation. |
| `vpn-dashboard-installer.zip` | 30-file snapshot predating the certificate-name fix and newer design/status documentation. |
| `vpn-dashboard-compatibility-fix.zip` | Historical local snapshot including the certificate-name fix; predates the nft readback fix and CI work. Use the test branch for the latest source. |

Both older distributed ZIP integrity checks passed during the audit. They were
not replaced. Their hashes below identify the preserved historical snapshots;
the compatibility-fix bundle is a separate artifact.

SHA256 values of the preserved files:

```text
original upload  9c1ccce555c52fa6b1ddb93424462ce929150b123a592fb6b3d24c11a1fa8dab
hardened ZIP     08ceef746a40ad0e2d2576b51fca018713664eb5200fd4803e8a4209f554e566
installer ZIP    2f2d573e67c1053b7b4bab5f46daf1037274735e8e56288b791bae00b67d8ab6
```

## Earlier audit findings and blockers (historical snapshot)

1. **Client certificate-name compatibility bug: fixed locally.** The audit
   reproduced rejection of `OpenVPN Server` because the validator treated a
   certificate name like a hostname. The targeted fix permits internal spaces,
   requires quoting in the profile, preserves exact identity matching and rejects
   controls/boundary whitespace. Three regression tests were added. Old ZIPs
   still contain the bug; the fix has not been deployed to the user's desktop.
2. **No verified client deployment.** The current suite passes 109 tests, with
   simulated root metadata and mocked host VPN/firewall operations. The separate
   disposable-container checks also cover real nftables readback and UI startup.
   Real Access
   Server profile compatibility, networking, DNS/IPv6 containment, reconnect and
   desktop integration remain unverified.
3. **No automatic firewall/DNS migration.** A successful application installation
   does not establish working VPN connectivity. The client requires a separately
   reviewed matching firewall and resolver configuration.
4. **Local authentication confirmed; recovery unverified.** The user reported
   the selected account uses local authentication with no explicit `prop_deny`
   value. This is not a full review of effective permissions, lockout or MFA
   settings. No successful reset/login result has been supplied.
5. **Git publication is separate from deployment.** The later testing request
   uses a separate review/test branch and does not change the existing VPN.

## Isolated testing follow-up

The existing 105 tests passed again before adding the CI workflow. Python/shell
syntax and example JSON checks pass locally, and the workflow YAML parses.
Git remote reads and test-branch pushes worked before API access was available.
The first REST/GraphQL attempts were refused by the environment network proxy.
After a targeted network draft was saved and the user published the environment,
GitHub API reads succeeded. This does not grant all GitHub administration rights:
the Actions secrets public-key endpoint returns HTTP 403, "Resource not accessible
by integration". No personal access token was requested as a workaround.

The disposable Ubuntu 24.04 test exposed nft readback differences: redundant
IPv4 family checks disappear beside positive IPv4 address matches, and state-set
membership is represented as equality. The comparison now recognizes those
equivalent forms; endpoint/UID restrictions and all other policy checks remain.
Four regressions were added. All 109 tests, real Tk rendering/closure under Xvfb,
and real nft install/readback plus added-bypass refusal pass in that container.
Networking changes occurred only inside a fresh network namespace, and the
container shares the workspace host's kernel. No live VPN connection was tested.
The same 109-test suite, Tk startup/closure and real nftables check also passed in
a disposable Ubuntu 22.04 container. The implementation and CI workflow were
committed as `d973f339a8764c234ca5d7bdccf0124250354cc0` and pushed to
`test/isolated-vpn-validation`; a remote-ref read confirmed publication. Remote
At that point `main` remained at the initial README-only commit. GitHub-hosted results were then
verified through the API: [run 40162859451](https://github.com/efrgdgr0024345/vpn/actions/runs/40162859451)
completed successfully for commit `b76990ce3855906d4f7bd87f28d72fefe935d4dc`.
Both Ubuntu 22.04 and 24.04 jobs report successful source checks, unit/security
tests, real Tk smoke checks and isolated nftables readback. The earlier run for
the implementation commit also succeeded. These results do not test a VPN
connection or production deployment.

No DigitalOcean connector or API credential is configured. No test droplet has
been created, no cloud charges incurred by this task, and no production SSH
connection established. The user supplied provider-console output confirming
Debian 13, SSH listening on port 22, and successful addition of the temporary
public key on a separate disposable lab droplet. Its host-key fingerprint was
supplied out of band. Before the GitHub-runner route, no network scan had reached
that host and no scanned key had been compared or authentication attempted. Publishing recreated
the runtime without the corresponding private key formerly stored in `/tmp`.
That old authorized key should be removed during the next console setup step.
Direct SSH is still refused after the network change; its precise refusal source
is not established. GitHub-runner reachability was verified in the follow-up below.
See TESTING.md for the separate client/server test stages.

The user initially chose clean Ubuntu for the new design, then selected an
existing Debian 13 droplet for reuse and authorized discarding its old contents.
It remains separate from the working Access Server. No server packages, settings
or data have been changed by this task, and the new server design remains
unimplemented. A console-run installer or a separately configured GitHub SSH
runner is needed if direct access cannot be established.

## GitHub runner administration follow-up

The user selected GitHub Actions. A manual, main-branch-only lab workflow now
provides pinned-host connectivity checks and fixed read-only SSH inventory.
The console bootstrap provisions a dedicated root SSH key with a 24-hour
authorized-key expiry. It preserves unrelated keys and can remove the obsolete
key explicitly identified by the user. No actual lab key is in the repository.

Twelve new safeguard tests and an actual OpenSSH integration test pass locally.
The integration ran in an unexposed Debian 13 container and verified real root
SSH inventory, expired-key refusal and same-key renewal. No lab/server changes
are claimed from these disposable-container results. See GITHUB_LAB.md.

The environment-creation API also returns HTTP 403, "Resource not accessible by
integration". The owner needs to create `vpn-lab`, restrict deployments to `main`
and save its dedicated private key directly as the environment secret
`VPN_LAB_SSH_PRIVATE_KEY`. This is GitHub permission setup, not a request to send
secret material to the assistant. Default-branch publication and actual lab
reachability are recorded below as confirmed; initial admin operations do not
install or remove server software.

The new code was committed as `079352437bf67678705cb1ae77721fedf0546910`.
[GitHub run 40166128639](https://github.com/efrgdgr0024345/vpn/actions/runs/40166128639)
passed both Ubuntu client/security jobs (109 existing plus 12 new unit tests)
and the real Debian 13 SSH integration job. The tested branch was then published
to default `main` with a fast-forward push so manual dispatch is available.

[Lab connectivity run 40166246400](https://github.com/efrgdgr0024345/vpn/actions/runs/40166246400)
successfully reached the disposable droplet from a GitHub runner and verified
the independently supplied ED25519 fingerprint. The `inventory` job was skipped
as intended for that connectivity-only run. SSH authentication and server
inventory still await the owner's environment-secret/bootstrap step. No private
key or actual endpoint address was added to source, and no VPN configuration,
firewall or server data has been changed by the assistant.

## Disposable Debian server foundation work

The user explicitly authorized removing the lab's old services and asked that
implementation and third-party attribution be kept in GitHub. A successful
SSH inventory run confirmed Debian 13, roughly 70 GB free, no OpenVPN, and an
old self-hosted runner service for another project. The working Access Server
is not this lab droplet. The first secret omitted private-key envelope lines;
after the owner corrected it, actual SSH inventory succeeded.

Approved inventory is now published as a bounded check notice because signed
log-download hosts are unavailable from the controller. This avoids another
network-settings change; no credential material is included in the report.

The foundation installer, native service/firewall/PAM/PKI generators, local
packet self-test and isolated container harness are implemented in `ops/` and
`ci/`. There are 109 existing desktop tests and 19 lab/safeguard tests. Local
real OpenVPN integration now passes correct/incorrect credentials, encrypted
IPv4 DNS/NAT, private/cloud-metadata denial, client IPv6 blocking, a second login
not displacing the active one, and reruns preserving existing credentials.

Real tests caught and fixed Debian's duplicate compatibility/canonical PAM
plugin paths and an Easy-RSA CN environment override. Explicit certificate
identity checks and a CN-scoping regression prevent those issues recurring.
THIRD_PARTY_NOTICES.md credits the upstream projects and records the absence of
an identified original ZIP author/repository-wide license. Private keys,
passwords and real exported profiles stay out of source and CI artifacts.

GitHub-hosted validation, actual installation and live server checks are
recorded below. This milestone is conventional OpenVPN; the
staged authorization broker is still unimplemented. SERVER_SETUP.md records
test limits, recovery and private client-profile locations.

The foundation passed [four GitHub CI jobs](https://github.com/efrgdgr0024345/vpn/actions/runs/40272577803)
before the initial installation attempt. That attempt stopped during legacy
runner-unit cleanup. Unit-entry handling was corrected without following or
reading an old symlink target, with a regression covering safe removal. Both
subsequent CI runs for the corrected commit passed.

Actual [installation run 40273060571](https://github.com/efrgdgr0024345/vpn/actions/runs/40273060571)
then succeeded for commit `f1c6e7175d8a993df53b65c63f814eb7aebf9eae`.
The returned report confirms the service is active, one old runner service was
retired, maximum clients is one, and certificate plus PAM password is required.
The working Access Server was not touched.

The [live packet self-test](https://github.com/efrgdgr0024345/vpn/actions/runs/40273149219)
passed all checks: correct/incorrect password behavior, encrypted DNS through
NAT, metadata/private-network drop, IPv6 block response and a second login not
displacing the active session. Private credentials stayed on the droplet.
The [external UDP probe](https://github.com/efrgdgr0024345/vpn/actions/runs/40273151402)
also confirmed that a runner-originated nonce reached the server's UDP 1194
interface. This is distinct from a full external-client TLS handshake.

`deployments/vpn-lab.json` records these sanitized results and the remaining
physical-client/reboot tests. The install workflow now has an additional gate
requiring successful push-CI for the exact deployment commit before accessing
its SSH secret. There are 23 lab/safeguard/gate unit tests plus 109 desktop tests.
The new gate's GitHub validation is recorded when complete. No staged broker,
new OS or custom cryptography is claimed implemented.

The controller/check-gate commit `6994457ff1221a07da2e98bc2db56dbec33ea535`
passed all four GitHub CI jobs. Post-install inventory also succeeded and
confirmed the native VPN service and dedicated firewall on the lab.

The owner uses the provider web console rather than an existing Kali SSH key.
A temporary file-download path is therefore implemented: a separate public-key
account is forced into read-only internal SFTP, chrooted to just the two VPN
client files, with no shell/forwarding/password authentication or other key
providers. Its grant expires after 24 hours; a fixed revocation action removes
the key and private export copies. The owner's private download key is generated
on Kali and never supplied to the assistant.

The actual Debian 13 SSH integration test passes download, chroot escape denial,
mutation denial, no shell, revocation, and preservation of root administrative
access. There are now 26 lab/gate/download unit tests plus 109 desktop tests.
Production/lab download enrollment awaits the owner's public key; no claim is
made that a physical Kali VPN connection has been tested.

Download setup and closure also require the matching-commit CI gate. The helper
disables other SSH key providers and trusted user CAs for the download account,
validates effective sshd settings before reloading, and keeps administrative
settings intact. The root-owned protected installer library is installed by the
foundation workflow for this helper's guarded import path. No new public key
is enrolled until supplied by the owner.

The final credential-handling hardening disables core dumps in the controller,
installer, self-test and download helper. Commit
`81aa80f0f60adafa91e0613fb87e62fe25fbe437` passed all four GitHub CI jobs,
including 135 unit tests per Ubuntu job and real Debian SSH/SFTP and VPN packet
integration. [Gated deployment 40276817573](https://github.com/efrgdgr0024345/vpn/actions/runs/40276817573)
then succeeded: connectivity, matching-commit CI verification and administration
all passed. The installer rerun preserved credentials and reused the existing
PKI; the protected helper library is now installed on the server.

[Live test 40277258126](https://github.com/efrgdgr0024345/vpn/actions/runs/40277258126)
passed the full packet/authentication checks again after that deployment.
Post-install inventory confirmed the VPN service active, the old runner absent
from running services, and two firewall tables with default-drop input and
forward chains. No physical Kali connection or reboot test is claimed.
The next external prerequisite is the owner's Kali ED25519 public key for
temporary private file transfer; the corresponding private key stays on Kali.

## Original Access Server recovery reference

Keep the existing root recovery console open. Inspect Access Server's current
authentication backend and selected account status, then reset the account using
the corresponding supported mechanism. Keep new credentials out of chat, logs,
shell history and this public project. Verify one real VPN login before changing
connection limits, account permissions or administrative access. Review patches
and the reported reboot requirement after recovery is established.

That original audit made no changes to the Access Server. Subsequent lab
deployment and the resumed staged-access work are recorded above; they must
not be confused with recovery or migration of the separate Access Server.

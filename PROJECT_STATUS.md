# Project history and current status

This reconciles the conversation available in this task, the original uploaded
ZIP, the local project, Git history, the current remote main ref and the preserved
distributed ZIPs. Separate older ChatGPT conversations are not exposed through
the tools/resources attached to this task. No conversation export or additional
history file was found in the shared workspace folders.

Current priority: test in GitHub and on separate disposable infrastructure while
the user continues working through the existing VPN. Production changes are
paused. New staged-login, password-suffix, sandbox and bootloader development
also remains paused.

## Three distinct systems

| Component | Evidence and status |
| --- | --- |
| Existing VPS | The user's console identifies OpenVPN Access Server Appliance 3.2.2 and a root shell. This task has no live connection to that console. |
| VPN Desk project | A local Linux desktop client/diagnostic prototype, with privileged client helpers and an installer. It is not an Access Server deployment or administration tool. |
| Proposed new VPN | A design in NEW_VPN_DESIGN.md. No credential broker, restricted bootstrap VPN, device-attestation service, exclusive server lease or two-tunnel handoff is implemented. |

The installer-created `vpn-desk` account is a local client-machine service
account for privilege dropping. It is not the remote VPN login account.
The desktop firewall candidate is not a VPS firewall migration.

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

## Findings and remaining blockers

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

## Recovery actions after isolated testing

Keep the existing root recovery console open. Inspect Access Server's current
authentication backend and selected account status, then reset the account using
the corresponding supported mechanism. Keep new credentials out of chat, logs,
shell history and this public project. Verify one real VPN login before changing
connection limits, account permissions or administrative access. Review patches
and the reported reboot requirement after recovery is established.

The audit itself made no runtime changes. The subsequent certificate-name fix
changes only local client validation and tests. New VPN feature work remains
paused, and no live VPS settings or credentials have been changed here.

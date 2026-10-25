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
| `vpn-dashboard-compatibility-fix.zip` | New local source snapshot including the certificate-name fix and current documentation; not a verified live deployment. |

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
Git remote reads work. GitHub CLI has authentication configured, but both REST
and GraphQL API requests are currently refused by the environment's network
proxy. Authentication configuration alone does not establish API access or
permission to push. No GitHub Actions execution is claimed at this point.

The disposable Ubuntu 24.04 test exposed nft readback differences: redundant
IPv4 family checks disappear beside positive IPv4 address matches, and state-set
membership is represented as equality. The comparison now recognizes those
equivalent forms; endpoint/UID restrictions and all other policy checks remain.
Four regressions were added. All 109 tests, real Tk rendering/closure under Xvfb,
and real nft install/readback plus added-bypass refusal pass in that container.
Networking changes occurred only inside a fresh network namespace, and the
container shares the workspace host's kernel. No live VPN connection was tested.
The same 109-test suite and real nftables check also passed in a disposable
Ubuntu 22.04 container. The test branch is `test/isolated-vpn-validation`;
GitHub-hosted results still need independent verification.

No DigitalOcean connector or API credential is configured. No test droplet has
been created, no cloud charges incurred by this task, and no production SSH
connection established. A temporary SSH key was prepared outside the repository;
it has not been confirmed authorized on any VPS. See TESTING.md for the separate
client/server test stages.

The user chose a clean Ubuntu droplet for the new design rather than a matching
Access Server appliance. The target is a separate Ubuntu 24.04 LTS test server.
Creation/access are still pending; the new server design remains unimplemented.

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

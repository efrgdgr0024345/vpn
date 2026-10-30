# GitHub administration of the disposable VPN lab

The user selected GitHub Actions for administration of the separate Debian 13
lab droplet. The working Access Server is outside this workflow's scope.

`Lab server administration` is a manual workflow on `main`:

| Operation | Effect |
| --- | --- |
| `connectivity` | Reach SSH and compare its ED25519 key with the independently supplied provider-console fingerprint. No authentication or private key needed. |
| `inventory` | Repeat identity verification, then run a fixed read-only Python inventory as root using the lab environment's dedicated SSH key. |
| `diagnose-connection` | Read service health, the VPN interface, DNS bindings, the single-device forwarding lease, two fixed firewall counters and clock synchronization; test the VPS resolver locally. No configuration or session changes. |
| `prepare-test-access` | Create or verify a dedicated root-protected SSH test identity on the lab. Return its public key/fingerprint only; its private key stays on the lab. Requires matching build checks. |
| `inspect-test-peer` | From the lab, verify an external test machine's supplied host fingerprint and inspect it using the dedicated test key. Fixed read-only inventory; no package, service or network changes. |
| `test-from-peer` | Prepare the peer's client tools, then run a real external VPN connection, private DNS, public forwarding and verified HTTPS in its own network namespace. Uses a fresh temporary certificate and restores/revokes it afterward. Requires matching build checks. |
| `install-foundation` | Provision the disposable Debian 13 OpenVPN foundation, replacing its firewall and retiring old runner services. |
| `test-foundation` | Test the running VPN locally without exporting its credentials or changing host routes/DNS. |
| `probe-udp` | Send a random non-secret UDP probe from the GitHub runner and observe its arrival on the lab's external interface. No VPN credentials are exported. |
| `prepare-download` | Authorize a supplied public key for a 24-hour, read-only, chrooted SFTP view of the selected device's two client files. No shell or forwarding. |
| `close-download` | Remove the download key and private export copies, preventing new download logins. |
| `device-status` | Public enrollment fingerprints and enabled flags; no private credentials. |
| `revoke-device`, `enable-device` | Disable or explicitly reenable one existing enrolled identity. |
| `reset-sessions` | Deny forwarding, then restart the VPN and broker with fresh session-token state. |
| `reboot-lab` | Schedule a disposable-server reboot after ten seconds so the workflow can report first. |

There is no arbitrary command input or automatic production deployment.
SERVER_SETUP.md documents the explicitly selected installation/test operations.
STAGED_ACCESS.md describes the selected one-tunnel authorization broker. All
mutations and the disruptive packet test require successful matching-commit CI.

## One-time GitHub environment setup

The connected integration can push code and read test results, but environment
creation and Actions secrets endpoints return HTTP 403. The repository owner
must perform this step; no personal access token needs sharing in chat.

1. In repository **Settings → Environments**, create `vpn-lab`.
2. Under **Deployment branches and tags**, choose selected branches/tags and add
   the branch `main`. Keep the lab secret scoped to this environment.
3. Add an environment secret named **`VPN_LAB_SSH_PRIVATE_KEY`** containing the
   dedicated private key generated below. Paste it directly into GitHub's secret
   field, including BEGIN/END lines. Never paste it into chat, source or reports.

## Dedicated SSH key on the droplet

Keep the provider console open. Download `ops/bootstrap_runner_key.py` at the
reviewed commit, verify its SHA256 against the supplied value, and run it with
`/usr/bin/python3 -I -B` in the droplet's root console. It uses existing Python 3
and OpenSSH tools and does not install packages.

It stores a dedicated ED25519 key at `/root/.vpn-lab-actions/id_ed25519`, with
owner-only permissions, and adds a `restrict,expiry-time="..."` authorized-key
entry valid for 24 hours. Other administrative keys are preserved. The optional
`--remove-key-blob` removes only a specified obsolete public key. The script
prints the public fingerprint and private-key location, never private contents.

View that private file only in your trusted provider console and copy it directly
to the GitHub environment-secret field. Do not send that output to this chat.
Use this key only for this disposable server.

Re-running the verified bootstrap renews the same key for 24 hours without
changing the GitHub secret. Expiration prevents new SSH logins; it does not
terminate an established connection. Administrative jobs have short timeouts
and do not create persistent sessions.

## Renew the existing grant from the provider root console

An SSH authentication rejection cannot be repaired over that rejected SSH
connection. Keep the existing private key and GitHub environment secret. The
following command requires that existing key, verifies the immutable reviewed
bootstrap source before execution, and renews the same grant for 24 hours.
It does not change VPN/firewall settings. The bootstrap's generic first-install
copy hint can be ignored for renewal; do not copy key contents to chat.

```sh
python3 -I -B - <<'PY'
import hashlib
from pathlib import Path
from urllib.request import urlopen
if not Path('/root/.vpn-lab-actions/id_ed25519').is_file():
    raise SystemExit('Existing key missing; stop here.')
url = 'https://raw.githubusercontent.com/efrgdgr0024345/vpn/71586730bc7af1ff4fe39a07abe7540a2b3f94c0/ops/bootstrap_runner_key.py'
source = urlopen(url, timeout=20).read(65537)
if hashlib.sha256(source).hexdigest() != '331590e03c9c741d9c36c89b9bae3f7e28ae4878f403034e4cba896ee157ec6a':
    raise SystemExit('Checksum mismatch; nothing executed.')
exec(compile(source, 'verified-key-bootstrap', 'exec'), {'__name__': '__main__'})
PY
```

## Run and inspect

For an external VPN test client, the owner selected the existing older VPS and
asked to grant access from the lab rather than create another GitHub secret.
`prepare-test-access` creates an idempotent Ed25519 identity at
`/root/.vpn-lab-external-test/id_ed25519`, under a root-only directory. It does
not export that private file. The owner authorizes only its public key on the
external machine with a temporary SSH expiry and supplies that machine's SSH
host fingerprint through the provider console.

`inspect-test-peer` still connects to the lab using the existing lab environment
secret. Its optional `test_peer_host`, `test_peer_port` and
`test_peer_host_fingerprint` inputs select the separate, pinned inspection target.
The lab verifies that host key before presenting its dedicated test identity.
The peer returns a bounded, strictly validated OS/client-tool inventory; it
never receives general command input. No extra GitHub secret is required.
The private key remains on the lab, and peer inspection does not start a VPN,
change the old Access Server or replace any routes, resolver or firewall rules.
Actual external VPN packet acceptance is a separate test after this access step.

`test-from-peer` installs only missing stock OpenVPN, slirp4netns and CA tools on
the peer; it refuses an existing stock OpenVPN configuration before installing
that client package. It neither upgrades/removes named packages nor changes the
older Access Server's settings. The client runs in a fresh network namespace
with userspace networking, preserving the host routes and resolver. A successful
report requires login, private DNS, a public DNS forwarding roundtrip and
certificate-verified HTTPS to an address resolved through the VPN's DNS.

The lab signs a fresh client certificate and briefly substitutes it into the
unused Android enrollment slot at `.249`, after refusing a busy VPN. The original
registry is restored and the test certificate revoked; other root edits are
preserved and reported as a failure. No existing Kali/mobile private key is sent.
The test profile and shared VPN login pass directly from the lab to its pinned
peer over SSH, never through the Actions runner or logs. They exist only in a
root-private temporary directory on the peer, removed during cleanup. This is
different from the loopback self-test, whose credentials never leave the lab.
No password rotation, service restart or firewall flush is part of this test.
OpenVPN 2.6+ uses userspace mode, so a pass does not validate Kali 2.7's DCO path.

The gated `rotate-password` operation is independent root-only recovery for an
exposed initial VPN password. It preflights the protected original/device copies,
clears forwarding and stops OpenVPN before changing PAM and all four private
login files, closes old download access, then starts OpenVPN with a new in-memory
token signing secret. A partial credential-write failure leaves the VPN stopped
for provider-console recovery. Its report contains fixed booleans, never a
password. Use the owner's existing verified SSH public key with `prepare-download`
to retrieve the replacement login privately, then close that temporary grant.
This operation does not implement automatic password rotation at every handoff.

Use **Actions → Lab server administration → Run workflow**, choosing `main`.
Supply the lab IPv4 address, SSH port and full `SHA256:...` ED25519 fingerprint
obtained through the provider console. Start with `connectivity`, then choose
`inventory` after the secret is configured.

The address and fingerprint are public workflow inputs. Operational addresses
are not committed to source. Public Actions logs show the inventory: OS/kernel,
free disk, service unit names, listening port numbers, tool presence, firewall
counts and a candidate-subnet conflict check. IP addresses, profiles, credentials,
process arguments, account databases, configuration contents and journals are
omitted. The approved inventory is also attached as a check notice, so an
administrator can read it through GitHub's Checks API when log-download hosts
are unreachable. Workflow-command escapes preserve literal percent sequences,
and oversized notices fail before server data is printed.

`diagnose-connection` adds a separate, strictly validated report for connection
troubleshooting. It intentionally includes tunnel/DNS binding addresses and the
authorized VPN source, plus a bounded `example.com` DNS result. Unknown nested
fields, arbitrary service text and raw command errors are refused before output.
It reads no profiles, credentials, journals or OpenVPN management socket. The
DNS query restricts output to loopback and binds a verified local server tunnel
address, never a public fallback. A successful local query alone does not test the remote client's
path. Capture another report while the client is connected to inspect its lease
and changes to the authorized-DNS/drop counters.

The runner verifies the fingerprint before authentication and keeps strict SSH
host checking enabled. Private temporary key files are 0600, deleted after use
and never uploaded as artifacts. Forwarding and agent forwarding are disabled.
No secrets are supplied to pull requests; admin runs require manual dispatch on
this repository's `main`.

`restrict` disables SSH forwarding/PTY features. It does **not** restrict root
commands usable by a key holder. Anyone able to modify trusted main-branch code
and access this environment can exercise that lab root authority. Limit write
access and review changes before running administration.

After testing, remove the dedicated authorized key, its private files on the
droplet and the GitHub environment secret. Preserve independent console access
and the user's other administrative keys.

## Validation

Fourteen unit tests cover host/input validation, strict SSH arguments, key-file
cleanup, manual/main context, unrelated-key preservation, symlink/hardlink
refusal, interrupted authorization updates and bounded/escaped check reports.

`sh ci/test_ssh_container.sh` uses a digest-pinned Debian 13 container without
host mounts, published ports or added capabilities. It runs real OpenSSH and
the actual console bootstrap, verifies a pinned SSH inventory, rejects an expired
key, renews that same key and confirms restored access. Package signatures stay
enabled. The existing 109-test desktop suite, Xvfb and nft checks remain separate.

The SSH integration also checks a separate chrooted SFTP account: selected-file
download succeeds, parent files cannot be read, file mutations and shells are
denied, revocation closes new logins, and root administration remains available.
The earlier gate/download milestone had 26 lab unit tests. Broker and device
administration tests now extend that suite.

Local tests and [GitHub-hosted validation](https://github.com/efrgdgr0024345/vpn/actions/runs/40166128639)
pass. The [initial connectivity run](https://github.com/efrgdgr0024345/vpn/actions/runs/40166246400)
reached the actual lab droplet and verified the provider-console host fingerprint.
Actual SSH authentication and installation subsequently succeeded, and fresh
[inventory 40428981258](https://github.com/efrgdgr0024345/vpn/actions/runs/40428981258)
confirmed administrative access at the start of staged-access implementation.

# GitHub administration of the disposable VPN lab

The user selected GitHub Actions for administration of the separate Debian 13
lab droplet. The working Access Server is outside this workflow's scope.

`Lab server administration` is a manual workflow on `main`:

| Operation | Effect |
| --- | --- |
| `connectivity` | Reach SSH and compare its ED25519 key with the independently supplied provider-console fingerprint. No authentication or private key needed. |
| `inventory` | Repeat identity verification, then run a fixed read-only Python inventory as root using the lab environment's dedicated SSH key. |
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

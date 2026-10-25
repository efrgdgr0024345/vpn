# Testing before production

Keep the working Access Server unchanged while testing. The desktop installer
in this repository is not an Access Server installer. The new staged-login
architecture remains a proposal.

## GitHub Actions

`.github/workflows/checks.yml` runs on pushes, pull requests and manual dispatch.
It uses disposable GitHub-hosted Ubuntu 22.04 and 24.04 runners, a read-only
repository token and a checkout pinned to a verified commit. No production SSH
key, VPN profile, password or DigitalOcean token is needed.

The workflow checks Python/shell/JSON syntax, runs the existing unit/security
suite, renders the actual Tk dashboard under Xvfb, and applies and reads back the
candidate nftables JSON inside a fresh network namespace. It also checks that
the guard rejects an added output bypass. The nft test substitutes only fixture
policy/account lookup; it does not install accounts or configuration on a host.
It fails if namespace creation or kernel testing is unavailable rather than
silently skipping those checks. No VPN connection is made by this workflow.

During local CI preparation on disposable Ubuntu 24.04, this test caught and
fixed nftables readback normalization the mocked fixtures had missed. The suite
now has 109 tests. The unit suite, Xvfb check and real nft readback check pass in
local Ubuntu 22.04 and 24.04 containers. GitHub-hosted results were subsequently
verified: both Ubuntu jobs in [run 40162859451](https://github.com/efrgdgr0024345/vpn/actions/runs/40162859451)
completed successfully for commit `b76990ce3855906d4f7bd87f28d72fefe935d4dc`.

A passing run does not establish working routing, DNS/IPv6 containment or Access
Server interoperability. It also does not exercise a real desktop installation,
the proposed credential handoff or the user's Kali version.

## Temporary droplet

The user selected a clean system for the new design, then chose to reuse a
separate **Debian 13 (trixie) droplet**, authorizing removal of its old contents.
It is not the working Access Server. Keep credentials and private-network routes
separate from production. Direct SSH is currently refused from the cloud task;
an allowlist update enabled GitHub API reads but did not establish an SSH route.
The old temporary private key did not survive publication of the environment;
its authorized public key should be removed during console setup. Do not keep
authorizing that obsolete key or assume another publish will enable SSH.

There is no new server installer or credential broker implemented by this
repository yet. Establish a conventional working VPN and independent console
recovery before adding staged authentication. GitHub's available integration can
read Actions results but cannot manage Actions secrets (HTTP 403). A console-run
installer or separately configured GitHub runner is an alternative setup route.

Also use a separate client VM for desktop and leak tests: a server droplet alone
cannot test the desktop's routing or firewall. Keep this infrastructure separate
from the working server:

1. Create a clearly named test droplet, with a temporary SSH public key and a
   provider firewall allowing SSH/admin access only from the test administrator's
   current source address. Allow the intended VPN transport only from test-client
   addresses. Check the provider's displayed cost before creating it.
2. Verify its SSH host-key fingerprint through the provider console. Use fresh
   VPN accounts, profiles and keys, without copying production credentials or
   connecting it to a production private network.
3. Record the server and client versions. Test successful and rejected logins,
   password reset, reconnect, reboot recovery and the independent root console.
   Review account/admin settings and patches on this test server first.
4. On the disposable client, test installation/permissions, supported profile
   compatibility, generated firewall readback, intended traffic, blocked direct
   IPv4/IPv6/DNS traffic, tunnel failure and reconnection. Capture packet evidence
   from outside that client before claiming leak prevention. Keep a console open
   when testing a default-drop firewall.
5. Record results and remaining failures, revoke temporary access, and delete
   test droplets and any separately billed resources when finished.

Do not put private keys, API tokens, passwords or real client profiles in this
public repository or in chat. There is no automatic production deployment.

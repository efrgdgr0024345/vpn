# IPv4-only Kali setup

## Current deployment status and owner requirement

The owner requires IPv6 disabled on the VPN server and persistently blocked on
Kali, including before connection and after reboot. This is separate from the
broader server lockdown and boot-image work currently deferred.

The VPS migration and reboot are complete. Live
[post-reboot verification](https://github.com/efrgdgr0024345/vpn/actions/runs/41030851958)
confirmed the active `ipv6.disable=1` boot argument, disabled kernel subsystem,
unavailable IPv6 sockets, no IPv6 addresses/routes, all three firewall blocks,
IPv4-only VPN settings and active VPN/broker/private-DNS services. The exact
source passed all five functional jobs and security analysis before migration.
[External acceptance](https://github.com/efrgdgr0024345/vpn/actions/runs/41030975757)
then verified real login, private DNS, public IPv4 forwarding and HTTPS from the
owner's older VPS, with cleanup confirmed. `deployments/ipv4-only.json` records
the evidence. The original foundation,
certificates and credentials were preserved; only the narrow migration was run.

Kali still needs the owner to apply the checked setup below and reboot. Its last
physical report has `ipv6_kernel_disabled: false`; the VPS result does not change
the laptop. Broader lockdown and boot-image work remain deferred.

The fixed GitHub Actions operation `enable-ipv4-only` accepts only the recognized
lab configuration, refuses an active forwarding lease and preserves VPN
credentials, PKI and unrelated live firewall rules. It removes the legacy IPv6
tunnel settings, inserts first-position IPv6 drops in input/forward/output,
updates the known packet self-test, applies interface sysctls, and adds the
`ipv6.disable=1` GRUB argument. It does not reboot automatically. The existing
`reboot-lab` operation activates that boot argument; `ipv4-only-status` verifies
both the running kernel state and service health afterward. All mutations are
gated on functional and security CI for the exact commit.

## Reviewed Kali setup

`ops/disable_client_ipv6.py` is a standalone system-Python setup. Run only the
reviewed, independently SHA256-checked source with `sudo /usr/bin/python3 -I -B`.
It requires the already tested protected IPv4-capable VPN Desk helper, an
ordinary IPv4 route and no active VPN, guard or saved networking state. It
preserves conflicting configuration files, the existing GRUB command line, VPN
profiles, credentials, DNS and firewall rules. It installs only the two fixed
configuration files below, runs `update-grub`, applies the interface settings,
and reports whether a reboot is required. It does not reboot the laptop.

After a normal reboot, run the same verified script with `--check`. Completion
requires `kernel_ipv6_disabled: true`, `boot_parameter_active: true`,
`persistence_installed: true`, `boot_argument_configured: true`,
`ipv6_address_count: 0`, and
`reboot_required: false`. Files present before reboot are not proof that the
running kernel has IPv6 disabled. Save the command offline before rebooting.

## Temporary connectivity test before permanent setup

The owner selected a temporary test before changing boot settings. Run with normal
Internet working, the VPN disconnected and its guard released. This changes only
runtime interface IPv6 flags. It schedules and verifies a system restore timer
before any IPv6 write; failure or an existing test-unit collision stops first.
The timer runs independently of the terminal and restores the saved settings
including per-interface differences after about 90 seconds while the machine is
awake. Newly created interfaces use the saved default; vanished interfaces are
skipped. A setup exception requests immediate restoration too.

```sh
sudo -- /usr/bin/python3 -I -B - <<'PYCODE'
import hashlib, os, resource
from urllib.request import urlopen
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
os.chdir('/')
os.environ.clear()
os.environ.update(PATH='/usr/sbin:/usr/bin', LC_ALL='C')
url = 'https://raw.githubusercontent.com/efrgdgr0024345/vpn/d49f434c824af44efd414e038889cd632de90e39/ops/temporary_client_ipv6.py'
try:
    source = urlopen(url, timeout=30).read(262145)
except OSError:
    raise SystemExit('Download failed; no test started.') from None
if hashlib.sha256(source).hexdigest() != 'c54d066e33b6958fe01070e9e317e9118460eaa63fc9e89fa276306cbb8ed138':
    raise SystemExit('Checksum mismatch; no test started.')
exec(compile(source, 'checked-temporary-ipv6-test', 'exec'), {'__name__': '__main__'})
PYCODE
```

Try browsing during the test. For an early restore, run this locally; it needs no
Internet and cancels the remaining timer after restoration succeeds:

```sh
sudo systemctl start vpn-desk-ipv6-restore.service &&
sudo systemctl stop vpn-desk-ipv6-restore.timer
```

The command does not edit GRUB or persistent sysctl configuration and requires no
reboot. It refuses a kernel that already has IPv6 disabled. Avoid VPN Connect or
the permanent setup during the test. Restoring flags does not instantly rebuild
addresses/routes: RA, DAD and DHCPv6 can take additional time; Wi-Fi may need
reconnecting. NetworkManager can also reenable IPv6 during an experiment; this is
a connectivity test, not proof of a strict VPN-only policy or a packet leak test.
No actual systemd timer was started on the user's laptop by repository tests:
four targeted tests cover scheduling-before-write, failure-before-write, immediate
recovery request, and restoration across interface additions/removals. The actual
Kali timer must be active before the script proceeds.

## Permanent Kali setup command

With the VPN stopped and normal networking restored, this downloads the public
standalone setup at the immutable reviewed revision and checks its SHA256 before
execution. It asks only for the local sudo password. It does not reboot or change
DNS. Reboot normally when the report says `reboot_required: true`.

```sh
sudo -- /usr/bin/python3 -I -B - <<'PYCODE'
import hashlib, os, resource, sys
from urllib.request import urlopen
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
os.chdir('/')
os.environ.clear()
os.environ.update(PATH='/usr/sbin:/usr/bin', LC_ALL='C')
url = 'https://raw.githubusercontent.com/efrgdgr0024345/vpn/3623cbf5b4dff97028d8c08508c33cb9b0ec0de8/ops/disable_client_ipv6.py'
try:
    source = urlopen(url, timeout=30).read(262145)
except OSError:
    raise SystemExit('Download failed; no setup executed.') from None
if hashlib.sha256(source).hexdigest() != '6354432caff7256460c1d37a1c035286e69caa2d2769986cc0ade9cecaebc01e':
    raise SystemExit('Checksum mismatch; no setup executed.')
sys.argv = ['checked-ipv6-setup']
exec(compile(source, 'checked-ipv6-setup', 'exec'), {'__name__': '__main__'})
PYCODE
```

After reboot, rerun the block with its `sys.argv` line changed to
`sys.argv = ['checked-ipv6-setup', '--check']` and save the resulting status. The
read-only check is safe to run while connected. Full completion still requires
the kernel and boot checks described above; the server's state is independent.

## Prepared Kali configuration

The owner's lab is reachable again after provider billing recovery. A stalled
login while the VPN server was suspended does not establish an IPv6 fault.
The owner separately requested IPv6 disabled entirely on Kali.

First stop the VPN and restore normal networking. Install the reviewed transport
helper update described in `vpn-dashboard/INSTALL.md` before disabling IPv6.
It ignores the older server's IPv6 tunnel/route pushes, uses an explicit IPv4
transport, and keeps IPv4 `redirect-gateway def1` locally enforced.

For a reviewed public update directory and updater, verify the updater and
`client-update.json` against independently supplied SHA256 values before executing:

```sh
sudo /usr/bin/python3 -I -B ops/upgrade_client_transport.py \
  /path/to/public-update-directory VERIFIED_UPDATE_MANIFEST_SHA256
```

The updater recognizes the earlier protected transport by its known SHA256 and
checks the public-code manifest, metadata and process/action locks before writes.
It updates the six fixed transport/logging/IPv6-check module copies and their manifest entries; unknown modifications are
preserved and refused. Private profiles, login files and recovery state remain
unchanged. It does not turn off IPv6 by itself.

## Persistent IPv6 disablement on a GRUB-based Kali installation

This changes the whole Kali OS, including applications outside the VPN. An
IPv6-only network or service will no longer be usable. Save these instructions
offline and verify IPv4 connectivity before applying them. The boot step below
requires `/usr/sbin/update-grub` and `/etc/default/grub` on the actual machine;
other bootloaders need their own equivalent configuration.

The two fixed public configuration files are tracked under `deployments/kali/`.
Use the checked standalone command above to install them. It preserves a differing
existing file and stops for review. It also reads back the generated
`/boot/grub/grub.cfg`: every recognized Linux/LinuxEFI entry must contain one
`ipv6.disable=1`, with no conflicting value, before immediate sysctl changes.
A successful `update-grub` exit status or two saved drop-ins alone is insufficient.

The sysctls disable current and future interfaces immediately. A normal reboot
activates the kernel argument and prevents userspace managers re-enabling IPv6.
The post-reboot check is still required because generated GRUB entries alone do
not prove which bootloader the firmware used. Save the instructions offline.

After reboot, verify `grep -o 'ipv6.disable=1' /proc/cmdline` reports the argument
and `ip -6 address show` lists no IPv6 addresses. A sysctl value of 1 alone does
not establish that the boot parameter took effect. Test the actual IPv4 VPN and
DNS; an empty IPv6 address list is not evidence of a healthy VPN connection.

The app's **Restore normal networking** releases its saved VPN DNS/firewall
state; it intentionally does not undo this separate OS preference. To undo the
OS preference later, remove only these two owned configuration files, run
`sudo update-grub`, and reboot. This is not an app early-boot kill switch.

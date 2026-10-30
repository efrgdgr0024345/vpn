# IPv4-only Kali setup

## Current deployment status and owner requirement

The owner requires IPv6 disabled on the VPN server and persistently blocked on
Kali, including before connection and after reboot. This is separate from the
broader server lockdown and boot-image work currently deferred.

The repository now includes a narrow server migration and a standalone Kali
setup. Deployment is not established by these source changes: live server
migration/reboot and the owner's Kali apply/reboot checks are separate evidence.
The last physical Kali report still has `ipv6_kernel_disabled: false`.

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
`persistence_installed: true`, `ipv6_address_count: 0`, and
`reboot_required: false`. Files present before reboot are not proof that the
running kernel has IPv6 disabled. Save the command offline before rebooting.

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

The two public configuration files are tracked under `deployments/kali/`.
Keep an independently verified source copy/hash. If either destination already
exists with different content, preserve it and review the conflict first.
Run from the reviewed repository root, with no active VPN and after restoring
normal networking:

```sh
test -x /usr/sbin/update-grub && test -f /etc/default/grub
sudo test ! -e /etc/vpn-desk/network-state.json
sudo install -d -o root -g root -m 755 /etc/default/grub.d
sudo install -o root -g root -m 644 deployments/kali/90-vpn-desk-ipv4-only.conf \
  /etc/sysctl.d/90-vpn-desk-ipv4-only.conf
sudo install -o root -g root -m 644 deployments/kali/99-vpn-desk-ipv4-only.cfg \
  /etc/default/grub.d/99-vpn-desk-ipv4-only.cfg
sudo update-grub
sudo sysctl -p /etc/sysctl.d/90-vpn-desk-ipv4-only.conf
ip -6 address show
```

Run these in order and stop on any error. The sysctl settings disable current
and future interfaces immediately. The kernel argument takes effect after a
normal reboot and prevents userspace network managers re-enabling IPv6. It is
appended without replacing existing kernel arguments. Until reboot, a network
manager/root action can still change interface sysctls; verify after reconnects.

After reboot, verify `grep -o 'ipv6.disable=1' /proc/cmdline` reports the argument
and `ip -6 address show` lists no IPv6 addresses. A sysctl value of 1 alone does
not establish that the boot parameter took effect. Test the actual IPv4 VPN and
DNS; an empty IPv6 address list is not evidence of a healthy VPN connection.

The app's **Restore normal networking** releases its saved VPN DNS/firewall
state; it intentionally does not undo this separate OS preference. To undo the
OS preference later, remove only these two owned configuration files, run
`sudo update-grub`, and reboot. This is not an app early-boot kill switch.

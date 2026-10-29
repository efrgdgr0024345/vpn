# IPv4-only Kali setup

The owner's lab is reachable again after provider billing recovery. A stalled
login while the VPN server was suspended does not establish an IPv6 fault.
The owner separately requested IPv6 disabled entirely on Kali.

First stop the VPN and restore normal networking. Install the reviewed transport
helper update described in `vpn-dashboard/INSTALL.md` before disabling IPv6.
It ignores the older server's IPv6 tunnel/route pushes, uses an explicit IPv4
transport, and keeps IPv4 `redirect-gateway def1` locally enforced.

For a reviewed transport helper and updater, verify both independently supplied
SHA256 values before executing:

```sh
sudo /usr/bin/python3 -I -B ops/upgrade_client_transport.py \
  vpn-dashboard/vpn_session_helper.py VERIFIED_HELPER_SHA256
```

The updater recognizes the earlier protected transport by its known SHA256 and
checks the public-code manifest, metadata and process/action locks before writes.
It updates only that helper and its manifest entry; unknown modifications are
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

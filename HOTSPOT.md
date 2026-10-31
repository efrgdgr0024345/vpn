# Temporary iPhone hotspot through the Kali VPN

The owner selected sharing the laptop's one VPN connection. The iPhone uses Wi-Fi;
it does not import a VPN profile or run a VPN app. The server continues to see
Kali's existing single connection and certificate identity. The phone's local
hotspot address is `10.77.0.x`, with gateway `10.77.0.1` and DNS `172.27.240.1`.
No iPhone VPN icon is expected for this arrangement.

The observed adapter advertises one managed Wi-Fi connection plus one AP on a
single channel. `ops/vpn_hotspot.py` discovers the current radio/channel itself,
refuses unavailable, DFS/no-IR or unsupported channels, and never retunes the
upstream Wi-Fi or changes regulatory settings. The laptop needs an independent
Wi-Fi internet source. Advertised capability does not replace testing the actual
driver/radio on the owner's machine.

## Protection and lifecycle

- The runtime AP is `vpn-ap0`, with WPA2-CCMP and a new 192-bit random password
  each run, client isolation, WPS disabled and at most one associated station.
- The controlled DHCP service advertises only the private VPN DNS. Both ordinary
  UDP and TCP DNS requests are redirected there. Encrypted DNS in applications
  is not decoded or represented as a plaintext DNS observation.
- Forwarding permits IPv4 only from the AP subnet to `tun0`, plus established
  replies to that subnet. NAT masquerades only onto `tun0`. There is no rule
  permitting AP traffic onto the upstream Wi-Fi or Ethernet interface.
- Exact gateway rules live inside the app-owned `vpn_guard`, whose other chains
  retain default drop. The normal session helper accepts either the exact old
  guard or the complete gateway guard; unknown additions still fail inspection.
- Kernel IPv6 disablement is required before startup. Restore normal networking
  refuses while `vpn-ap0` exists, avoiding accidental removal of protection while
  the phone can still send traffic.
- DHCP runs as the dedicated nonlogin `vpn-hotspot` user, with DNS service disabled
  and no persistent lease file. Hostapd has the radio privileges it requires.
  Configuration containing the Wi-Fi password is root-only under `/run`.
- On VPN/service/route/channel failure or Ctrl+C, cleanup stops the AP before the
  owned VPN process, removes only its virtual AP and runtime NM configuration,
  restores the previous IPv4-forwarding value, then restores normal laptop
  networking only after cleanup/ownership checks succeed. An uncertain cleanup
  preserves state for review and does not claim protection or successful restore.

**Turn off iPhone mobile data during the VPN-only test.** The laptop cannot stop
the phone independently switching to its own cellular connection.

## Controlled startup

The verified runner downloads no private profiles and embeds no VPN password. It
uses the existing root-only `/etc/vpn-desk/testing-login.txt`. It first checks the
protected installed baseline and radio, then requests a normal stop of only the
same desktop owner's existing session. A narrow known-baseline update changes
only the three guard/network modules and their code-manifest entries; the existing
IPv4-capable transport helper remains unchanged. This code update and the dedicated
account persist. The hotspot, forwarding setting and NM override are temporary;
no boot service, radio profile, system-wide DNS or unrelated firewall migration is
installed by the hotspot mode.

Distribution dependencies are `hostapd`, `dnsmasq-base`, `iw` and optionally
`qrencode`. The runner prints a Wi-Fi QR code when qrencode is installed. Package
installation is a separate visible apt action; distribution package scripts can
start services. The actual hotspot programs run directly under the foreground
runner rather than enabling their generic services.

Keep its terminal open. The phone joins `VPNDesk-iPhone` by scanning the local QR
code or using the printed random password. Ctrl+C stops the session. Do not paste
that password, profiles or private logs into chat or GitHub. The existing offline
recovery command remains:

```sh
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore
```

Stop the hotspot/VPN first. If cleanup cannot verify that its virtual AP is gone,
restore deliberately refuses; report the fixed error and review the state.

## Verification

Unit regressions cover exact gateway/legacy guard recognition, rejection of a
physical fallback or missing DNS redirects, radio restrictions, private generated
configuration, fixed source hashes, scoped upgrades and AP-before-VPN cleanup.
The disposable packet fixture uses fresh network namespaces and real nftables,
dnsmasq, DHCP packets, UDP/TCP DNS redirection, NAT source observation and failed
fallback after route/tunnel removal. It never changes the host network namespace.
Those tests do not claim a real Wi-Fi beacon, iPhone association, sleep/resume or
mobile-data transition has been tested. Owner device acceptance is still required.

# Diagnose a connection without weakening protection

Browser failure alone cannot distinguish a missing tunnel, broken forwarding,
an unanswered DNS request, or a browser-specific problem. The app writes the
private resolver configuration before starting OpenVPN, under the kill switch.
Until the tunnel is initialized, ordinary internet and DNS can be unavailable.
That is expected protection during startup, not evidence of an IPv6 fault.

## On Kali, in a second terminal

Keep the connection terminal open. These checks do not change configuration or
print credentials. `example.com` is a fixed public diagnostic name.

```bash
ip -brief address show tun0
ip -4 route get 172.27.240.1
awk '/^nameserver[[:space:]]/{print}' /etc/resolv.conf
if ip -4 route get 172.27.240.1 | grep -q 'dev tun0'; then
  if command -v dig >/dev/null; then
    dig @172.27.240.1 example.com A +time=3 +tries=1
  fi
  timeout 8 getent ahostsv4 example.com
fi
```

- No `tun0` or no initialized event: diagnose authentication/TLS/transport first.
- DNS route uses Wi-Fi: the required tunnel route is missing or overridden.
- Direct query times out: private DNS or the tunnel/authorization path may be
  unavailable; a timeout does not identify which end dropped the packet.
- Direct query returns SERVFAIL/REFUSED: a DNS service replied with an error;
  inspect resolver health/upstream resolution/access policy on the VPS.
- Direct query succeeds but `getent` fails: inspect the OS resolver configuration
  and its local resolution services.
- Both succeed but the browser fails: next inspect forwarding, MTU and browser
  proxy/encrypted-DNS settings. Do not change browser settings without evidence.

The automatic **Session log / audit** check separates private DNS health from
tunnel initialization and stays bound to `tun0`. It never falls back to LAN DNS.
Neither this check nor a green OpenVPN message is a full leak test.

## Inspect the server from an unaffected connection

The GitHub administrator can run `diagnose-connection` independently of Kali's
internet access. Start with a server baseline while Kali is disconnected, then
capture another report during a failed connected lookup. The dedicated root SSH
grant must still be valid. Do not require the owner to open the provider's web
console through a failing VPN connection.

The fixed read-only report checks Unbound/OpenVPN/broker state, DNS listeners,
the local resolver response, and the kernel forwarding lease for the connected
device. Its firewall counters help locate a query that reaches the server but
is dropped. No second connection to OpenVPN's management socket is made: the
authorization broker owns that channel.

`test-foundation` separately performs real TLS/PAM and packet tests on the live
server, with credentials retained locally. Its test client connects over server
loopback; it does not establish the physical Kali or external Internet path.
It temporarily uses the single VPN slot and exercises revocation/handover, so it
must be coordinated with the owner. `probe-udp` tests external UDP arrival only,
not an external client's TLS authentication. See GITHUB_LAB.md.

## Recover ordinary internet deliberately

Press Ctrl+C in the original connection terminal and wait for the session to
stop, then run on Kali:

```bash
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore
```

The same action is available as **Restore normal networking** in the app.
Do not flush unrelated firewall rules or add public DNS servers as a workaround.
The guard intentionally remains enabled after failure or disconnect.

## Changing Wi-Fi networks still needs review

The installed policy pins a DHCP server, and recovery saves the pre-connection
resolver. A move to a different LAN can make either value obsolete. The gateway
address alone does not establish the actual DHCP server. On ordinary internet,
read the current lease without printing SSIDs or credentials:

```bash
nmcli -g DHCP4.OPTION device show wlan0 |
  tr '|' '\n' |
  awk '/^[[:space:]]*dhcp_server_identifier[[:space:]]*=/'
```

Review changed lease/resolver details before updating protected policy or its
firewall baseline. DNS health reporting does not implement automatic roaming
or silently rewrite saved recovery ownership.

The checked updater supports `--dhcp-server` for a reviewed lease change. It
requires inactive VPN/guard state, the configured Wi-Fi/default IPv4 route and
the same explicit NetworkManager DHCP identifier at preflight and commit. It
changes only that policy field and the complete derived private candidate,
publishing the inert candidate first and policy last with private `0600` modes.
Unknown candidates are refused; the recognized interrupted pair can resume.
Profiles, credentials and live routes/DNS/firewall are preserved. The update
must not be used while saved app network state still requires restoration.

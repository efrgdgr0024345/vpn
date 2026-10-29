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

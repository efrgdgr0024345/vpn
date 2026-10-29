# Connection diagnostics

Use **Session log / audit** for connection troubleshooting. The main dashboard's
**Copy safe log** is a redacted local OS snapshot; it does not explain the last
OpenVPN handshake failure. The terminal and session viewer now show the actual
server IP/port and IPv4 protocol, physical interface/source/gateway, local socket
port when observable, expected TLS name, engine/library versions, negotiated TLS
and cipher names, tunnel address/MTU, mssfix, DNS configuration and local route
checks. Missing values are explicitly "not observed" in the viewer/export.

Network addresses are intentionally included at the owner's request. No external
IP-check service or telemetry is used. Route lookups are local kernel queries;
the logger does not send connectivity probes. The configured DNS target and a
matching resolver file do not establish that a DNS query succeeded.

## Expected sequence

This is an illustration, not a captured client session:

```text
VPN server IP: 203.0.113.10
VPN server port: 1194
Transport: udp4
Physical interface: wlan0
Local IPv4: 192.0.2.20
Local socket port: 49152
Expected TLS certificate name: VPNLabServer
Negotiated TLS: TLSv1.3
Control-channel cipher: TLS_AES_256_GCM_SHA384
Data-channel cipher: AES-256-GCM
Tunnel interface: tun0
Tunnel IPv4: 172.27.240.10
Tunnel MTU: 1500
Configured mssfix: 1300
Configured VPN DNS: 172.27.240.1
DNS file matches managed configuration: True
IPv4 route lookup interface: tun0
Both IPv4 full-tunnel /1 routes observed: True

(+0.000s) Checking the protected profile, local interfaces and existing network controls.
(+0.100s) The configured firewall baseline passed its startup check.
(+0.200s) Contacting the VPN server over IPv4; waiting for a reply.
(+0.300s) The VPN server replied; TLS negotiation is in progress.
(+0.400s) The configured TLS peer verification succeeded.
(+0.500s) An encrypted TLS control channel was negotiated.
(+0.600s) OpenVPN is configuring the tunnel interface or IPv4 routes.
(+0.700s) OpenVPN initialized the tunnel; DNS and leak behavior still require validation.
```

Actual events include UTC timestamps and elapsed time from the helper's local
monotonic clock. Details are observed at startup or their most recent reported
stage, not continuously audited. Tunnel initialization is not a leak test.

## Failure and recovery

The helper distinguishes no recognized server reply, TLS/authentication failure,
configuration rejection, kernel offload trouble and route setup errors. A startup
deadline of 60 seconds starts with transport activity; a three-minute overall
deadline includes credential entry. Retries cannot keep resetting these budgets.
After an established connection drops, its reconnect gets a fresh bounded budget.
The helper stops only its owned process using its Linux process descriptor.
It preserves the kill switch and prints recovery instructions.

OpenVPN's numeric exit status is retained. A graceful process exit of 0 after a
timeout is not successful connection establishment: the recorded attempt remains
an error and the helper returns failure. The last failure survives cleanup.

The latest attempt, including stage checkpoints, is stored under
`/var/lib/vpn-desk-history/<desktop-uid>.json`, bounded to 300 events and 128 KiB.
Root owns the record. A Linux POSIX read ACL permits only its desktop owner to
read it; the owner cannot overwrite it and other ordinary users cannot read it.
Unsupported ACL storage reports an OS error and retains terminal/live viewing;
it does not fall back to a broadly readable or user-writable history file.

The viewer prefers the authenticated live Unix helper. When that helper exits,
it labels the root-written record **Saved last attempt**. Saved history does not
describe current network state after disconnect/restoration. Root can still alter
local records; this is not a cryptographically attested or remote audit service.
Exports are private owner-only files and include network addresses. Passwords,
tokens, private keys, inline certificates, pushed configuration and arbitrary raw
server text are excluded by typed schemas and bounded parsing.

After a failed attempt, stop the VPN, use **Restore normal networking**, reopen
the session log and save its report. The report includes the protected terminal
recovery command as well. Do not disable verification or flush unrelated rules.

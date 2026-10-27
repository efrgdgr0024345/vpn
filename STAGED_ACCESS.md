# Single-tunnel staged VPN access

This implements the owner's selected direct-device design. Deployment evidence
is recorded separately in deployments/vpn-lab.json; source does not prove that a
server or phone has been updated.

## Authentication and authorization

1. OpenVPN verifies TLS 1.3, the server identity, a CA-valid client certificate
   and possession of its private key. TLS control traffic is also encrypted.
2. The distribution PAM plugin checks the known VPN username/password. The
   broker independently checks that the verified leaf certificate's SHA256
   fingerprint and common name match an administrator-enrolled device.
3. Admission reserves one global slot but grants no forwarding. After OpenVPN's
   `ESTABLISHED` event, the broker binds the grant to that daemon-assigned client
   ID and the device's fixed VPN address. An unrelated event cannot inherit it.
4. OpenVPN issues its standard hidden HMAC authentication token. Subsequent TLS
   renegotiations use the token instead of asking for the known password.
   Tokens renew at 120 seconds and have a maximum 24-hour lifetime. They are
   reusable within that session, not one-time passwords. Restarting the server
   changes its in-memory signing secret; no persistent token-secret file exists.
5. On disconnect, forwarding is removed before another device can own the slot.
   A new login cannot evict the active owner. An old token alone cannot create a
   fresh broker admission: establishment without an approved pending client ID
   is killed without receiving a forwarding grant.

The server pushes explicit exit notification for prompt voluntary release.
An abrupt loss of power/connectivity still needs OpenVPN's dead-peer detection
(up to its 60-second keepalive timeout). A competing login must not shorten that
timeout by taking over; independent administrator reset remains available.

A token-only reconnect receives `AUTH_FAILED,SESSION`, instructing clients to
discard the old token and use initial authentication again. Revocation/expiry
uses a `HALT` message so a disabled session does not enter an automatic retry
loop. Phone-specific handling of these messages is part of device acceptance.

The two stages occur within one tunnel; there is no account/password rotation
and no second tunnel. The restricted stage is the authentication phase with no
data forwarding, rather than a browser-accessible bootstrap network. Standard
certificate proof is the independent factor; the token itself is not another
factor. There is no extra interactive MFA challenge in this version.

## Fail-closed packet enforcement

The nftables `authorized` set holds at most one IPv4 address with a **20-second
kernel timeout**. Both forwarding directions, including established NAT flows,
require membership. OpenVPN bytecount/liveness notifications refresh the grant
every three seconds, only for the current client ID. Silence for more than 12
seconds, device revocation, identity replacement or the 24-hour monotonic session
limit removes forwarding and asks OpenVPN to end the session. Ownership is not
released until a matching disconnect arrives.

If the broker freezes or dies without cleanup, the kernel grant expires within
20 seconds of its last refresh. Access does not necessarily stop instantly.
Normal broker exit clears it immediately; management disconnect also triggers
an OpenVPN soft restart and hold. Broker restart starts with an empty set and
does not restore an owner from disk. Server restart also begins with no grant.
There is no wall-clock deadline that can be extended by setting the clock back.
OpenVPN handles certificate validity and token timestamps separately.

Source addresses other than the assigned grant, private/reserved destinations,
cloud metadata, host services and IPv6 forwarding are denied. No client-to-client
shortcut is configured. The exclusive global OpenVPN limit remains one.

## Trust boundary and device administration

The broker reads identities only from the root-controlled local Unix management
socket, with OpenVPN enforcing `management-client-user root`. It has no TCP/HTTP
listener. The source is root-owned; systemd limits the broker to NET_ADMIN,
Unix/netlink sockets and a protected filesystem. It discards password/token
environment fields and emits no raw management messages to journals.

`/etc/openvpn/lab/devices.json` pins three separately generated certificates:
`kali`, `iphone`, and `android`, with addresses .10, .11 and .12. Admission does
not offer enrollment or key replacement. Installer reruns preserve existing
identities, password and disabled states; unexpected identity changes fail.

Manual main-branch workflow operations:

| Operation | Result |
| --- | --- |
| `device-status` | Return device names, enabled flags and public certificate fingerprints. |
| `revoke-device` | Disable the selected device and close outstanding profile-download access. The broker removes its active grant on its next one-second policy check, or the kernel timeout bounds access if the broker is frozen. |
| `enable-device` | Explicitly allow the existing device identity again; does not replace its key. |
| `reset-sessions` | Flush forwarding first and restart the VPN and broker, invalidating session tokens. |
| `reboot-lab` | Schedule a reboot of the disposable lab for actual boot/recovery validation. |
| `prepare-download` | Export only the selected device's profile/login through the existing expiring read-only SFTP sandbox. |
| `close-download` | Remove new download access and private export copies. |

Mutations and the disruptive packet self-test require successful CI for the
exact workflow commit. Recovery remains available through the provider console.
For an emergency console reset:

```sh
nft flush set inet vpn_lab authorized
systemctl restart openvpn-server@vpn-lab.service
```

Device certificates expire after 90 days; renewal/replacement is still an
administrator task. A lost device should remain disabled until a new identity
is explicitly provisioned; merely enabling its old key is not replacement.

## Validation and remaining limits

Unit tests exercise competing reservations, mismatched pins/names, token-state
rejection, late establishment, stale disconnect/liveness events, expiry,
revocation and malformed management input. Real integration uses separate
Debian server/DNS containers, native PAM/OpenVPN/nftables, actual certificate
keys, private token observation and unconfigured client TUNs. The packet test
also freezes the broker to verify expiry without a cleanup handler, attempts
old-token replay, transfers access to a different enrolled certificate, and
checks normal disconnect releases ownership promptly for the third identity.

The live self-test uses protected credentials locally, temporarily changes and
restores test device policy, and deliberately disrupts its own sessions. Run it
only on the disposable lab when no human is using it. It never exports private
credentials or changes host default routes/resolver settings.

Hardware-backed device keys, physical mobile clients, suspend/roaming behavior,
client DNS/IPv6/kill-switch enforcement and reboot recovery require separate
validation. Server-generated exportable keys prove possession of an approved
key, not the identity of physical hardware. Root compromise or malware on an
approved connected device remains outside what credential handoff can prevent.

OpenVPN protocol references: [management interface](https://github.com/OpenVPN/openvpn/blob/v2.6.14/doc/management-notes.txt)
and [session-token options](https://github.com/OpenVPN/openvpn/blob/v2.6.14/doc/man-sections/server-options.rst).
OpenVPN, its PAM plugin, TLS and HMAC token mechanism remain upstream work;
see THIRD_PARTY_NOTICES.md.

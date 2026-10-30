# Disposable Debian 13 VPN foundation

The owner authorized reusing the lab droplet and removing obsolete services.
The separate working OpenVPN Access Server is not modified. The lab uses
OpenVPN Community and distribution packages, not Access Server.

## GitHub Actions operations

Use the manual `Lab server administration` workflow on `main`, with the `vpn-lab`
environment and pinned provider-console host fingerprint:

Installation additionally requires successful functional and security push-CI for the exact
deployment commit. Missing, failed or unverifiable CI status blocks installation
before the SSH secret is supplied to the administration job.
The same gate protects download/device mutations, session reset and the
disruptive live packet self-test.

| Operation | Effect |
| --- | --- |
| `inventory` | Approved read-only OS, ports, services and firewall summary. |
| `ipv4-only-status` | Read current tunnel, firewall, interface and kernel IPv6-disablement status without changing configuration. |
| `enable-ipv4-only` | Narrow migration of the existing lab to IPv4, preserving certificates, credentials and unrelated live rules. Requires an idle VPN and matching CI. A separate server reboot is required for the kernel argument. |
| `install-foundation` | Install/update required Debian packages; retire old self-hosted runner services; provision credentials and PKI; apply the dedicated default-drop firewall; persist and start the VPN, broker and private recursive DNS services. |
| `test-foundation` | Use protected local credentials to test the real running VPN. Credentials stay on the server. No desktop/client installation is performed. |
| `probe-udp` | Confirm runner-originated UDP 1194 packets reach the external interface, using a random nonce and a short-lived packet listener. |
| `device-status`, `revoke-device`, `enable-device`, `reset-sessions` | Device enrollment status, revocation and independent recovery; see STAGED_ACCESS.md. |

Host addresses are workflow inputs, not committed source settings. Source,
configuration generators, tests, acknowledgement notices and setup instructions
are in the repository. Keys, passwords and real exported profiles are excluded.
The deployed source commit is recorded in `/etc/openvpn/lab/state.json`.

## Security and behavior

- Exactly one permitted VPN account, `vpn-lab-client`, with a 256-bit randomly
  generated password and a required separately enrolled device certificate. PAM explicitly
  rejects other operating-system accounts; sshd explicitly denies SSH to the
  VPN credential and transport accounts, including forwarding/SFTP paths.
- TLS 1.3 minimum, AEAD data ciphers, TLS control-channel encryption, no
  compression, a named nonlogin transport account, native PAM privilege
  separation, certificate-name verification and a public readable CRL. Private
  PKI/configuration directories and exports are root-only.
- `max-clients 1` limits concurrent VPN sessions. The packet test checks that
  another valid login does not displace the first. Contention can also be caused
  by stale sessions; it is not itself proof of intrusion.
- OpenVPN issues a hidden authentication token after login, with a 24-hour
  maximum lifetime and 120-second renewal/renegotiation. A separate root-local
  broker pins the enrolled device and authorizes a single established session.
  Kernel packet grants expire after 20 seconds without broker refresh. There is
  no second tunnel, custom cryptography or rotating operating-system account;
  see STAGED_ACCESS.md for the state machine, revocation and token-replay policy.
- Server nftables rules default-drop input and forwarding. Recovery SSH and the
  VPN transport remain available on the external interface, with loopback,
  established replies, DHCP and ICMP exceptions. VPN forwarding permits public
  IPv4 internet traffic through NAT and blocks private/reserved networks and
  cloud metadata. The current generator uses IPv4-only tunnel settings and early
  IPv6 drops in input, forwarding and output. Existing deployments need the narrow
  migration above; see IPV4_ONLY.md for actual deployment and reboot status.
  The host's own outbound IPv4 package/management traffic is allowed.
- The private Unbound resolver binds only to the VPN address. Authorized VPN
  clients can query UDP/TCP 53; no public recursive listener is opened. Production
  resolves recursively using distribution DNS root trust data, with no public
  forwarding resolver and no query/reply logging. Public-name resolution still
  depends on root/authoritative DNS infrastructure.
- Installation intentionally replaces the disposable server's firewall after a
  kernel syntax check. A root-only pre-change firewall snapshot is retained at
  `/root/vpn-lab/recovery/nftables.before`. SSH administrative settings and keys
  are preserved; only denial of the VPN-specific accounts is added and validated.
- Old `actions.runner.*.service` workers are stopped as a group, disabled and
  masked. Registration credential files are removed without reading them when
  their working-directory ancestry is safely root-owned. No other GitHub
  repository registrations or services are changed remotely.
- Native systemd service sandboxing, a restart policy, protected filesystems,
  restricted namespaces/address families and disabled core dumps are applied.
  Distribution package signatures, TLS checks and host identity checks stay on.

## Local credential files and recovery

The owner retrieves `/root/vpn-lab/client.ovpn` and `/root/vpn-lab/login.txt`
privately using their own administrative access. Both are 0600. `login.txt`
contains the VPN username followed by the password, on separate lines. Do not
paste either file into chat or store it in GitHub logs, artifacts or source.
The installer reuses existing credentials/PKI on a same-settings rerun instead
of silently resetting them. Changes to the endpoint/SSH port require review.

Separate device profiles/login files live under `/root/vpn-lab/devices/kali`,
`iphone` and `android`. Mobile profiles use portable `dev tun`; never import one
device's identity on another. The workflow `device` input selects which profile
is copied into the temporary download sandbox. Disabled devices cannot export.

For owners using only the provider console, `prepare-download` accepts a public
ED25519 key generated on their own computer. The key's private half never leaves
that computer. A separate `vpn-lab-download` account is forced into read-only
internal SFTP, with forwarding/TTY/shell access disabled and a root-owned chroot
containing only `client.ovpn` and `login.txt`. The account cannot read the server's
administrative keys, PKI or other files. Its public-key grant expires after 24
hours. `close-download` deletes that key and the private export copies once the
owner finishes; it prevents new logins rather than invalidating already copied
VPN credentials or forcibly terminating an established SSH connection.

Root/provider-console recovery remains independent of VPN access. Stopping
`openvpn-server@vpn-lab.service` closes VPN access immediately. A password-only
account lock need not revoke a previously issued authentication token: stop or
restart the VPN service when revoking an active session. Certificate revocation
uses Easy-RSA and the protected PKI; copy the regenerated CRL to the service's
public CRL path before admitting clients again.

Lab certificates expire after 90 days; the generated CRL lasts 365 days. This is
a lab foundation, not an unattended long-term certificate-renewal system. The
GitHub administrative SSH grant independently expires after 24 hours and can be
renewed using the verified console bootstrap documented in GITHUB_LAB.md.

## Actual tests and limits

`ci/test_server_container.sh` runs the installer in isolated Debian 13 containers
with an explicit TUN device and NET_ADMIN capability. A separate container
simulates a public DNS server, with no published host ports. Real OpenVPN, PAM,
Easy-RSA certificates, nftables and NAT are used. Reinstallation must preserve
the profile and credentials.

`server_selftest.py` checks a wrong password is rejected, correct credentials
connect, actual DNS packets traverse the encrypted tunnel and IPv4 NAT, cloud
metadata/private packets hit the drop rule, IPv6 tunnel configuration is absent,
early IPv6 drop rules cover all three base chains, and a different enrolled device
does not displace the active session. These configuration checks are not an
external IPv6 leak test or proof the kernel boot parameter is active.
It also tests unapproved pins, actual token reauthentication, old-token replay,
a frozen broker's kernel timeout, ownership transfer and device revocation.

The local test creates temporary unconfigured TUN devices and uses AF_PACKET;
it does not change the host's default routes, addresses or resolver. Private
test profiles/logs are deleted afterwards and never exported to the runner.

The separate `probe-udp` check demonstrates arrival through the public cloud
network without exporting any VPN credential. It does not perform an external
client TLS handshake. These checks do not demonstrate a physical Kali client
integrates its DNS correctly, a desktop kill switch works, or the server survives
reboot. A normal Linux CLI client does not apply
pushed DNS options on its own. Those checks are separate before moving daily
traffic. The selected single-tunnel broker is documented in STAGED_ACCESS.md;
the earlier literal two-tunnel handoff is not the selected implementation.

## Credits

See THIRD_PARTY_NOTICES.md. The installed package-version ledger is
`/usr/local/share/doc/vpn-lab/package-versions.txt`; distribution copyright files
remain installed. Upstream code is not relicensed or claimed as this project's.

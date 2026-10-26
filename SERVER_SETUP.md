# Disposable Debian 13 VPN foundation

The owner authorized reusing the lab droplet and removing obsolete services.
The separate working OpenVPN Access Server is not modified. The lab uses
OpenVPN Community and distribution packages, not Access Server.

## GitHub Actions operations

Use the manual `Lab server administration` workflow on `main`, with the `vpn-lab`
environment and pinned provider-console host fingerprint:

Installation additionally requires a successful push-CI run for the exact
deployment commit. Missing, failed or unverifiable CI status blocks installation
before the SSH secret is supplied to the administration job.

| Operation | Effect |
| --- | --- |
| `inventory` | Approved read-only OS, ports, services and firewall summary. |
| `install-foundation` | Install/update required Debian packages; retire old self-hosted runner services; provision credentials and PKI; apply the dedicated default-drop firewall; persist and start the OpenVPN service. |
| `test-foundation` | Use protected local credentials to test the real running VPN. Credentials stay on the server. No desktop/client installation is performed. |
| `probe-udp` | Confirm runner-originated UDP 1194 packets reach the external interface, using a random nonce and a short-lived packet listener. |

Host addresses are workflow inputs, not committed source settings. Source,
configuration generators, tests, acknowledgement notices and setup instructions
are in the repository. Keys, passwords and real exported profiles are excluded.
The deployed source commit is recorded in `/etc/openvpn/lab/state.json`.

## Security and behavior

- Exactly one permitted VPN account, `vpn-lab-client`, with a 256-bit randomly
  generated password and a required matching client certificate. PAM explicitly
  rejects other operating-system accounts; sshd explicitly denies SSH to the
  VPN credential and transport accounts, including forwarding/SFTP paths.
- TLS 1.3 minimum, AEAD data ciphers, TLS control-channel encryption, no
  compression, a named nonlogin transport account, native PAM privilege
  separation, certificate-name verification and a public readable CRL. Private
  PKI/configuration directories and exports are root-only.
- `max-clients 1` limits concurrent VPN sessions. The packet test checks that
  another valid login does not displace the first. Contention can also be caused
  by stale sessions; it is not itself proof of intrusion.
- Standard OpenVPN authentication tokens expire after 900 seconds and TLS
  renegotiates every 300 seconds. These maintained mechanisms are not the
  proposed staged-login broker or rotating-account handoff.
- Server nftables rules default-drop input and forwarding. Recovery SSH and the
  VPN transport remain available on the external interface, with loopback,
  established replies, DHCP and ICMP exceptions. VPN forwarding permits public
  IPv4 internet traffic through NAT and blocks private/reserved networks and
  cloud metadata. IPv6 forwarding is denied, with client IPv6 blocking pushed
  through the VPN. The host's own outbound package/management traffic is allowed.
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
metadata/private packets hit the drop rule, IPv6 generates a client block
response, and a second login does not displace the active session.

The local test creates temporary unconfigured TUN devices and uses AF_PACKET;
it does not change the host's default routes, addresses or resolver. Private
test profiles/logs are deleted afterwards and never exported to the runner.

The separate `probe-udp` check demonstrates arrival through the public cloud
network without exporting any VPN credential. It does not perform an external
client TLS handshake. These checks do not demonstrate a physical Kali client
integrates its DNS correctly, a desktop kill switch works, or the server survives
reboot. A normal Linux CLI client does not apply
pushed DNS options on its own. Those checks are separate before moving daily
traffic. The staged broker, enrolled-device authorization, exclusive expiring
grant and automated handoff in NEW_VPN_DESIGN.md remain subsequent work.

## Credits

See THIRD_PARTY_NOTICES.md. The installed package-version ledger is
`/usr/local/share/doc/vpn-lab/package-versions.txt`; distribution copyright files
remain installed. Upstream code is not relicensed or claimed as this project's.

# Mobile support and the single-session requirement

The owner subsequently requested our own application and rejected third-party
VPN frontends/plugins. The stock OpenVPN Connect proposal below is historical.
Kali is the current implementation in OWNED_CLIENT.md. Native iPhone/Android
apps are not implemented; they will require their platform VPN APIs, an auditable
transport library, licensing review and actual signing/device tests. Standard
server profile support does not establish that those native apps exist.

The owner approved direct device connections and single-tunnel staged access.
The implementation uses ordinary OpenVPN profiles and session tokens rather
than a custom mobile app. Physical iOS/Android testing remains necessary; server
and Linux-client tests cannot establish phone app behavior.

## Confirmed policy

- One main VPN session may exist across the account, including computers,
  iPhones and Android devices. Enrolling more devices does not add session slots.
- A new login must not evict the existing owner.
- A restricted entry session has no general internet access and cannot reserve
  the main slot without proving an independently enrolled device identity.
- Recovery remains independent through the provider console.
- Server/container validation precedes asking the owner to test locally.

## Two different ways another device can use the system

**Share a gateway.** A router or supported computer holds the one main tunnel.
Other devices use that gateway. The server sees one VPN session; that is not a
guarantee of one physical end device. The gateway needs its own forwarding,
DNS/IPv6 and fail-closed firewall validation. Phone hotspot traffic must not be
assumed to inherit the phone's VPN. A dedicated VPN router is the recommended
starting point for sharing across several devices.

**Transfer ownership.** A separately enrolled phone or computer becomes the
main VPN client after the current owner releases its session. Releasing or
transferring ownership must be an authenticated operation, not a consequence of
someone else knowing the entry password. Packet forwarding for the old owner
must end before forwarding for the next owner begins. Failure leaves access
denied; it must not create two active owners.

The selected behavior is direct enrollment with disconnect-before-transfer.
Gateway sharing is not part of this implementation. A VPN server cannot stop
an authorized client deliberately forwarding traffic for another device; the
enforced limit is one authorized VPN session, not one physical end device.

## Staged access on mobile

Use a single tunnel with server-enforced restricted and active states. This
avoids requiring a phone to run overlapping packet tunnels and reduces routing
and resolver transitions. Conventional OpenVPN session tokens can remove the
need to type a second password, but issuing such a token alone is not an
authorization broker or an independently verified second factor. The broker
therefore separately pins each approved device certificate and gates packet
forwarding only after OpenVPN reports authentication and session establishment.
Entry here means the TLS/PAM admission phase with no forwarding at all, not a
connected browser portal. The broker has no client-reachable network listener.

A literal automatic handoff between two distinct tunnels is a different client
feature. Do not promise that importing two profiles into a stock phone app
implements it. It may require custom VPN app integration and platform-specific
distribution. Likewise, a server configuration alone cannot establish an
iPhone/Android kill switch, unattended reconnect or hotspot containment.

Before calling mobile support complete, test profile import, device identity,
token handling, session contention, Wi-Fi/mobile-data changes, sleep/resume,
disconnect/reconnect, DNS/IPv6 behavior and forwarding denial during every
transition on each supported platform. Server tests cannot substitute for
those device tests. Keep private profiles, keys and passwords out of GitHub
source, Actions artifacts and chat.

Profiles under `/root/vpn-lab/devices/iphone` and `android` use portable `dev tun`
and separate EC client keys; Kali retains its protected-install `tun0` profile.
Enroll/import through private transfer, never GitHub artifacts or chat. Revoke
the corresponding device through the lab workflow if a phone is lost. Device
keys currently originate on the server and are exported in protected profiles;
they are not hardware-attested or guaranteed nonexportable. An imported profile
is a secret, and sharing it defeats the device-identity policy.

The intended stock client is OpenVPN Connect on iPhone and Android. Profile
import, background behavior, credential caching, DNS, IPv6, switching networks
and platform VPN-lockdown settings must be checked on real devices. No claim of
an iOS equivalent to Android always-on/lockdown follows from this server setup.

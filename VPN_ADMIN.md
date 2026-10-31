# Private VPN administration panel

The first version is a read-only panel for the owner's working single-session
VPN. Deployment evidence is recorded separately in `deployments/admin-panel.json`.
The target address after HTTP deployment is
`http://172.27.240.1:8080`. It is reachable only through an authorized VPN
connection and requires a separate administrator password.

## What it shows

- OpenVPN, authorization broker and private DNS service health.
- A server-side private DNS probe and tunnel status.
- Registered device names, enabled flags and public certificate fingerprints.
- Sampled forwarding authorization for the single permitted VPN address.
- Server kernel IPv6-disablement observations.
- Bounded, typed service/authorization changes observed since collection started.
- Searchable private destination-IP/port and plaintext DNS-query metadata, with
  device address, first/last timestamps, protocol and reply-observed status.

This is not a raw journal viewer or a complete intrusion log. Short events between
samples may be missed; service-change history is in memory and resets with the
status collector. Network history is separately persisted as described below. Stale
or unavailable observations become unknown. A sampled authorization badge expires
using its remaining kernel lease and the full observation age; it is not proof
of physical device identity or continuous traffic forwarding.

This version has no remote shell, password/profile export, device mutation,
service restart or VPN-disconnect API. The owner was asked which management
controls should follow the status view. No extra simultaneous VPN slot is added.

## Privilege and network boundaries

`vpn-admin/server.py` runs as the dedicated nonlogin `vpn-lab-admin` account with
no capabilities. It reads only protected application configuration, its password
verifier and a validated public status snapshot, plus read-only access to the private
network-metadata database.
It never imports root administration helpers, reads VPN credentials, accesses the
OpenVPN management socket, or executes a command supplied by an HTTP request.

The separate root collector uses the existing bounded diagnostics and protected
device registry. It publishes an atomic root-owned, group-readable snapshot under
`/run/vpn-lab-admin`; no raw journals, tokens, private keys or credentials enter it.
Its sample age begins before the diagnostics commands and DNS probe, so slow
collection cannot make an expired lease appear fresh.

The installer adds one narrow rule to the existing input chain, before the VPN
host-drop rule: authorized source on `tun-lab`, destination `172.27.240.1`, TCP
8080. Every packet needs the current kernel authorization grant. It never flushes
the live ruleset, changes VPN credentials/PKI, or restarts OpenVPN, its broker or
Unbound. It verifies those daemon identities remain unchanged. A future full
foundation reinstall refuses an installed panel until its firewall is reviewed.
Only the three panel services are enabled/restarted.

## Network history and retention

The owner chose **30 days with a storage cap**. The separate observer passively
reads IPv4 packets on `tun-lab` using an AF_PACKET socket. It records source and
destination addresses/ports, protocol, byte counts and timestamps; plaintext DNS
questions additionally record domain and numeric query type. Packet bodies are
parsed transiently for DNS and are never written to storage. The observer has
`CAP_NET_RAW`; the web process has no capabilities, no packet socket and no
write access to history. The observer is a trusted privileged component, not a
sandbox that can safely execute arbitrary code. Its allowed socket families are
AF_PACKET/AF_UNIX, and its filesystem writes are confined to its state directory.

History lives at `/var/lib/vpn-lab-admin/history.sqlite3` (root:panel, 0640,
directory 0750). It has a 30 MiB SQLite main-file limit, rollback-journal headroom
within a **64 MiB storage budget**, and a 100,000-record cap. Old records are
pruned automatically; capacity may remove them before 30 days. Freed SQLite
pages are reused; this is logical deletion, not forensic erasure from disk,
snapshots or provider backups. Collection begins on installation. Restarts are
counted, and socket drops, queue drops and DNS stream gaps are reported. A fresh
heartbeat confirms the observer loop, not complete capture of every packet.
The writer still prunes when the tunnel is absent; an offline server prunes
when it next starts. If logging is stopped, its retention task is also stopped.

The authenticated `/api/history` endpoint supports device, record type,
domain/IP-prefix, date and cursor filters with bounded parameterized queries.
The table uses browser-local time and explicitly names its timezone; the API
uses UTC timestamps. Page size is at most 200 and the browser retains at most
1,000 displayed rows. History is not included in GitHub reports, workflow
artifacts, source, request logs, or the public status snapshot.

**These are observations, not complete website-visit history.** HTTPS conceals
paths, page contents and credentials. Encrypted DNS, caches, tunnels and proxies
limit domain visibility. DNS queries do not prove visits, and domains are not
guessed from shared destination IPs. IPv4 fragments and incomplete/out-of-order
TCP DNS streams may not be fully parsed. UDP/TCP destination records say
“outbound attempt” or “reply observed”; capture may see an attempt before a
firewall drops it, and a reply does not prove a successful application request.
Device labels map configured VPN addresses and do not attest physical hardware.
The panel's own TCP 8080/legacy 8443 polling is excluded. Raw packet contents, full URLs,
HTTP headers and TLS secrets are never persisted.

## Web authentication

The administrator password is separately generated with 256 bits of randomness.
Its original is root-only at `/root/vpn-lab/admin/login.txt`; the web account gets
only a fixed-parameter scrypt verifier. Obtain that password in the trusted
provider root console and copy it directly into the panel. It is never returned
by HTTP or the GitHub workflow and is never embedded in source.

Sessions use HttpOnly/SameSite=Strict host-only cookies and random tokens,
are bound to the VPN source address, and expire after one hour absolutely or
15 minutes without authenticated requests. Automatic status polling counts as
requests; this is not a promise of logout after 15 minutes of human inactivity.
A fresh successful login retires the previous administrator session.

Login attempts and scrypt concurrency are bounded. State-changing login/logout
requests require the exact HTTP Origin; logout additionally requires a CSRF
token. The server checks Host and fetch metadata, accepts only fixed routes,
bounds HTTP framing/body/header sizes, refuses ambiguous framing and reuse, and
limits simultaneous HTTP requests plus their total connection lifetime. It emits
no generic request/exception logs containing URLs, cookies or credentials.
All assets are local; the content-security policy excludes inline/remote code.

## Open it in your normal browser

The owner explicitly selected **HTTP inside the VPN**. Connect the VPN and open
`http://172.27.240.1:8080` in the normal browser. No CA import, browser helper,
domain name, additional package or separate browser profile is required.
The panel still needs its separate administrator password; it has no username.
Obtain that password in the provider root console:

```sh
cat /root/vpn-lab/admin/login.txt
```

Copy it directly into the panel, never GitHub or chat. The VPN encrypts the
client-to-server transport. There is no additional TLS layer on the inner HTTP
connection; the browser may label the page “not secure”. This setup trusts the
VPN endpoints, their routing and the server. It does not protect traffic after
VPN decryption against a compromised endpoint or privileged server process.

The cookie is named `vpn-admin-http`, has no Domain attribute and deliberately
omits Secure so browsers send it over HTTP. The old HTTPS cookie name is not
accepted. Login remains rate-limited, peer-address-bound and subject to exact
Host/Origin checks, CSRF-protected logout, expiry and the existing kernel lease.
The service binds only to `172.27.240.1:8080`; its web account has no capabilities.

The migration preserves admin credentials and private history. It verifies known
managed files before changing them, replaces only the existing panel firewall
exception in one nft transaction, and confirms the legacy 8443 listener is gone.
Existing TLS files are retained for recovery, but the HTTP service neither loads
nor serves them and cannot access the old leaf private key under its sandbox.
The legacy `ops/open_admin_panel.py` helper is no longer used for this setup.

## Deployment and validation

`install-admin-panel` is a fixed manual main-branch lab operation. Functional and
security checks must pass for its exact source revision before it receives the
existing environment-scoped SSH key. An expired SSH authorization must be renewed
by the owner in the provider root console; no alternate access is attempted.

The installer preserves unknown or modified existing managed files, retains
credentials/certificates on supported retries and checks real account/group
separation. The public code lives under `/opt/vpn-lab-admin` to avoid exposing
unrelated private `/usr/local/libexec` contents. Installation does not broaden
permissions on unrelated ancestors. Its manifest covers public code, static
assets, configuration and service units; it does not claim root-resistant
attestation.

Unit tests cover HTTP/auth/parser boundaries, actual HTTP cookie-jar login,
slow-request deadlines, bounded connections, stale/secret-contaminated snapshots,
collector publication, migration rule validation and preservation of unrelated files. Browser smoke checks use explicitly synthetic data, cover desktop
and mobile layout, strict CSP and lease expiry, and do not establish live VPN
acceptance. The disposable VPN integration additionally exercises the actual
private HTTP endpoint through real OpenVPN/PAM, an unprivileged web UID and the
nftables exception while preserving VPN identities and daemon processes.

Administrator passwords and private history stay outside the Git repository. Live
installation/connection evidence is recorded separately after it exists.

## Client-side verification and destination identity

The server panel cannot establish the laptop's current resolver or firewall
state. `ops/live_vpn_check.py` checks an existing client session without changing
settings. Its `--watch` mode repeats sampled checks; `--json` provides structured
results for a future local display. It requires explicit sudo and the pinned
`DIAGNOSTICS_SOURCE` dependency (the checksum is embedded in the script).
This checker is not yet installed on the owner's Kali machine or wired into a
tray indicator. Its local integrity baseline trusts root and is not remote
attestation. Public exit-IP confirmation, browser proxy/DoH settings and browser
certificate state are not established by its result.

For external websites, browser HTTPS certificate/hostname validation provides
destination authentication. Matching a DNS log with the text entered in a
browser does not establish that the page or server is authentic. Full browser
URL/certificate display requires a browser integration; the VPN sees destination
flows and observable DNS questions, not HTTPS paths or contents. The HTTP choice
for this private panel does not disable HTTPS on external websites.

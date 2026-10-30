# One-attempt Kali diagnostics

This is an explicit troubleshooting action for the lab. It saves the current
test login locally, starts one VPN attempt without a VPN credential prompt,
collects connection and network checks, stops that attempt, and attempts the
explicitly requested restoration of ordinary networking. The ordinary VPN Desk
Connect action continues to use terminal authentication and retain the guard
after disconnect.

Run the checked update and test as the ordinary desktop owner while the VPN is
disconnected and VPN Desk is closed. The update supports the original installed
release; the intervening logging update is not a prerequisite. Downloaded code
must be pinned to a reviewed immutable commit and independently checked hashes
before privileged execution, as with the existing checked updater.

## Credentials

The existing read-only, key-authenticated SFTP export supplies a fresh login
file over host-pinned SSH. Enrollment rejects a device credential copy that
differs from the protected master. Its access expires after 24 hours and can be
closed earlier. The user's SSH private key stays on Kali. An encrypted SSH key
can still request its passphrase; sudo uses the Kali password.

The diagnostic runner validates the private local source and atomically saves
it as `/etc/vpn-desk/testing-login.txt`, owned by root with mode `0600`. It stays
available for another explicit test without retyping the VPN login. It is not
embedded in source, a launcher, command arguments, reports, or GitHub secrets.
Root can read this local plaintext file. Remove it when testing ends or replace
the installation during the planned fresh setup.

OpenVPN initially reads the fixed protected file before dropping privileges.
Test mode retains `auth-nocache`, certificate/server-name validation, disabled
compression and the dedicated transport account. Authentication failure or a
reconnect stops the one-shot attempt. It does not grant the transport account
permission to reread the stored password or loop through authentication retries.

## Report and recovery

The runner checks the protected installed public-code baseline before importing
the application helpers. It reads typed session status from its own root child,
with peer identity checked, and performs bounded network probes. Its report
contains stages, timings, endpoint and local network addresses, TLS/cipher
observations, tunnel and route checks, private DNS results, OS resolution and
HTTPS results. Passwords, authentication tokens, profiles, raw OpenVPN output,
SSID information and arbitrary command output are excluded.

The total attempt and individual network probes are bounded. A failed probe
does not trigger successive reconnects. The report distinguishes authentication
failure, TLS/transport trouble, DNS failure and incomplete cleanup rather than
calling an initialized tunnel an internet or leak-test success.

`--restore-after-test` is mandatory authorization for this diagnostic's return
to ordinary networking. The runner stops only its owned child and restores only
after verifying that the attempt owned the network setup and no OpenVPN process
remains. It reacquires the shared action lock and uses the application's guarded
restore operation. If ownership or cleanup cannot be confirmed, it preserves
the guard and reports that recovery requires attention. It never flushes
unrelated firewall rules or adds a public DNS fallback.

After an interrupted or incomplete test, stop its connection first, then use
**Restore normal networking** in VPN Desk or the existing protected command:

```bash
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore
```

The report includes local network addresses intentionally. Review it before
posting it publicly. Successful checks do not certify the host, browser,
long-term availability, IPv6 configuration or absence of leaks.

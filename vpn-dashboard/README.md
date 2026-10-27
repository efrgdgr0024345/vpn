# VPN Desk: owned local client

Our Kali desktop app controls the local OpenVPN engine through a small protected
helper. It provides Connect/Disconnect, an app-owned runtime firewall/private-DNS
policy, explicit networking restoration, a local session log, an installation
baseline check and a read-only socket viewer. It uses no hosted client account,
analytics SDK or third-party VPN frontend/plugin.

OpenVPN, Python/Tk, Linux and crypto/networking components remain explicit,
auditable upstream dependencies. This is not zero third-party code or a claim
that an app/AI review can prove an OS uncompromised.

Use [INSTALL.md](INSTALL.md) for reviewed installation and controls. Root helpers
and configuration live in protected system paths; there is no sudo fallback to
checkout code or a home profile. Credentials remain in the authentication
terminal. Session events exclude tokens, passwords, private keys and payloads;
exports stay local and private.

This build requires controlled device acceptance before daily use. Its runtime
guard remains after disconnect until explicit restoration; early-boot enforcement
and physical roaming/resume/leak behavior are not yet verified. Native phone
applications are a later phase.

```sh
bash install.sh --check
bash install.sh
python3 -m unittest discover -s tests -v
```

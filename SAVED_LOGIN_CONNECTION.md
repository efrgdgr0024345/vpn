# Stay connected during saved-login testing

The automatic diagnostic deliberately disconnects and restores ordinary networking.
This command instead verifies the installed code baseline and starts the same
protected helper with the saved root-only test login, without the diagnostic
parent's stop timer. It neither changes the installed application nor downloads
credentials again. Run it on Kali as the ordinary desktop owner with no existing
VPN session. Keep the connection terminal open.

The public verifier is pinned to the tested release and SHA256, verified from
bounded bytes before privileged execution. Core dumps are disabled before
private data is read, the environment is controlled, and the verifier checks the
protected installed baseline before importing the helper. The login remains in
`/etc/vpn-desk/testing-login.txt`; no password is embedded in this command.

```bash
(
set -eu
umask 077
runner=$(mktemp /tmp/vpn-desk-connect.XXXXXXXX.py)
trap 'rm -f -- "$runner"' EXIT
curl -4 --proto '=https' --tlsv1.2 -fsS --connect-timeout 10 --max-time 90 \
  'https://raw.githubusercontent.com/efrgdgr0024345/vpn/1aa0c4a4eee9cee49235536fa92e0f8de3eafb1a/ops/client_diagnostics.py' \
  -o "$runner"
sudo -- /usr/bin/python3 -I -B - "$runner" <<'PY'
import hashlib, os, pathlib, resource, stat, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
owner = int(os.environ.get('SUDO_UID', '0'))
if owner <= 0:
    raise SystemExit('Run this from your ordinary Kali desktop account.')
path = pathlib.Path(sys.argv[1])
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, 'rb') as stream:
    info = os.fstat(stream.fileno())
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (0, owner) or info.st_mode & 0o022):
        raise SystemExit('Unsafe verifier file; stopped.')
    code = stream.read(262145)
if hashlib.sha256(code).hexdigest() != '2fd2c9bbec1aaed5f422d86c1ab4769fa0a795cc919b596906220e0e28104dbf':
    raise SystemExit('Verifier checksum mismatch; stopped.')
os.chdir('/')
os.environ.clear()
os.environ.update(PATH='/usr/sbin:/usr/bin', LC_ALL='C')
scope = {'__name__': 'vpn_desk_checked_connection', '__file__': str(path)}
try:
    exec(compile(code, str(path), 'exec'), scope)
    modules = scope['load_modules']()
    print('Using the saved VPN login. Keep this terminal open; Ctrl+C stops the VPN.', flush=True)
    raise SystemExit(modules['vpn_session_helper'].main(owner, test_credentials=True))
except (OSError, ValueError, RuntimeError):
    raise SystemExit('Connection refused: the protected installation or saved test login could not be verified.')
PY
)
```

After the initialized event, allow a few seconds for the known startup DNS repair
before trying a webpage. **Session log / audit** in VPN Desk can display the
live events. This is the same temporary saved-login mode already tested: normal
TLS renegotiation continues, but an authentication failure or an actual reconnect
stops the owned session instead of rereading the password after privilege drop.
It is not an unattended reconnect feature.

Press Ctrl+C in the original terminal to stop. The guard stays enabled after stop
or failure. Use **Restore normal networking** in VPN Desk, or run:

```bash
sudo -- /usr/bin/python3 -I -B /usr/local/libexec/vpn-desk/privileged.py network-restore
```

No boot-image work, additional server lockdown or server integrity attestation is
performed by this command. Those are separate future changes.

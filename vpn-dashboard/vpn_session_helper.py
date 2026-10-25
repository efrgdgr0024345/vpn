#!/usr/bin/env python3
"""Explicit root session: close/verify portal, serialize against portal opening."""
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import portal_helper
from security import PROFILE, SERVICE_USER, load_policy, read_trusted, service_account, validate_profile


def openvpn_argv():
    policy = load_policy()
    validate_profile(read_trusted(PROFILE, private=True), policy)
    service_account()
    executable = next((p for p in ('/usr/sbin/openvpn', '/usr/bin/openvpn') if Path(p).is_file()), None)
    if not executable:
        raise portal_helper.Refused('OpenVPN is not installed.')
    return [executable, '--config', str(PROFILE), '--auth-user-pass', '--auth-nocache',
            '--mssfix', '1300', '--script-security', '1',
            '--allow-compression', 'no', '--user', SERVICE_USER,
            '--group', SERVICE_USER, '--persist-key', '--persist-tun']


def prepare_session():
    if os.geteuid() != 0:
        raise portal_helper.Refused('This session helper requires explicit terminal sudo.')
    command = openvpn_argv()
    portal_helper.check_network()
    portal_helper.act('close')
    if portal_helper.act('status').get('state') != 'closed':
        raise portal_helper.Refused('Portal closure could not be verified. VPN not started.')
    return command


def main():
    try:
        if os.geteuid() != 0:
            raise portal_helper.Refused('Requires explicit sudo in a visible terminal.')
        fd = os.open('/run/vpn-dashboard-portal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise portal_helper.Refused('Unsafe runtime lock file.')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            command = prepare_session()
            print('Portal verified closed. Starting OpenVPN; shared action lock held until exit.', flush=True)
            # One more check after firewall validation. External root network
            # managers remain outside this lock's trust boundary.
            portal_helper.check_network()
            process = subprocess.Popen(command, cwd='/', extra_groups=[],
                                       env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
            while True:
                try:
                    return process.wait()
                except KeyboardInterrupt:
                    # Terminal Ctrl+C also reaches the foreground OpenVPN child.
                    continue
    except (portal_helper.Refused, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print('VPN NOT CONFIRMED: ' + (str(exc) if isinstance(exc, portal_helper.Refused)
                                      else 'Session verification or action lock failed. No automatic retry.'), flush=True)
        return 1

if __name__ == '__main__':
    raise SystemExit('Use the installed privileged entry point; do not sudo a checkout script.')

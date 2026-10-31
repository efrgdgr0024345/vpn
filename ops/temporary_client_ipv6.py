"""Temporary interface-level IPv6 test, with a separately scheduled rollback."""
import json
import os
from pathlib import Path
import re
import resource
import subprocess

BASE = Path('/proc/sys/net/ipv6/conf')
UNIT = 'vpn-desk-ipv6-restore'
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
RESTORE = r'''
import json, pathlib, sys
base = pathlib.Path('/proc/sys/net/ipv6/conf')
old = json.loads(sys.argv[1])
errors = []
names = ['all', 'default'] + sorted(p.name for p in base.iterdir() if p.name not in ('all', 'default'))
for name in names:
    try:
        (base / name / 'disable_ipv6').write_text(old.get(name, old['default']) + '\n')
    except FileNotFoundError:
        continue
    except OSError:
        errors.append(name)
if errors:
    raise SystemExit('Some IPv6 settings could not be restored; inspect locally.')
print('Previous IPv6 settings restored. Wi-Fi may need a moment to recover.')
'''


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, env=ENV, timeout=20).stdout


def test():
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo and system Python.')
    module = Path('/sys/module/ipv6/parameters/disable')
    if not BASE.is_dir() or module.exists() and module.read_text().strip() in ('1', 'Y', 'y'):
        raise RuntimeError('IPv6 is already disabled in the kernel; this test cannot enable it.')
    if os.path.lexists('/etc/vpn-desk/network-state.json'):
        raise RuntimeError('Stop the VPN and use Restore normal networking first.')
    objects = json.loads(run(['/usr/sbin/nft', '-j', 'list', 'ruleset']))['nftables']
    if any(item.get('table', {}).get('name') == 'vpn_guard' for item in objects):
        raise RuntimeError('Use Restore normal networking first.')
    links = json.loads(run(['/usr/sbin/ip', '-j', '-d', 'link', 'show']))
    if any(row['ifname'].startswith(('tun', 'tap', 'wg', 'ovpn'))
           or row.get('linkinfo', {}).get('info_kind') in ('tun', 'wireguard', 'ovpn') for row in links):
        raise RuntimeError('Stop all VPN tunnels before this test.')
    names = ['all', 'default'] + sorted(p.name for p in BASE.iterdir() if p.name not in ('all', 'default'))
    if len(names) > 128 or any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name) for name in names):
        raise RuntimeError('Unexpected interface names; no changes made.')
    saved = {name: (BASE/name/'disable_ipv6').read_text().strip() for name in names}
    if any(value not in ('0', '1') for value in saved.values()):
        raise RuntimeError('Unexpected IPv6 settings; no changes made.')
    if all(value == '1' for value in saved.values()):
        raise RuntimeError('IPv6 is already disabled on every interface; nothing to test.')
    run(['/usr/bin/systemd-run', '--quiet', '--unit='+UNIT,
         '--on-active=90s', '--timer-property=AccuracySec=1s',
         '/usr/bin/python3', '-I', '-B', '-c', RESTORE, json.dumps(saved)])
    # A name collision or scheduling failure stops before the first IPv6 write.
    try:
        run(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT+'.timer'])
        print('Automatic restore armed for about 90 seconds. Try your browser now.', flush=True)
        print('Restore sooner: sudo systemctl start '+UNIT+'.service', flush=True)
        for name in names:
            (BASE/name/'disable_ipv6').write_text('1\n')
        if any((p/'disable_ipv6').read_text().strip() != '1' for p in BASE.iterdir()):
            raise RuntimeError('IPv6 disablement did not hold; restoring.')
        print('All current IPv6 interface settings verified OFF. No boot settings changed.', flush=True)
    except BaseException:
        try:
            run(['/usr/bin/systemctl', 'start', UNIT+'.service'])
        except (OSError, subprocess.SubprocessError):
            pass  # The independently scheduled timer remains the fallback.
        raise


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    try:
        test()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, RuntimeError) else 'A required check failed; inspect the restore timer if it was armed.'
        raise SystemExit('IPv6 test stopped: '+message) from None

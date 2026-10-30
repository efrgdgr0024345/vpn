"""Legacy policy migration with real nftables and VPN restarts in CI containers.

The disposable server namespace starts with IPv6 interface sysctls disabled by
Docker. This test checks the legacy configuration transition; it does not boot a
kernel or claim the generated GRUB fixture proves physical-machine boot behavior.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import types
from unittest.mock import patch

import enable_ipv4_only as migration
import server_foundation as foundation


def run(lifecycle):
    if (not Path('/.dockerenv').is_file() or os.geteuid()!=0
            or os.environ.get('VPN_LAB_DISPOSABLE_SERVER_TEST')!='1'):
        raise RuntimeError('IPv4 migration fixture requires the disposable container.')
    fixture=Path('/test/ipv4-migration')
    foundation.directory(fixture)
    original_configuration=foundation.read_owned(migration.SERVER_CONFIG)
    plugin=re.findall(r'^plugin (\S+) vpn-lab$',original_configuration,re.M)[0]
    legacy_configuration=foundation.server_configuration(plugin).replace(
        'server 172.27.240.0 255.255.255.0\n',
        'server 172.27.240.0 255.255.255.0\nserver-ipv6 fd47:27:240::/64\n').replace(
        'push "redirect-gateway def1"\n',
        'push "redirect-gateway def1 ipv6"\npush "block-ipv6"\n')
    route=json.loads(foundation.run(['/usr/sbin/ip','-j','-4','route','show','default']))[0]
    legacy_firewall=foundation.firewall(route['dev'],22)
    for name in ('input','forward','output'):
        legacy_firewall=legacy_firewall.replace(
            '  meta nfproto ipv6 counter drop comment "vpn-lab-block-ipv6-'+name+'"\n','')
    legacy_firewall=legacy_firewall.replace(
        ' chain output {\n  type filter hook output priority 0; policy accept;\n }',
        ' chain output { type filter hook output priority 0; policy accept; }')
    legacy_firewall=legacy_firewall.replace(
        '  iifname "'+route['dev']+'" ip protocol icmp accept\n',
        '  iifname "'+route['dev']+'" udp sport 547 udp dport 546 accept\n'
        '  iifname "'+route['dev']+'" ip protocol icmp accept\n'
        '  iifname "'+route['dev']+'" meta l4proto ipv6-icmp accept\n')
    # Only the isolated namespace contains this lab policy, so reconstructing
    # its old table is allowed here. The production migration never loads a
    # flush-ruleset file and must preserve additional tables below.
    foundation.run(['/usr/sbin/nft','-f','-'],data=legacy_firewall)
    foundation.run(['/usr/sbin/nft','-f','-'],data='''table inet migration_sentinel {
 chain output { type filter hook output priority 5; policy accept; }
}
''')
    sentinel=foundation.run(['/usr/sbin/nft','-j','list','table','inet','migration_sentinel'])
    foundation.write(migration.SERVER_CONFIG,legacy_configuration)
    foundation.write(migration.FIREWALL_CONFIG,legacy_firewall,0o644)
    foundation.write(migration.FOUNDATION_SYSCTL,migration.FOUNDATION_SYSCTL_CONTENT,0o644)
    # A tiny, approved legacy self-test fixture proves replacement rather than
    # accepting the already-updated test file without exercising that write.
    old_selftest='# Prior approved public self-test fixture.\n'
    foundation.write(migration.SELFTEST,old_selftest,0o644)
    new_selftest=Path('/test/ops/server_selftest.py').read_text()
    files=[foundation.EXPORT/'login.txt',foundation.EXPORT/'client.ovpn',
           foundation.CONFIG/'devices.json',*sorted(foundation.PKI.rglob('*'))]
    before={str(path):hashlib.sha256(path.read_bytes()).digest()
            for path in files if path.is_file()}
    grub_config=fixture/'grub.cfg'
    grub_output=fixture/'generated-grub.cfg'
    foundation.write(grub_output,'linux /vmlinuz root=/dev/fixture\n',0o644)
    for path,content,mode in ((Path('/etc/default/grub'),'# Public CI boot fixture.\n',0o644),
                             (Path('/usr/sbin/update-grub'),'#!/bin/sh\nexit 1\n',0o755)):
        if not path.exists():
            foundation.write(path,content,mode)
    engine=types.SimpleNamespace(**{key:getattr(foundation,key) for key in
        ('CONFIG','EXPORT','SetupError','directory','read_owned','write','validate')})
    engine.server_configuration=lambda unused:legacy_configuration
    engine.firewall=lambda unused_interface,unused_port:legacy_firewall
    def observed(argv,**kwargs):
        if argv==['/usr/sbin/update-grub']:
            if foundation.read_owned(grub_config)!=migration.GRUB_CONTENT:
                raise RuntimeError('Migration did not publish the expected GRUB drop-in.')
            foundation.write(grub_output,'linux /vmlinuz root=/dev/fixture ipv6.disable=1\n',0o644)
            return ''
        if argv==['/usr/sbin/sysctl','-p',str(fixture/'disable-ipv6.conf')]:
            # Docker supplies these settings in this namespace. Its read-only
            # /proc/sys mount is retained rather than relaxed for the fixture.
            if (foundation.read_owned(fixture/'disable-ipv6.conf')!=migration.SYSCTL_CONTENT
                    or any(Path('/proc/sys/net/ipv6/conf',name,'disable_ipv6').read_text().strip()!='1'
                           for name in ('all','default'))):
                raise RuntimeError('The isolated IPv6 sysctl fixture is not disabled.')
            return ''
        return lifecycle(argv,**kwargs)
    engine.run=observed
    with patch.object(migration,'server',engine), \
         patch.object(migration,'GRUB_CONFIG',grub_config), \
         patch.object(migration,'GRUB_OUTPUT',grub_output), \
         patch.object(migration,'SYSCTL_CONFIG',fixture/'disable-ipv6.conf'), \
         patch.object(migration,'SELFTEST_SOURCE',new_selftest,create=True), \
         patch.object(migration,'SELFTEST_PREVIOUS_SHA256',hashlib.sha256(old_selftest.encode()).hexdigest(),create=True):
        report=migration.administer('enable-ipv4-only')
        if (not report['server_configuration_ipv4_only'] or not report['firewall_ipv6_blocked']
                or not report['interface_ipv6_disabled'] or not report['reboot_required']
                or report['kernel_ipv6_disabled'] or report['credential_contents_returned']):
            raise RuntimeError('Migration reported an incorrect runtime or boot state.')
        # A retry must preserve both original recovery snapshots and identities.
        recovery=foundation.EXPORT/'recovery'
        snapshots={str(path):path.read_bytes() for path in
                   (recovery/'vpn-lab.before-ipv4-only.conf',recovery/'nftables.before-ipv4-only.conf')}
        migration.administer('enable-ipv4-only')
        if any(Path(path).read_bytes()!=value for path,value in snapshots.items()):
            raise RuntimeError('An IPv4 migration retry replaced its recovery baseline.')
    if (sentinel!=foundation.run(['/usr/sbin/nft','-j','list','table','inet','migration_sentinel'])
            or any(hashlib.sha256(Path(path).read_bytes()).digest()!=value for path,value in before.items())
            or foundation.read_owned(migration.SELFTEST)!=new_selftest):
        raise RuntimeError('Migration changed unrelated firewall state or VPN identities.')
    foundation.run(['/usr/sbin/nft','delete','table','inet','migration_sentinel'])
    print('PASS: legacy IPv6 policy migration, real nft preservation, VPN/broker restart, original recovery snapshots and unchanged VPN identities; GRUB generation and sysctl application use isolated fixtures.',flush=True)

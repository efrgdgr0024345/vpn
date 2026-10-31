"""App-owned kill switch and resolver policy for the staged VPN lab.

Never flush an unrelated ruleset. The guard remains on after disconnect/failure;
only explicit authenticated restore releases it. This version supports a regular
root-owned resolv.conf, as found on the owner's Kali host, not symlink managers.
"""
import json
import os
from pathlib import Path
import tempfile
import firewall_policy
import portal_helper
from security import CONFIG_DIR, Refused, load_policy, read_trusted, service_account

STATE = CONFIG_DIR/'network-state.json'
RESOLVER = Path('/etc/resolv.conf')
DNS = '172.27.240.1'
MANAGED_DNS = '# VPN Desk managed DNS; direct network DNS is blocked by the guard.\nnameserver '+DNS+'\n'


def resolver_read():
    # read_trusted checks every ancestor, file type, link count and root owner.
    return read_trusted(RESOLVER,limit=16384)


def resolver_write(value):
    resolver_read()
    fd,temporary=tempfile.mkstemp(prefix='.vpn-desk-dns-',dir=RESOLVER.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o644)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,RESOLVER)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_state(value):
    # The existing installer created this root-only configuration directory.
    from safe_io import private_write
    read_trusted(CONFIG_DIR/'policy.json',private=True)
    if STATE.exists() or STATE.is_symlink():
        read_trusted(STATE,private=True)
    private_write(STATE,json.dumps(value,sort_keys=True)+'\n')


def state_read():
    value=json.loads(read_trusted(STATE,private=True,limit=32768))
    if (not isinstance(value,dict) or set(value)!={'version','resolver_before','policy','vpn_uid'}
            or value['version']!=1 or not isinstance(value['resolver_before'],str)
            or len(value['resolver_before'])>16384 or type(value['vpn_uid']) is not int or value['vpn_uid']<=0):
        raise Refused('Unsupported owned network state.')
    return value


def empty_ruleset(document):
    return (isinstance(document,dict) and isinstance(document.get('nftables'),list)
            and all(isinstance(item,dict) and set(item)=={'metainfo'} for item in document['nftables']))


def prepare():
    policy=load_policy()
    if policy['server_name']!='VPNLabServer':
        raise Refused('Managed DNS setup requires the staged lab server profile.')
    uid=service_account().pw_uid
    before=resolver_read()
    document=portal_helper.js([portal_helper.NFT,'-j','list','ruleset'])
    if STATE.exists():
        state=state_read()
        if state['policy']!=policy or state['vpn_uid']!=uid:
            raise Refused('Saved network settings differ; restore/review before changing them.')
        if not empty_ruleset(document):
            portal_helper.inspect_guard(document)
    else:
        if not empty_ruleset(document):
            raise Refused('A pre-existing firewall requires a reviewed migration; no rules were changed.')
        # Persist recovery before applying any network change. A failed startup
        # resumes this same state; it never silently discards the baseline.
        write_state({'version':1,'resolver_before':before,'policy':policy,'vpn_uid':uid})
    if empty_ruleset(document):
        batch=json.dumps(firewall_policy.render_batch(policy,uid))
        portal_helper.run([portal_helper.NFT,'-c','-j','-f','-'],batch)
        try:
            portal_helper.run([portal_helper.NFT,'-j','-f','-'],batch)
        except Refused as exc:
            raise portal_helper.MutationUnknown('Firewall outcome is unknown; keep protection enabled and inspect locally.') from exc
    portal_helper.inspect_guard(portal_helper.js([portal_helper.NFT,'-j','list','ruleset']))
    # Only after the output drop policy is verified may resolver configuration
    # change. Wi-Fi DHCP/DNS rewrites cannot create a physical DNS exception.
    resolver_write(MANAGED_DNS)
    return {'guard':'enabled','dns':'private_vpn_resolver','restore_required':True}


def verify_during_session():
    _,active=portal_helper.inspect_guard(portal_helper.js([portal_helper.NFT,'-j','list','ruleset']))
    if active:
        raise Refused('A direct-network bypass is active; session verification failed.')
    if resolver_read()!=MANAGED_DNS:
        # NetworkManager may refresh resolv.conf after DHCP renewal. Reassert
        # the app's policy while the guard blocks any direct-DNS interval.
        resolver_write(MANAGED_DNS)
        return False
    return True


def restore():
    if portal_helper.hotspot_present():
        raise Refused('Stop the VPN hotspot before restoring normal networking.')
    if portal_helper.active_openvpn():
        raise Refused('Stop the VPN before restoring normal networking.')
    state=state_read()
    if state['policy']!=load_policy() or state['vpn_uid']!=service_account().pw_uid:
        raise Refused('Saved network ownership no longer matches the installed policy.')
    document=portal_helper.js([portal_helper.NFT,'-j','list','ruleset'])
    portal_helper.inspect_guard(document)
    current=resolver_read()
    if current not in (MANAGED_DNS,state['resolver_before']):
        raise Refused('Resolver ownership changed; review it before releasing the guard.')
    # Restore DNS while physical traffic is still blocked. Then delete only the
    # positively identified owned table; never flush unrelated firewall tables.
    resolver_write(state['resolver_before'])
    portal_helper.mutate('delete table inet vpn_guard\n')
    STATE.unlink()
    return {'guard':'released','dns':'previous_configuration_restored'}

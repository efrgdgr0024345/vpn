"""Render a candidate nft JSON batch for administrator review; never apply it."""
import argparse
import json
from pathlib import Path

from portal_helper import allowed_input_rules, allowed_rules
from security import validate_policy


def render_batch(policy, vpn_uid):
    policy = validate_policy(policy)
    if type(vpn_uid) is not int or vpn_uid <= 0:
        raise ValueError('A non-root dedicated VPN UID is required.')
    objects = [{'add': {'table': {'family': 'inet', 'name': 'vpn_guard'}}}]
    for name in ('input', 'output', 'forward'):
        objects.append({'add': {'chain': {
            'family': 'inet', 'table': 'vpn_guard', 'name': name,
            'type': 'filter', 'hook': name, 'prio': 0, 'policy': 'drop'}}})
    for chain, rules in (('input', allowed_input_rules(policy)), ('output', allowed_rules(policy, vpn_uid))):
        for expression in rules:
            objects.append({'add': {'rule': {'family': 'inet', 'table': 'vpn_guard',
                                           'chain': chain, 'expr': expression}}})
    return {'nftables': objects}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--uid', required=True, type=int)
    args = parser.parse_args()
    print(json.dumps(render_batch(json.loads(args.policy.read_text()), args.uid), indent=2))

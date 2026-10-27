#!/usr/bin/env python3
"""Visible per-action terminal authentication; no credentials handled by GUI."""
import subprocess
import sys
from security import Refused, installed_command


def command(action):
    if action not in ('close', 'status'):
        raise ValueError('Portal opening is disabled until browser traffic can be isolated.')
    return installed_command('portal-' + action)


def main():
    if len(sys.argv) != 2:
        return 2
    try:
        argv = command(sys.argv[1])
        print('VPN Desk portal action: ' + sys.argv[1], flush=True)
        print('Enter sudo credentials only here. Read the helper result below.\n', flush=True)
        result = subprocess.run(argv, check=False)
        code = result.returncode
    except (OSError, ValueError, Refused):
        print('Could not run portal helper. No success is assumed.')
        code = 1
    except KeyboardInterrupt:
        print('\nInterrupted. Do not assume the action completed; run portal status.')
        code = 130
    try:
        input('\nPress Enter to close this terminal. ')
    except (EOFError, KeyboardInterrupt):
        pass
    return code

if __name__ == '__main__':
    raise SystemExit(main())

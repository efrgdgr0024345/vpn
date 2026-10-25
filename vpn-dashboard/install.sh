#!/bin/sh
# Keep the extracted files together. Run from a terminal as your desktop user.
set -eu
installer_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x /usr/bin/python3 ]; then
    printf '%s\n' 'Python 3 is required. Install it with your distribution package manager.' >&2
    exit 1
fi
exec /usr/bin/python3 -I -B "$installer_dir/install.py" "$@"

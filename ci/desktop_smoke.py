"""Render the actual dashboard under Xvfb; do not trigger privileged actions."""
from pathlib import Path
import sys
import tkinter as tk
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vpn-dashboard'))
import app


def main():
    original = tk.Tk
    checked = []
    failures = []

    class SmokeWindow(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.after(1000, self.check_window)

        def report_callback_exception(self, kind, value, traceback):
            failures.append(kind.__name__)
            self.destroy()

        def check_window(self):
            try:
                assert self.winfo_ismapped(), 'Dashboard was not mapped'
                assert 'VPN Desk' in self.title(), 'Wrong dashboard title'
                assert self.winfo_children(), 'Dashboard has no widgets'
                checked.append(True)
            except Exception as exc:
                failures.append(str(exc))
            finally:
                self.destroy()

    # The widget tree and event loop are real. Local state collection is
    # substituted so this UI check cannot inspect runner-specific identifiers.
    with patch.object(tk, 'Tk', SmokeWindow), patch.object(
            app, 'collect', return_value={'Status': 'Disposable UI smoke test'}):
        result = app.main()
    if result != 0 or not checked or failures:
        raise SystemExit('Dashboard smoke test failed: ' + ', '.join(failures))
    print('Dashboard rendered and closed successfully; no Connect action invoked.')


if __name__ == '__main__':
    main()

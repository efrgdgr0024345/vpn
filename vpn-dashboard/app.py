#!/usr/bin/env python3
"""Offline-first diagnostics with explicit terminal-authenticated actions."""
import datetime
import getpass
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import sys
import launch_vpn
import session_channel
from safe_io import bounded_run, private_write
from security import Refused
import threading
from dataclasses import dataclass
from pathlib import Path

BASE = Path(__file__).resolve().parent
COMMANDS = {
    'links': ('/usr/sbin/ip', '-j', 'link', 'show'),
    'routes': ('/usr/sbin/ip', '-j', '-4', 'route', 'show'),
    'routes6': ('/usr/sbin/ip', '-j', '-6', 'route', 'show'),
    'nm': ('/usr/bin/nmcli', '-t', '-f', 'TYPE,DEVICE', 'connection', 'show', '--active'),
    'dns': ('/usr/bin/nmcli', '-t', '-f', 'GENERAL.DEVICE,IP4.DNS,IP6.DNS', 'device', 'show'),
    'services': ('/usr/bin/systemctl', 'list-units', '--type=service', '--all', '--no-legend', '--no-pager', 'openvpn*'),
    'firewall': ('/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'vpn_guard'),
}

@dataclass
class Result:
    ok: bool
    output: str = ''
    error: str = ''


def run_command(key):
    """Fixed argv only. Never invokes a shell, sudo, journal, or profile file."""
    try:
        p = bounded_run(COMMANDS[key], capture_output=True, text=True,
                        timeout=6, check=False, limit=131072,
                        env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': ''})
        # Do not propagate raw stderr: it may contain identifiers.
        return Result(p.returncode == 0, p.stdout[:131072],
                      '' if p.returncode == 0 else 'Unavailable (permission or command error)')
    except FileNotFoundError:
        return Result(False, error='Command not installed')
    except subprocess.TimeoutExpired:
        return Result(False, error='Timed out after 6 seconds')
    except (OSError, UnicodeError, subprocess.SubprocessError):
        return Result(False, error='Command could not be read')


def redact(text, sensitive=()):
    """Defense in depth; exports are constructed summaries, never raw outputs."""
    for value in sorted(set(sensitive), key=len, reverse=True):
        if value:
            text = text.replace(value, '[PRIVATE]')
    text = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[MAC]', text)
    text = re.sub(r'(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?', '[IP]', text)
    # IPv6 tokens, including compressed and zone-qualified addresses.
    def ipv6(match):
        token = match.group(0)
        try:
            ipaddress.IPv6Address(token.split('%')[0].split('/')[0])
            return '[IP]'
        except ValueError:
            return token
    text = re.sub(r'(?<![\w])(?:[0-9A-Fa-f]*:){2,}[0-9A-Fa-f:.]*(?:%[\w.-]+)?(?:/\d+)?', ipv6, text)
    text = re.sub(r'(?im)\b(ssid|hostname|username|password|token|secret)\s*[:=]\s*[^\n]+', r'\1=[PRIVATE]', text)
    return text


def json_list(result):
    if not result.ok:
        return None
    try:
        data = json.loads(result.output)
        return data if isinstance(data, list) else None
    except (ValueError, TypeError):
        return None


def summarize(results):
    """Never equate an interface, route, or readable firewall with safety."""
    links = json_list(results['links'])
    tunnel = next((x for x in (links or []) if isinstance(x, dict) and x.get('ifname') == 'tun0'), None)
    if links is None:
        tunnel_text = 'UNKNOWN — interface information unavailable'
    elif tunnel is None:
        tunnel_text = 'NOT FOUND — tun0 is absent'
    else:
        tunnel_text = 'PRESENT — tun0 exists; VPN health unverified'
    routes = json_list(results['routes'])
    if routes is None:
        route_text = 'UNKNOWN — IPv4 routes unavailable'
    else:
        split = {x.get('dst') for x in routes if isinstance(x, dict) and x.get('dev') == 'tun0'}
        route_text = ('Split /1 routes via tun0 observed' if {'0.0.0.0/1', '128.0.0.0/1'} <= split
                      else 'Expected pair of split /1 routes not observed') + '; no leak test performed'
    fw = results['firewall']
    try:
        data = json.loads(fw.output) if fw.ok else {}
        readable = isinstance(data, dict) and isinstance(data.get('nftables'), list)
    except ValueError:
        readable = False
    firewall_text = ('READABLE — vpn_guard returned; policy NOT audited' if readable
                     else 'UNKNOWN — vpn_guard not readable; do not assume protection')
    nm = results['nm']
    vpn_count = sum(line.split(':')[0] == 'vpn' for line in nm.output.splitlines()) if nm.ok else None
    backend_text = ('NetworkManager reports %d active VPN profile(s)' % vpn_count if nm.ok
                    else 'NetworkManager information unavailable') + '; direct OpenVPN CLI configured (user-confirmed)'
    dns = results['dns']
    dns_count = sum(bool(line.split(':', 1)[-1]) for line in dns.output.splitlines()
                    if line.startswith(('IP4.DNS', 'IP6.DNS'))) if dns.ok else None
    dns_text = ('%d DNS entry/entries reported; resolution/leak safety untested' % dns_count if dns.ok
                else 'UNKNOWN — DNS information unavailable')
    services = results['services']
    service_text = ('%d matching OpenVPN service row(s); exact unit must be confirmed' %
                    len([x for x in services.output.splitlines() if x.strip()]) if services.ok
                    else 'OpenVPN service information unavailable')
    ipv6 = json_list(results['routes6'])
    ipv6_text = ('DISABLED — IPv6 is disabled by the kernel boot setting'
                 if session_channel.kernel_ipv6_disabled() else
                 'UNKNOWN — routes unavailable' if ipv6 is None else
                 'IPv6 routes observed: %d; firewall coverage NOT verified' % len(ipv6))
    return {'Tunnel': tunnel_text, 'Routes': route_text, 'Firewall': firewall_text,
            'Backend': backend_text, 'DNS': dns_text, 'Services': service_text,
            'IPv6': ipv6_text}


def collect(runner=run_command):
    return summarize({key: runner(key) for key in COMMANDS})


def export_log(status, sensitive=()):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    lines = ['VPN Desk • diagnostics + terminal launcher', 'Snapshot UTC: ' + now,
             'Overall: UNVERIFIED. Not a security certification.',
             'Redacted summary only: no profiles, credentials, journals, raw command output or SSIDs.',
             'Identity: local desktop session only; VPN/server identity NOT verified.']
    lines.extend(key + ': ' + value for key, value in status.items())
    lines.append('Controls: terminal-authenticated Connect/Portal actions. Stop VPN with Ctrl+C in its original terminal. Portal state NOT read by this summary.')
    return redact('\n'.join(lines) + '\n', sensitive)


def main():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except ImportError:
        print('Tkinter is not installed. Read recovery.txt offline; ask your administrator to enable Python Tk support.')
        return 1
    try:
        root = tk.Tk()
    except tk.TclError:
        print('A graphical desktop is required. Read recovery.txt in a terminal: less recovery.txt')
        return 1
    root.title('VPN Desk · local VPN control')
    root.geometry('1040x830')
    root.minsize(820, 650)
    root.configure(bg='#0b1220')
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background='#0b1220', foreground='#e2e8f0', font=('DejaVu Sans', 10))
    style.configure('TFrame', background='#0b1220')
    style.configure('TLabel', background='#0b1220')
    style.configure('TButton', padding=(14, 9), background='#26364d')
    style.map('TButton', foreground=[('disabled', '#8c9aae')], background=[('active', '#334762')])
    style.configure('Title.TLabel', font=('DejaVu Sans', 24, 'bold'))
    style.configure('Warn.TLabel', foreground='#fbbf24')
    outer = ttk.Frame(root, padding=24)
    outer.pack(fill='both', expand=True)
    ttk.Label(outer, text='◈  VPN Desk', style='Title.TLabel').pack(anchor='w')
    ttk.Label(outer, text='Local connection controls, private session logs and code review', foreground='#94a3b8').pack(anchor='w', pady=(5, 12))
    ttk.Label(outer, text='!  UNVERIFIED — this dashboard cannot certify VPN health or leak protection.', style='Warn.TLabel').pack(anchor='w')
    user = getpass.getuser()
    host = socket.gethostname()
    ttk.Label(outer, text=f'Local session: {user}  •  Host: {host}  •  UID: {os.getuid()}').pack(anchor='w', pady=(10, 2))
    ttk.Label(outer, text='Local OS identity only — not a verified VPN account, remote user, or server identity.', foreground='#94a3b8').pack(anchor='w')
    if os.geteuid() == 0:
        ttk.Label(outer, text='Run this app as your ordinary desktop user, not root.', style='Warn.TLabel').pack(anchor='w')
    body = ttk.Frame(outer)
    body.pack(fill='x', pady=16)
    labels = {}
    for row, key in enumerate(('Tunnel', 'Routes', 'Firewall', 'Backend', 'DNS', 'Services', 'IPv6')):
        ttk.Label(body, text={'Tunnel':'◉', 'Routes':'↗', 'Firewall':'▣', 'Backend':'⚙', 'DNS':'⌕', 'Services':'≡', 'IPv6':'◇'}[key]+'  '+key, width=13).grid(row=row, column=0, sticky='nw', pady=5)
        var = tk.StringVar(value='Not checked yet')
        labels[key] = var
        ttk.Label(body, textvariable=var, wraplength=730).grid(row=row, column=1, sticky='w', pady=5)
    controls = ttk.Frame(outer)
    controls.pack(fill='x')
    connect_btn = ttk.Button(controls, text='▶ Connect in terminal', state='disabled')
    connect_btn.pack(side='left', padx=(0, 8))
    stop_btn = ttk.Button(controls, text='■ Disconnect')
    stop_btn.pack(side='left', padx=(0, 8))
    portal_open = ttk.Button(controls, text='Wi-Fi bypass disabled', state='disabled')
    portal_close = ttk.Button(controls, text='Close portal')
    portal_status = ttk.Button(controls, text='Portal status')
    ttk.Label(outer, text='Disconnect keeps the kill switch on. Restore normal networking deliberately releases it. Boot-time client protection is not yet verified.', foreground='#fbbf24', wraplength=920).pack(anchor='w', pady=8)
    log = tk.Text(outer, height=11, wrap='word', bg='#111d30', fg='#cbd5e1', insertbackground='white', relief='flat', padx=12, pady=12, font=('DejaVu Sans Mono', 9))
    log.pack(fill='both', expand=True, pady=(8, 12))
    scrollbar = ttk.Scrollbar(log, command=log.yview)
    scrollbar.pack(side='right', fill='y')
    log.configure(yscrollcommand=scrollbar.set)
    current = {'text': export_log({'Status': 'Not checked yet'}, (user, host)), 'busy': False, 'launched': False}
    def display(text):
        log.configure(state='normal')
        log.delete('1.0', 'end')
        log.insert('1.0', text)
        log.configure(state='disabled')
    display(current['text'])
    footer = ttk.Frame(outer)
    footer.pack(fill='x')
    note = tk.StringVar(value='No network probes. Refresh reads local state only.')
    inbox = queue.Queue()
    def refresh():
        if current['busy']:
            return
        current['busy'] = True
        refresh_btn.configure(state='disabled')
        note.set('Reading local state… up to 42 seconds. No network changes.')
        def worker():
            try:
                inbox.put(collect())
            except Exception:
                inbox.put({'Status': 'Collection failed; all results UNKNOWN'})
        threading.Thread(target=worker, daemon=True).start()
    def poll():
        try:
            status = inbox.get_nowait()
        except queue.Empty:
            pass
        else:
            for key, var in labels.items():
                var.set(status.get(key, 'UNKNOWN — collection failed'))
            current['text'] = export_log(status, (user, host))
            display(current['text'])
            current['busy'] = False
            refresh_btn.configure(state='normal')
            if not current['launched'] and os.geteuid() != 0:
                connect_btn.configure(state='normal')
            note.set('Snapshot updated. UNKNOWN is not safe; inspect the offline guide.')
        root.after(100, poll)
    def connect():
        if current['busy'] or current['launched']:
            return
        if not messagebox.askokcancel('Connect with protection',
            'Enter credentials in the authentication terminal. '
            'The helper enables the app-owned kill switch and private VPN DNS, then verifies them. '
            'An unrelated firewall is preserved and causes setup to stop. '
            'Disconnect keeps Internet traffic blocked until you explicitly Restore normal networking. Continue?', parent=root):
            return
        current['busy'] = True
        connect_btn.configure(state='disabled')
        refresh_btn.configure(state='disabled')
        note.set('Checking for an existing tunnel before opening a terminal…')
        def preflight_impl():
            # A fresh local check, not the potentially stale displayed snapshot.
            links = json_list(run_command('links'))
            error = None
            if links is None:
                error = 'Cannot inspect interfaces. No connection started.'
            elif any(str(x.get('ifname', '')).startswith(('tun', 'tap')) for x in links if isinstance(x, dict)):
                error = 'A tunnel interface already exists. Use your original terminal; no duplicate session started.'
            try:
                launch_vpn.argv()  # Verify installed code, never a home-directory profile.
                if launch_vpn.existing_openvpn():
                    error = 'An OpenVPN process already exists. Use the original terminal.'
            except (Refused, ValueError, OSError) as exc:
                error = str(exc)
            terminal = next((p for p in ('/usr/bin/x-terminal-emulator', '/usr/bin/xterm') if os.access(p, os.X_OK)), None)
            if not terminal:
                error = 'No supported system terminal found. Use the exact command in Offline help.'
            if not error:
                try:
                    subprocess.Popen([terminal, '-e', sys.executable, str(BASE / 'launch_vpn.py')],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except OSError:
                    error = 'Terminal could not be launched. Use Offline help.'
            launch_results.put(error)
        def preflight():
            try:
                preflight_impl()
            except Exception:
                launch_results.put('Preflight failed. No connection confirmed; inspect the original terminal before retrying.')
        threading.Thread(target=preflight, daemon=True).start()
    launch_results = queue.Queue()
    def poll_launch():
        try:
            error = launch_results.get_nowait()
        except queue.Empty:
            pass
        else:
            current['busy'] = False
            refresh_btn.configure(state='normal')
            if error:
                connect_btn.configure(state='normal')
                messagebox.showwarning('No connection started', error, parent=root)
                note.set(error)
            else:
                current['launched'] = True
                note.set('Terminal launch requested — connection NOT confirmed. Authenticate there; Ctrl+C there to stop.')
                show_session()
                messagebox.showinfo('Check the VPN terminal',
                    'Terminal launch was requested, not verified. Authenticate there and look for OpenVPN errors. '
                    'Keep it open. Refresh checks local state only. Connect stays disabled in this app session '
                    'to prevent repeated launches; restart the app only after confirming the old VPN has stopped.', parent=root)
        root.after(100, poll_launch)
    connect_btn.configure(command=connect)
    def disconnect():
        terminal=next((p for p in ('/usr/bin/x-terminal-emulator','/usr/bin/xterm') if os.access(p,os.X_OK)),None)
        try:
            launch_vpn.argv('disconnect')
            if terminal is None:
                raise ValueError('No supported terminal is available.')
            subprocess.Popen([terminal,'-e',sys.executable,str(BASE/'launch_vpn.py'),'disconnect'],
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            current['launched']=False
            note.set('Authenticate in the terminal to stop only this app-owned session. The firewall stays enabled.')
        except (OSError,Refused,ValueError):
            messagebox.showwarning('Disconnect unavailable','The protected disconnect helper could not be launched.',parent=root)
    stop_btn.configure(command=disconnect)
    def restore_network():
        if not messagebox.askokcancel('Restore normal networking',
            'After stopping the VPN, this releases the app-owned kill switch and restores your previous DNS. '
            'Normal Internet traffic can then use Wi-Fi directly. Authenticate in the terminal to continue.',parent=root):
            return
        terminal=next((p for p in ('/usr/bin/x-terminal-emulator','/usr/bin/xterm') if os.access(p,os.X_OK)),None)
        try:
            launch_vpn.argv('network-restore')
            if terminal is None:
                raise ValueError('No terminal.')
            subprocess.Popen([terminal,'-e',sys.executable,str(BASE/'launch_vpn.py'),'network-restore'],
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        except (OSError,Refused,ValueError):
            messagebox.showwarning('Restore unavailable','Normal networking was not confirmed restored.',parent=root)
    ttk.Button(controls,text='Restore normal networking',command=restore_network).pack(side='left',padx=(8,0))
    root.after(100, poll_launch)
    def portal(action):
        if action == 'open':
            messagebox.showwarning('Disabled', 'Portal opening is disabled until browser traffic can be isolated.', parent=root)
            return
        if os.geteuid() == 0:
            messagebox.showwarning('Run unprivileged', 'Restart the dashboard as your ordinary desktop user.', parent=root)
            return
        terminal = next((p for p in ('/usr/bin/x-terminal-emulator', '/usr/bin/xterm') if os.access(p, os.X_OK)), None)
        if not terminal:
            messagebox.showwarning('No terminal', 'No supported system terminal found. Read Offline help.', parent=root)
            return
        try:
            subprocess.Popen([terminal, '-e', sys.executable, str(BASE / 'portal_terminal.py'), action],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            messagebox.showwarning('Launch failed', 'Could not launch terminal. Portal state is UNKNOWN.', parent=root)
            return
        note.set('Portal ' + action + ' terminal requested. Read its JSON result; this dashboard does not assume success.')
    portal_open.configure(command=lambda: portal('open'))
    portal_close.configure(command=lambda: portal('close'))
    portal_status.configure(command=lambda: portal('status'))
    def copy():
        root.clipboard_clear()
        root.clipboard_append(current['text'])
        note.set('Redacted summary copied. Keep the app open until pasted; review before sharing.')
    def save():
        path = filedialog.asksaveasfilename(parent=root, title='Save reviewed redacted summary', defaultextension='.txt', initialfile='vpn-diagnostics-redacted.txt', filetypes=[('Text', '*.txt')])
        if path:
            try:
                private_write(path, current['text'])
                note.set('Redacted summary saved. Review it before sharing.')
            except OSError:
                messagebox.showerror('Could not save', 'Choose a writable location.', parent=root)
    def help_window():
        window = tk.Toplevel(root)
        window.title('Offline recovery · no internet needed')
        window.geometry('920x700')
        viewer = tk.Text(window, wrap='word', bg='#111d30', fg='#e2e8f0', padx=18, pady=18, font=('DejaVu Sans Mono', 10))
        viewer.pack(fill='both', expand=True)
        scroll = ttk.Scrollbar(window, command=viewer.yview)
        scroll.pack(side='right', fill='y')
        viewer.configure(yscrollcommand=scroll.set)
        try:
            text = (BASE / 'recovery.txt').read_text(encoding='utf-8')
        except OSError:
            text = 'recovery.txt is missing. Extract all files from the original archive together.'
        viewer.insert('1.0', text)
        viewer.configure(state='disabled')
    refresh_btn = ttk.Button(footer, text='↻ Refresh', command=refresh)
    refresh_btn.pack(side='left', padx=(0, 8))
    ttk.Button(footer, text='⧉ Copy safe log', command=copy).pack(side='left', padx=(0, 8))
    ttk.Button(footer, text='↓ Save log', command=save).pack(side='left', padx=(0, 8))
    ttk.Button(footer, text='? Offline help', command=help_window).pack(side='left', padx=(0, 8))
    connection_window = {'window': None}
    def show_connections():
        from connections_ui import open_connections
        existing = connection_window['window']
        if existing is not None and existing.winfo_exists():
            existing.lift()
            return
        connection_window['window'] = open_connections(root)
    ttk.Button(footer, text='↔ Connections', command=show_connections).pack(side='left')
    session_window={'window':None}
    def show_session():
        from session_ui import open_session_window
        existing=session_window['window']
        if existing is not None and existing.winfo_exists():
            existing.lift()
        else:
            session_window['window']=open_session_window(root)
    ttk.Button(footer,text='Session log / audit',command=show_session).pack(side='left',padx=(8,0))
    ttk.Label(outer, textvariable=note, foreground='#94a3b8', wraplength=930).pack(anchor='w', pady=(12, 0))
    root.after(100, poll)
    root.after(300, refresh)
    root.mainloop()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

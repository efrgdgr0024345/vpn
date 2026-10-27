"""Optional live socket snapshots; Tk objects remain on the main thread."""
from datetime import datetime, timezone
import queue
import threading
import connections
from safe_io import private_write


def open_connections(parent):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    window = tk.Toplevel(parent)
    window.title('Connections · observed TCP/UDP sockets, not a full audit')
    window.geometry('1140x720')
    window.minsize(860, 580)
    window.configure(bg='#0b1220')
    outer = ttk.Frame(window, padding=18)
    outer.pack(fill='both', expand=True)
    ttk.Label(outer, text='↔  Connections', style='Title.TLabel').pack(anchor='w')
    ttk.Label(outer, text='Local / peer endpoints are visible here. Direction is UNKNOWN — a peer is not proof of an outbound connection.',
              foreground='#fbbf24', wraplength=1050).pack(anchor='w', pady=(10, 4))
    ttk.Label(outer, text='TCP/UDP snapshots in this network namespace only; permissions may hide processes. Short-lived sockets can be missed. No payloads or DNS lookups.',
              wraplength=1050).pack(anchor='w', pady=(0, 12))
    pane = ttk.Frame(outer)
    pane.pack(fill='both', expand=True)
    columns = ('protocol', 'state', 'local', 'peer', 'process', 'direction')
    tree = ttk.Treeview(pane, columns=columns, show='headings', selectmode='browse')
    names = ('Protocol', 'State', 'Local endpoint', 'Peer endpoint', 'Process (if visible)', 'Direction')
    for key, name, width in zip(columns, names, (65, 100, 225, 225, 250, 100)):
        tree.heading(key, text=name)
        tree.column(key, width=width, minwidth=60, stretch=True)
    vertical = ttk.Scrollbar(pane, orient='vertical', command=tree.yview)
    horizontal = ttk.Scrollbar(pane, orient='horizontal', command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky='nsew')
    vertical.grid(row=0, column=1, sticky='ns')
    horizontal.grid(row=1, column=0, sticky='ew')
    pane.rowconfigure(0, weight=1)
    pane.columnconfigure(0, weight=1)
    status = tk.StringVar(value='No snapshot yet.')
    ttk.Label(outer, textvariable=status, wraplength=1050).pack(anchor='w', pady=10)
    history = tk.Text(outer, height=7, wrap='none', bg='#111d30', fg='#cbd5e1', font=('DejaVu Sans Mono', 9), padx=8, pady=8)
    history.pack(fill='x')
    history.configure(state='disabled')
    ttk.Label(outer, text='History: latest 300 observed appearance/disappearance events, memory only. These are not definitive connection-open/close events.',
              foreground='#94a3b8', wraplength=1050).pack(anchor='w', pady=8)
    raw = tk.BooleanVar(value=False)
    ttk.Checkbutton(outer, text='Include sensitive unredacted endpoints and process identifiers when copying/saving (OFF by default)', variable=raw).pack(anchor='w')
    actions = ttk.Frame(outer)
    actions.pack(fill='x', pady=(12, 0))
    tracker = connections.Tracker()
    state = {'records': [], 'busy': False, 'monitor': False, 'closed': False,
             'poll_id': None, 'refresh_id': None, 'error': 'No snapshot yet.', 'snapshot_at': None}
    results = queue.Queue(maxsize=1)

    def refresh():
        if state['closed'] or state['busy']:
            return
        if state['refresh_id'] is not None:
            window.after_cancel(state['refresh_id'])
            state['refresh_id'] = None
        state['busy'] = True
        refresh_button.configure(state='disabled')
        status.set('Reading local socket metadata… No network traffic is generated.')
        def worker():
            try:
                results.put((connections.collect_connections(), None))
            except connections.ConnectionError as error:
                results.put((None, str(error)))
            except Exception:
                results.put((None, 'Socket snapshot unavailable or unsupported. No complete connection visibility is assumed.'))
        threading.Thread(target=worker, daemon=True).start()

    def update_display():
        text = connections.format_export(state['records'], tracker.events, redacted=True, snapshot_at=state['snapshot_at'])
        history.configure(state='normal')
        history.delete('1.0', 'end')
        history.insert('1.0', text)
        history.see('end')
        history.configure(state='disabled')

    def poll():
        if state['closed']:
            return
        try:
            records, error = results.get_nowait()
        except queue.Empty:
            pass
        else:
            state['busy'] = False
            refresh_button.configure(state='normal')
            state['error'] = error
            if error:
                status.set(error + ' Any displayed rows are the LAST successful snapshot, not current.')
                state['monitor'] = False
                monitor_button.configure(text='Start 2-second monitor')
            else:
                state['snapshot_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
                state['records'] = records
                tracker.update(records)
                for item in tree.get_children():
                    tree.delete(item)
                for record in records:
                    tree.insert('', 'end', values=tuple(record.get(key, 'UNKNOWN') for key in columns))
                status.set(state['snapshot_at'] + ' • ' + str(len(records)) + ' observed socket(s) • ' + str(len(tracker.events)) + ' retained events • direction UNKNOWN • ' +
                           ('Monitoring enabled' if state['monitor'] else 'Monitoring stopped; snapshot only'))
                update_display()
            if state['monitor']:
                state['refresh_id'] = window.after(2000, refresh)
        state['poll_id'] = window.after(100, poll)

    def toggle_monitor():
        state['monitor'] = not state['monitor']
        monitor_button.configure(text='Stop monitor' if state['monitor'] else 'Start 2-second monitor')
        if state['monitor']:
            refresh()
        else:
            if state['refresh_id'] is not None:
                window.after_cancel(state['refresh_id'])
                state['refresh_id'] = None
            status.set('Monitoring stopped. A running read may finish; displayed data is a snapshot only.')

    def text_for_export():
        if raw.get() and not messagebox.askokcancel('Sensitive connection metadata',
            'This export includes local/remote IP addresses, ports and process identifiers. '
            'Review it before sharing. Export unredacted metadata?', parent=window):
            return None
        text = connections.format_export(state['records'], tracker.events, redacted=not raw.get(), snapshot_at=state['snapshot_at'])
        if state['error']:
            text = 'WARNING: latest snapshot unavailable; shown records may be stale.\n' + text
        return text

    def copy():
        text = text_for_export()
        if text is not None:
            window.clipboard_clear()
            window.clipboard_append(text)
            status.set('Connection snapshot/history copied. Review before sharing; keep app open until pasted.')

    def save():
        text = text_for_export()
        if text is None:
            return
        path = filedialog.asksaveasfilename(parent=window, title='Save reviewed connection metadata',
                                            initialfile='connections-redacted.txt' if not raw.get() else 'connections-SENSITIVE.txt',
                                            defaultextension='.txt', filetypes=[('Text', '*.txt')])
        if path:
            try:
                private_write(path, text)
                status.set('Saved only because you requested it. Review the file before sharing.')
            except OSError:
                messagebox.showerror('Save failed', 'Choose a writable location.', parent=window)

    def close():
        state['closed'] = True
        for key in ('poll_id', 'refresh_id'):
            if state[key] is not None:
                window.after_cancel(state[key])
        window.destroy()

    refresh_button = ttk.Button(actions, text='↻ Snapshot', command=refresh)
    refresh_button.pack(side='left', padx=(0, 8))
    monitor_button = ttk.Button(actions, text='Start 2-second monitor', command=toggle_monitor)
    monitor_button.pack(side='left', padx=(0, 8))
    ttk.Button(actions, text='Copy metadata', command=copy).pack(side='left', padx=(0, 8))
    ttk.Button(actions, text='Save metadata', command=save).pack(side='left', padx=(0, 8))
    ttk.Button(actions, text='Close', command=close).pack(side='right')
    window.protocol('WM_DELETE_WINDOW', close)
    state['poll_id'] = window.after(100, poll)
    refresh()
    return window

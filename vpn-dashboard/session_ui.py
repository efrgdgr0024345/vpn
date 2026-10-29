"""Local-only, bounded session event viewer. No raw OpenVPN log forwarding."""
from datetime import datetime,timezone
import queue
import threading
import session_channel
import install_audit
from safe_io import private_write


def session_report():
    try:
        snapshot=session_channel.request()
        return ('live',snapshot['state'],
                'Live session state: '+snapshot['state']+'\n'
                'Connection details were observed at startup or the latest reported stage.\n'
                'Tunnel initialization does not certify DNS or leak protection.\n\n'
                +session_channel.format_events(snapshot))
    except (OSError,session_channel.ChannelError,ValueError,TypeError,KeyError):
        try:
            record=session_channel.read_last()
            snapshot=record['snapshot']
            status='not recorded' if record['exit_status'] is None else str(record['exit_status'])
            return ('saved',snapshot['state'],
                    'Saved last attempt: '+snapshot['state']+'\n'
                    'OpenVPN exit status: '+status+'\n'
                    'This root-written record is read-only to the desktop user. It does not describe current network state.\n\n'
                    +session_channel.format_events(snapshot))
        except (OSError,session_channel.ChannelError,ValueError,TypeError,KeyError):
            return ('unavailable','unavailable',None)


def open_session_window(parent):
    import tkinter as tk
    from tkinter import ttk,filedialog,messagebox
    window=tk.Toplevel(parent)
    window.title('VPN Desk · session log and installation audit')
    window.geometry('950x650')
    frame=ttk.Frame(window,padding=16)
    frame.pack(fill='both',expand=True)
    state=tk.StringVar(value='Checking the protected local helper…')
    ttk.Label(frame,textvariable=state,wraplength=880).pack(anchor='w')
    ttk.Label(frame,text='Local connection details and events, including network addresses. Passwords, tokens, private keys and packet payloads are excluded.',
              wraplength=880).pack(anchor='w',pady=(5,10))
    area=ttk.Frame(frame)
    area.pack(fill='both',expand=True)
    text=tk.Text(area,wrap='word',height=20,bg='#111d30',fg='#e2e8f0',padx=12,pady=12)
    text.pack(side='left',fill='both',expand=True)
    scrollbar=ttk.Scrollbar(area,command=text.yview)
    scrollbar.pack(side='right',fill='y')
    text.configure(yscrollcommand=scrollbar.set)
    current={'text':'','busy':False,'alive':True}
    inbox=queue.Queue(maxsize=1)
    def display(value):
        if current['text']==value:
            return
        first,last=text.yview()
        current['text']=value
        text.configure(state='normal')
        text.delete('1.0','end')
        text.insert('1.0',value)
        text.configure(state='disabled')
        if last>=.999:
            text.see('end')
        else:
            text.yview_moveto(first)
    def refresh():
        if current['busy'] or not current['alive']:
            return
        current['busy']=True
        def worker():
            inbox.put(session_report())
        threading.Thread(target=worker,daemon=True).start()
    def poll():
        if not current['alive']:
            return
        try:
            source,value,report=inbox.get_nowait()
        except queue.Empty:
            pass
        else:
            current['busy']=False
            if report is not None:
                state.set(('Live protected helper: ' if source=='live' else 'Saved last attempt: ')+value.replace('_',' '))
                display(report)
            else:
                state.set('No live helper response. Any displayed events are the last observed snapshot.')
                if current['text'].startswith('Live session state: '):
                    display(current['text'].replace('Live session state: ', 'Previously observed session state: ', 1))
        window.after(150,poll)
    def cycle():
        if current['alive']:
            refresh()
            window.after(500,cycle)
    def audit():
        report=install_audit.format_report(install_audit.check())
        messagebox.showinfo('Installation baseline check',report,parent=window)
    def save():
        path=filedialog.asksaveasfilename(parent=window,title='Save local session events',
                                        initialfile='vpn-session-events.txt',defaultextension='.txt')
        if path:
            try:
                header=('VPN Desk local session observation\nExport UTC: '
                        +datetime.now(timezone.utc).isoformat(timespec='seconds')+'\n'
                        'This is a local observation, not a cryptographically attested audit trail.\n\n')
                private_write(path,header+current['text'])
            except OSError:
                messagebox.showerror('Export failed','Could not privately save the events.',parent=window)
    controls=ttk.Frame(frame)
    controls.pack(fill='x',pady=(10,0))
    ttk.Button(controls,text='Refresh session',command=refresh).pack(side='left',padx=(0,8))
    ttk.Button(controls,text='Save local log',command=save).pack(side='left',padx=(0,8))
    ttk.Button(controls,text='Check installed code',command=audit).pack(side='left')
    def close():
        current['alive']=False
        window.destroy()
    window.protocol('WM_DELETE_WINDOW',close)
    display('No session events have been observed.\n')
    window.after(100,poll)
    window.after(150,cycle)
    return window

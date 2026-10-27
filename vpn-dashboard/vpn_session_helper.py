#!/usr/bin/env python3
"""Explicit root session: close/verify portal, serialize against portal opening."""
import fcntl
import os
from pathlib import Path
import stat
import select
import signal
import subprocess
import time
import session_channel
import network_setup
import portal_helper
from security import PROFILE, SERVICE_USER, load_policy, read_trusted, service_account, validate_profile


def openvpn_argv():
    policy = load_policy()
    validate_profile(read_trusted(PROFILE, private=True), policy)
    service_account()
    executable = next((p for p in ('/usr/sbin/openvpn', '/usr/bin/openvpn') if Path(p).is_file()), None)
    if not executable:
        raise portal_helper.Refused('OpenVPN is not installed.')
    return [executable, '--config', str(PROFILE), '--auth-user-pass', '--auth-nocache',
            '--mssfix', '1300', '--script-security', '1',
            '--allow-compression', 'no', '--user', SERVICE_USER,
            '--group', SERVICE_USER, '--persist-key', '--persist-tun']


def prepare_session():
    if os.geteuid() != 0:
        raise portal_helper.Refused('This session helper requires explicit terminal sudo.')
    command = openvpn_argv()
    portal_helper.check_network()
    network_setup.prepare()
    portal_helper.act('close')
    if portal_helper.act('status').get('state') != 'closed':
        raise portal_helper.Refused('Portal closure could not be verified. VPN not started.')
    return command


def main(owner_uid):
    try:
        if os.geteuid() != 0:
            raise portal_helper.Refused('Requires explicit sudo in a visible terminal.')
        if type(owner_uid) is not int or owner_uid<=0:
            raise portal_helper.Refused('Run the app as your desktop user and authenticate through sudo.')
        fd = os.open('/run/vpn-dashboard-portal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                raise portal_helper.Refused('Unsafe runtime lock file.')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            command = prepare_session()
            print('Portal verified closed. Starting OpenVPN; shared action lock held until exit.', flush=True)
            # One more check after firewall validation. External root network
            # managers remain outside this lock's trust boundary.
            portal_helper.check_network()
            return controlled_session(command,owner_uid)
    except (portal_helper.Refused,session_channel.ChannelError, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print('VPN NOT CONFIRMED: ' + (str(exc) if isinstance(exc, portal_helper.Refused)
                                      else 'Session verification or action lock failed. No automatic retry.'), flush=True)
        return 1


def controlled_session(command,owner_uid):
    if type(owner_uid) is not int or owner_uid<=0:
        raise portal_helper.Refused('Start the app as your normal desktop user, then authenticate with sudo.')
    if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
        raise portal_helper.Refused('This controlled session requires Linux process-descriptor signaling.')
    events=session_channel.Events()
    events.add('guard_checked')
    events.add('dns_configured')
    events.add('credentials')
    process=None
    pidfd=None
    stop_at=None
    def stop():
        nonlocal stop_at
        if stop_at is None:
            events.add('stopping')
            stop_at=time.monotonic()
        try:
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd,signal.SIGTERM)
            elif process is not None:
                # Constructor cleanup only: this Popen object still owns the
                # just-created child if acquiring its pidfd failed. No PID is
                # ever supplied by a caller or read from a mutable file.
                process.terminate()
        except ProcessLookupError:
            # The child already exited; there is nothing left to signal.
            return
    previous_handler=signal.getsignal(signal.SIGTERM)
    try:
        with session_channel.Server(owner_uid,events,stop):
            if stop_at is not None:
                return 0
            process=subprocess.Popen(command,cwd='/',extra_groups=[],stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,
                                     env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'})
            pidfd=os.pidfd_open(process.pid)
            if stop_at is not None:
                signal.pidfd_send_signal(pidfd,signal.SIGTERM)
            signal.signal(signal.SIGTERM,lambda number,frame:stop())
            buffer=b''
            discarding=False
            checked_at=0.0
            os.set_blocking(process.stdout.fileno(),False)
            while True:
                try:
                    if stop_at is None and time.monotonic()-checked_at>=3:
                        if not network_setup.verify_during_session():
                            events.add('dns_repaired')
                        checked_at=time.monotonic()
                    if stop_at is not None and time.monotonic()-stop_at>10 and process.poll() is None:
                        signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    if select.select([process.stdout],[],[],.25)[0]:
                        chunk=os.read(process.stdout.fileno(),4096)
                        if not chunk and process.poll() is not None:
                            break
                        for part in chunk.splitlines(keepends=True):
                            complete=part.endswith(b'\n')
                            if not discarding:
                                buffer+=part
                                if len(buffer)>8192:
                                    buffer=b''
                                    discarding=True
                            if complete:
                                if not discarding:
                                    code=session_channel.classify(buffer.decode('utf-8',errors='replace').strip())
                                    if code:
                                        events.add(code)
                                        print(session_channel.MESSAGES[code],flush=True)
                                buffer=b''
                                discarding=False
                    if process.poll() is not None:
                        break
                except KeyboardInterrupt:
                    stop()
            result=process.wait()
            events.add('stopped' if result==0 or stop_at is not None else 'process_failed')
            print(session_channel.MESSAGES['stopped' if result==0 or stop_at is not None else 'process_failed'],flush=True)
            # Leave the final status available briefly for the desktop poller.
            time.sleep(1)
            return result
    except (portal_helper.Refused,OSError,ValueError,session_channel.ChannelError):
        events.add('process_failed')
        print('VPN stopped after a session or network-policy verification failure. Keep the guard enabled.',flush=True)
        return 1
    finally:
        signal.signal(signal.SIGTERM,previous_handler)
        if process is not None:
            if process.poll() is None:
                stop()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if pidfd is not None:
                        signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
        if pidfd is not None:
            os.close(pidfd)

if __name__ == '__main__':
    raise SystemExit('Use the installed privileged entry point; do not sudo a checkout script.')

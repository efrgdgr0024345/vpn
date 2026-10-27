"""Bounded diagnostic capture and atomic private exports."""
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time


class OutputLimitExceeded(subprocess.SubprocessError):
    pass


def bounded_run(argv, *, input=None, timeout=6, check=False, text=True,
                capture_output=True, env=None, limit=2_000_000):
    if not text or not capture_output:
        raise ValueError('Only bounded text capture is supported.')
    deadline = time.monotonic() + timeout
    output = { 'stdout': bytearray(), 'stderr': bytearray() }
    pending = memoryview(input.encode('utf-8') if input else b'')
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if pending else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=True)
    try:
        with selectors.DefaultSelector() as selector:
            for label in ('stdout', 'stderr'):
                stream = getattr(process, label)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    if key.data == 'stdin':
                        try:
                            count = os.write(key.fileobj.fileno(), pending[:4096])
                            pending = pending[count:]
                        except BrokenPipeError:
                            pending = memoryview(b'')
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            if sum(map(len, output.values())) + len(chunk) > limit:
                                raise OutputLimitExceeded('Diagnostic output exceeds the byte limit.')
                            output[key.data].extend(chunk)
        result = subprocess.CompletedProcess(argv, process.wait(timeout=max(0.001, deadline - time.monotonic())),
                                             output['stdout'].decode('utf-8'), output['stderr'].decode('utf-8'))
        if check:
            result.check_returncode()
        return result
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            process.poll()  # Reap an already exited owned child, if available.
        process.wait()
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def private_write(path, text):
    """Replace the selected filename with a complete 0600 file, never follow it."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.vpn-desk-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

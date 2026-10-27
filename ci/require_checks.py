"""Gate installation on a successful push-CI run for this exact commit."""
import json
import os
import re
import subprocess
import time


class GateError(RuntimeError):
    pass


def approved(runs, revision):
    matching=[r for r in runs if r.get('head_sha')==revision and r.get('event')=='push']
    if any(r.get('status')=='completed' and r.get('conclusion')=='success' for r in matching):
        return True
    if matching and all(r.get('status')=='completed' for r in matching):
        raise GateError('CI did not pass for this deployment commit; installation blocked.')
    return False


def all_approved(workflows,revision):
    # A green functional run alone cannot authorize deployment after security
    # analysis is enabled. Both must match these exact source bytes.
    ready=[]
    for name in ('checks.yml','security.yml'):
        ready.append(approved(workflows.get(name,[]),revision))
    return all(ready)


def main():
    repo=os.environ.get('GITHUB_REPOSITORY','')
    revision=os.environ.get('GITHUB_SHA','')
    if repo!='efrgdgr0024345/vpn' or not re.fullmatch(r'[0-9a-f]{40}',revision):
        raise GateError('Unexpected deployment context.')
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        workflows={}
        for name in ('checks.yml','security.yml'):
            path=f'repos/{repo}/actions/workflows/{name}/runs?head_sha={revision}&event=push&per_page=20'
            result=subprocess.run(['gh','api',path],capture_output=True,text=True,timeout=20)
            if result.returncode:
                raise GateError('Cannot verify functional/security CI status; installation blocked.')
            try:
                workflows[name]=json.loads(result.stdout)['workflow_runs']
            except (ValueError,KeyError,TypeError):
                raise GateError('Unsupported CI status response; installation blocked.') from None
        if all_approved(workflows,revision):
            print('Successful functional and security push-CI verified for deployment commit '+revision+'.')
            return
        print('Waiting for CI on the deployment commit...',flush=True)
        time.sleep(5)
    raise GateError('CI verification timed out; installation blocked.')


if __name__=='__main__':
    try:
        main()
    except (GateError,OSError,subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc) if isinstance(exc,GateError) else 'CI verification failed; installation blocked.')

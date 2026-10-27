"""Run repository unit suites with secret-free failure location annotations."""
from pathlib import Path
import re
import sys
import traceback
import unittest

ROOT=Path(__file__).resolve().parents[1]


class Result(unittest.TextTestResult):
    def annotate(self,test,error):
        name=test.id().split(' ',1)[0]
        if not re.fullmatch(r'[A-Za-z0-9_.]{1,200}',name):
            name='unit-test'
        frames=traceback.extract_tb(error[2])
        local=[frame for frame in frames if str(frame.filename).startswith(str(ROOT)+'/')]
        location=''
        if local:
            frame=local[-1]
            path=str(Path(frame.filename).relative_to(ROOT))
            if re.fullmatch(r'[A-Za-z0-9_./-]{1,240}',path):
                location='file='+path+',line='+str(frame.lineno)+','
        kind=error[0].__name__
        if not re.fullmatch(r'[A-Za-z0-9_]{1,80}',kind):
            kind='Exception'
        # Never expose error values, expected/actual private data or locals.
        print('::error '+location+'title=Unit test failure::'+name+' failed with '+kind+'.',flush=True)

    def addFailure(self,test,error):
        super().addFailure(test,error)
        self.annotate(test,error)

    def addError(self,test,error):
        super().addError(test,error)
        self.annotate(test,error)


if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('ci/tests','vpn-dashboard/tests'):
        raise SystemExit('Choose a fixed repository unit-test suite.')
    folder=ROOT/sys.argv[1]
    sys.path.insert(0,str(folder.parent))
    suite=unittest.TestLoader().discover(str(folder))
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)

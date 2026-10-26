from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from require_checks import approved,GateError


class DeploymentGateTests(unittest.TestCase):
    def run_result(self,**changes):
        return {'head_sha':'a'*40,'event':'push','status':'completed','conclusion':'success',**changes}

    def test_other_commit_and_other_event_cannot_authorize_installation(self):
        self.assertFalse(approved([self.run_result(head_sha='b'*40)],'a'*40))
        self.assertFalse(approved([self.run_result(event='pull_request')],'a'*40))

    def test_same_commit_success_is_required(self):
        self.assertTrue(approved([self.run_result()],'a'*40))
        for conclusion in ('failure','cancelled','skipped','timed_out'):
            with self.subTest(conclusion=conclusion),self.assertRaises(GateError):
                approved([self.run_result(conclusion=conclusion)],'a'*40)

    def test_waits_for_pending_retry_and_accepts_a_successful_retry(self):
        failed=self.run_result(conclusion='failure')
        pending=self.run_result(status='in_progress',conclusion=None)
        self.assertFalse(approved([failed,pending],'a'*40))
        self.assertTrue(approved([failed,self.run_result()],'a'*40))


if __name__=='__main__':
    unittest.main()

from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from report_security import summaries


class SecurityReportTests(unittest.TestCase):
    def document(self,severity='8.1',**changes):
        result={'ruleId':'py/test-rule','message':{'text':'SECRET RAW SOURCE'},
                'locations':[{'physicalLocation':{'artifactLocation':{'uri':'ops/example.py'},'region':{'startLine':12}}}]}
        result.update(changes)
        return {'runs':[{'tool':{'driver':{'rules':[{'id':'py/test-rule','properties':{'security-severity':severity}}]}},
                         'results':[result]}]}

    def test_medium_and_higher_security_findings_block_without_printing_raw_messages(self):
        for severity in ('4.0','7.0','9.9'):
            row=list(summaries(self.document(severity)))[0]
            self.assertTrue(row['blocking'])
            self.assertNotIn('SECRET',repr(row))
            self.assertEqual(row['file'],'ops/example.py')

    def test_quality_errors_block_and_warnings_remain_visible(self):
        self.assertTrue(list(summaries(self.document('-1',level='error')))[0]['blocking'])
        self.assertFalse(list(summaries(self.document('-1',level='warning')))[0]['blocking'])

    def test_suppression_does_not_hide_a_security_finding(self):
        row=list(summaries(self.document(suppressions=[{'kind':'inSource'}])))[0]
        self.assertTrue(row['blocking'])
        self.assertTrue(row['suppressed'])

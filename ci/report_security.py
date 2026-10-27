"""Expose bounded SARIF rule/location summaries through GitHub Checks.

Do not print raw code, snippets or diagnostic messages that could contain a
mistakenly committed secret. The complete findings remain in GitHub CodeQL.
"""
import json
from pathlib import Path,PurePosixPath
import re
import sys
from urllib.parse import unquote


def summaries(document):
    for run in document.get('runs',[]):
        rules={r.get('id'):r for r in run.get('tool',{}).get('driver',{}).get('rules',[])}
        for result in run.get('results',[]):
            if result.get('suppressions'):
                # Suppressed results remain visible for review, not silently
                # excluded by this local reporting/gating helper.
                suppressed=True
            else:
                suppressed=False
            rule_id=result.get('ruleId','unknown-rule')
            if not isinstance(rule_id,str) or not re.fullmatch(r'[A-Za-z0-9_./:-]{1,120}',rule_id):
                rule_id='unknown-rule'
            properties=rules.get(rule_id,{}).get('properties',{})
            try:
                severity=float(properties.get('security-severity',-1))
            except (ValueError,TypeError):
                severity=-1
            blocking=severity>=4 or result.get('level')=='error'
            location=next(iter(result.get('locations',[])),{}).get('physicalLocation',{})
            uri=unquote(location.get('artifactLocation',{}).get('uri',''))
            path=PurePosixPath(uri)
            safe_path=(uri if uri and not path.is_absolute() and '..' not in path.parts
                       and re.fullmatch(r'[A-Za-z0-9_./-]{1,240}',uri) else None)
            line=location.get('region',{}).get('startLine',1)
            if type(line) is not int or line<1:
                line=1
            yield {'rule':rule_id,'security_severity':severity,'blocking':blocking,
                   'file':safe_path,'line':line,'suppressed':suppressed}


def main():
    if len(sys.argv)!=2:
        raise SystemExit('Supply the local CodeQL result directory.')
    paths=sorted(Path(sys.argv[1]).glob('*.sarif'))
    if not paths or len(paths)>10:
        raise SystemExit('::error title=Security analysis::CodeQL results are missing or unsupported.')
    count=blocked=0
    for path in paths:
        if path.stat().st_size>20_000_000:
            raise SystemExit('::error title=Security analysis::CodeQL results exceed the reporting limit.')
        for row in summaries(json.loads(path.read_text())):
            count+=1
            blocked+=row['blocking']
            if count<=100:
                kind='error' if row['blocking'] else 'warning'
                location=('file='+row['file']+',line='+str(row['line'])+',') if row['file'] else ''
                note='CodeQL rule '+row['rule']+'; review the finding in repository Security / Code scanning.'
                if row['suppressed']:
                    note+=' The result is marked suppressed in SARIF.'
                print('::'+kind+' '+location+'title=CodeQL finding::'+note,flush=True)
    print(json.dumps({'codeql_findings':count,'blocking_findings':blocked},sort_keys=True))
    return 1 if blocked else 0


if __name__=='__main__':
    raise SystemExit(main())

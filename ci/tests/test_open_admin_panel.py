import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'ops'))
import open_admin_panel as browser

PUBLIC_DER = b'public CA unit fixture'
PUBLIC_PEM = '-----BEGIN CERTIFICATE-----\n'+base64.b64encode(PUBLIC_DER).decode()+'\n-----END CERTIFICATE-----\n'
FINGERPRINT = hashlib.sha256(PUBLIC_DER).hexdigest()
URL = 'https://api.github.com/repos/efrgdgr0024345/vpn/check-runs/123/annotations'


def report(pem=PUBLIC_PEM, fingerprint=FINGERPRINT):
    return [{'title': 'VPN lab install-admin-panel', 'message': json.dumps({
        'version': 1, 'panel_url': browser.ORIGIN, 'credential_contents_returned': False,
        'ca_certificate_sha256': fingerprint, 'ca_certificate_pem': pem})}]


class PublicCertificateTests(unittest.TestCase):
    def test_only_expected_public_certificate_is_selected(self):
        self.assertEqual(browser.annotation_certificate(report(), FINGERPRINT), PUBLIC_PEM.encode())
        for value in (report()+report(), [], {'message':'private'},
                      report(fingerprint='a'*64), report(pem=PUBLIC_PEM+'PRIVATE')):
            with self.subTest(value=value), self.assertRaises(browser.SetupError):
                browser.annotation_certificate(value, FINGERPRINT)
        changed=report()
        value=json.loads(changed[0]['message'])
        value['credential_contents_returned']=True
        changed[0]['message']=json.dumps(value)
        with self.assertRaises(browser.SetupError):
            browser.annotation_certificate(changed,FINGERPRINT)

    def test_wrong_hash_private_key_and_multiple_certificates_rejected(self):
        for pem, fingerprint in ((PUBLIC_PEM, 'a'*64), (PUBLIC_PEM*2, FINGERPRINT),
                                 (PUBLIC_PEM.replace('CERTIFICATE','PRIVATE KEY'), FINGERPRINT)):
            with self.subTest(pem=pem), self.assertRaises(browser.SetupError):
                browser.certificate_bytes(pem, fingerprint)

    def test_only_fixed_https_github_report_url_is_accepted(self):
        for url in (URL.replace('https:', 'http:'), URL+'?page=2', URL.replace('efrgdgr0024345','attacker'),
                    'https://172.27.240.1/ca.crt', 'file:///etc/shadow'):
            with self.subTest(url=url), patch.object(browser,'urlopen') as download, self.assertRaises(browser.SetupError):
                browser.download_certificate(url,FINGERPRINT)
            download.assert_not_called()

    def test_bounded_verified_https_download_and_redirect_refusal(self):
        class Response:
            def __init__(self, url=URL, data=None):
                self.url=url
                self.data=json.dumps(report()).encode() if data is None else data
            def __enter__(self): return self
            def __exit__(self,*args): return False
            def geturl(self): return self.url
            def read(self,limit):
                self.limit=limit
                return self.data[:limit]
        response=Response()
        with patch.object(browser,'urlopen',return_value=response) as download:
            self.assertEqual(browser.download_certificate(URL,FINGERPRINT),PUBLIC_PEM.encode())
        self.assertEqual(download.call_args.kwargs,{'timeout':20})
        self.assertEqual(download.call_args.args[0].full_url,URL)
        self.assertEqual(response.limit,1_000_001)
        for response in (Response(URL+'/redirect'),Response(data=b'x'*1_000_001)):
            with patch.object(browser,'urlopen',return_value=response), self.assertRaises(browser.SetupError):
                browser.download_certificate(URL,FINGERPRINT)


class ProfileTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        # The executor maps filesystem ancestors to a nonzero owner. Only tests
        # substitute that mapping; production trusts uid0 and the desktop uid.
        with tempfile.TemporaryDirectory(prefix='.panel-test-',dir=Path(__file__).resolve().parents[2]) as directory, \
             patch.object(browser,'ROOT_UID',Path('/').lstat().st_uid):
            home=Path(directory)
            home.chmod(0o700)
            yield home

    def fake_command(self,argv,**kwargs):
        database=Path(argv[argv.index('-d')+1].removeprefix('sql:'))
        if '-N' in argv:
            (database/'cert9.db').write_bytes(b'fixture database')
            (database/'cert9.db').chmod(0o600)
            return 0,b''
        if '-L' in argv:
            if '-n' not in argv:
                return 0, (browser.NICKNAME+'    C,,\n').encode()
            pem=database/'trusted-public.pem'
            return (0,pem.read_bytes()) if pem.exists() else (255,b'')
        if '-A' in argv:
            pem=database/'trusted-public.pem'
            pem.write_bytes(Path(argv[argv.index('-i')+1]).read_bytes())
            pem.chmod(0o600)
            return 0,b''
        raise AssertionError('Unexpected fixture command')

    def test_isolated_profile_creation_and_idempotence(self):
        with self.fixture() as home, patch.object(browser,'command',side_effect=self.fake_command):
            original=home/'.mozilla'/'firefox'/'personal'
            original.mkdir(parents=True)
            marker=original/'keep'
            marker.write_text('personal data')
            profile=browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            self.assertEqual(profile,home/'.local/share/vpn-lab-admin/browser')
            self.assertEqual(browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home),profile)
            self.assertEqual(marker.read_text(),'personal data')
            self.assertEqual(profile.stat().st_mode&0o777,0o700)
            self.assertEqual((profile/'user.js').read_bytes(),browser.USER_JS)
            manifest=json.loads((profile.parent/'setup.json').read_text())
            self.assertTrue(manifest['ready'])
            self.assertEqual(manifest['ca_sha256'],FINGERPRINT)
            self.assertEqual((profile.parent/'ca.crt').stat().st_mode&0o777,0o600)

    def test_root_run_and_missing_certutil_refused_before_profile_writes(self):
        with self.fixture() as home:
            with patch.object(browser.os,'geteuid',return_value=0), self.assertRaises(browser.SetupError):
                browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            with patch.object(browser,'CERTUTIL',home/'missing-certutil'), self.assertRaises(browser.SetupError):
                browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            self.assertFalse((home/'.local').exists())

    def test_existing_profile_without_our_manifest_is_preserved(self):
        with self.fixture() as home:
            base=home/'.local/share/vpn-lab-admin'
            base.mkdir(parents=True,mode=0o700)
            marker=base/'browser'
            marker.mkdir()
            (marker/'personal.txt').write_text('keep')
            with self.assertRaises(browser.SetupError):
                browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            self.assertEqual((marker/'personal.txt').read_text(),'keep')
            self.assertFalse((base/'setup.json').exists())

    def test_changed_ca_and_preferences_are_preserved_and_refused(self):
        with self.fixture() as home, patch.object(browser,'command',side_effect=self.fake_command):
            profile=browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            (profile/'user.js').write_text('user custom setting')
            with self.assertRaises(browser.SetupError):
                browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
            self.assertEqual((profile/'user.js').read_text(),'user custom setting')
            (profile/'user.js').write_bytes(browser.USER_JS)
            ca=PUBLIC_PEM.replace(base64.b64encode(PUBLIC_DER).decode(),base64.b64encode(b'another public CA').decode())
            with self.assertRaises(browser.SetupError):
                browser.profile_setup(ca,hashlib.sha256(b'another public CA').hexdigest(),home=home)
            self.assertEqual((profile.parent/'ca.crt').read_text(),PUBLIC_PEM)

    def test_partial_setup_resumes_after_failed_nss_initialization(self):
        with self.fixture() as home:
            with patch.object(browser, 'command', side_effect=browser.SetupError('fixture failure')):
                with self.assertRaises(browser.SetupError):
                    browser.profile_setup(PUBLIC_PEM, FINGERPRINT, home=home)
            manifest = home/'.local/share/vpn-lab-admin/setup.json'
            self.assertFalse(json.loads(manifest.read_text())['ready'])
            with patch.object(browser, 'command', side_effect=self.fake_command):
                browser.profile_setup(PUBLIC_PEM, FINGERPRINT, home=home)
            self.assertTrue(json.loads(manifest.read_text())['ready'])

    def test_busy_setup_lock_refuses_without_replacing_profile(self):
        import fcntl
        with self.fixture() as home, patch.object(browser, 'command', side_effect=self.fake_command):
            profile = browser.profile_setup(PUBLIC_PEM, FINGERPRINT, home=home)
            path = profile.parent/'setup.lock'
            fd = os.open(path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaisesRegex(browser.SetupError, 'Another panel setup'):
                    browser.profile_setup(PUBLIC_PEM, FINGERPRINT, home=home)
            finally:
                os.close(fd)

    def test_symlink_ancestor_and_unsafe_file_links_refused(self):
        with self.fixture() as home:
            elsewhere=home/'elsewhere'
            elsewhere.mkdir()
            (home/'.local').symlink_to(elsewhere,target_is_directory=True)
            with self.assertRaises(browser.SetupError):
                browser.profile_setup(PUBLIC_PEM,FINGERPRINT,home=home)
        with self.fixture() as home:
            value=home/'value'
            value.write_text('public')
            value.chmod(0o600)
            link=home/'link'
            link.symlink_to(value)
            with self.assertRaises(OSError): browser.read_user_file(link)
            link.unlink()
            os.link(value,link)
            with self.assertRaises(browser.SetupError): browser.read_user_file(value)

    @unittest.skipUnless(Path('/usr/bin/certutil').is_file() and Path('/usr/bin/openssl').is_file(), 'NSS and OpenSSL required')
    def test_actual_nss_import_and_relaunch_use_separate_profile(self):
        with self.fixture() as home:
            ca=home/'fixture-ca.crt'
            result=subprocess.run(['/usr/bin/openssl','req','-new','-x509','-newkey','ec',
                '-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(home/'fixture.key'),
                '-out',str(ca),'-subj','/CN=Public panel fixture','-days','1',
                '-addext','basicConstraints=critical,CA:TRUE'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(result.returncode,0)
            pem=ca.read_text()
            digest=hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
            profile=browser.profile_setup(pem,digest,home=home)
            # An existing matching CA with explicit distrust must not be
            # reported ready. The helper repairs only its verified CA entry.
            subprocess.run(['/usr/bin/certutil','-M','-d','sql:'+str(profile),'-n',browser.NICKNAME,'-t','p,,'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(browser.profile_setup(pem,digest,home=home),profile)
            self.assertEqual(browser.certificate_trust('sql:'+str(profile)), 'C,,')
            result=subprocess.run(['/usr/bin/certutil','-L','-d','sql:'+str(profile),'-n',browser.NICKNAME,'-a'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(hashlib.sha256(ssl.PEM_cert_to_DER_cert(result.stdout)).hexdigest(),digest)


if __name__=='__main__':
    unittest.main()

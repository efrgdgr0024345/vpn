from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import make_review_bundle as bundle


class ReviewBundleTests(unittest.TestCase):
    def test_archives_are_reproducible_and_do_not_include_untracked_material(self):
        revision=bundle.git('rev-parse','HEAD').decode().strip()
        with tempfile.TemporaryDirectory() as directory:
            first,second=Path(directory)/'first.zip',Path(directory)/'second.zip'
            self.assertEqual(bundle.build(first,revision),bundle.build(second,revision))
            with zipfile.ZipFile(first) as archive:
                names=archive.namelist()
                self.assertIn('REVIEW_MANIFEST.json',names)
                self.assertIn('source/README.md',names)
                self.assertTrue(all(name=='REVIEW_MANIFEST.json' or name.startswith('source/') for name in names))
                self.assertFalse(any(name.endswith(('.ovpn','.key','.pem')) for name in names))

    def test_named_branches_and_overwrite_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'review.zip'
            with self.assertRaises(RuntimeError):
                bundle.build(path,'main')
            path.write_text('KEEP')
            revision=bundle.git('rev-parse','HEAD').decode().strip()
            with self.assertRaises(FileExistsError):
                bundle.build(path,revision)
            self.assertEqual(path.read_text(),'KEEP')

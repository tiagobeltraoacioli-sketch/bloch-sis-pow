#!/usr/bin/env python3
"""Offline installer regressions using disposable assets, never network access."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).with_name('ci-install-scanner.sh')

class InstallerTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='bloch-scanner-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        self.mock = self.root / 'mock'; self.mock.mkdir()
        shutil.copyfile(INSTALLER, self.root / INSTALLER.name)
        self.script('uname', '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        self.script('curl', '''#!/bin/sh
printf 'download\\n' >> "$TEST_DOWNLOAD_LOG"
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then shift; out="$1"; fi
  shift
done
cp "$TEST_ASSET" "$out"
''')
        self.env = dict(os.environ, PATH=f"{self.mock}:{self.bin}:{os.environ['PATH']}",
                        CI_TOOLS_BIN=str(self.bin), TMPDIR=str(self.root),
                        TEST_ASSET=str(self.root / 'asset'), TEST_DOWNLOAD_LOG=str(self.root / 'downloads'))

    def script(self, name, text):
        p = self.mock / name; p.write_text(text); p.chmod(0o755)

    def asset(self, tool='osv-scanner', correct=True):
        binary = b'#!/bin/sh\necho verified-fixture\n'
        if tool == 'gitleaks':
            with tarfile.open(self.root / 'asset', 'w:gz') as archive:
                entry = tarfile.TarInfo('gitleaks'); entry.size = len(binary); entry.mode = 0o755
                archive.addfile(entry, io.BytesIO(binary))
            version, name = '8.18.4', 'gitleaks_8.18.4_linux_x64.tar.gz'
        else:
            (self.root / 'asset').write_bytes(binary)
            version, name = 'v1.9.2', 'osv-scanner_linux_amd64'
        digest = hashlib.sha256((self.root / 'asset').read_bytes()).hexdigest() if correct else '0' * 64
        (self.root / 'ci-scanner-checksums.txt').write_text(f'{tool} {version} {name} {digest}\n')
        return binary

    def run_installer(self, tool='osv-scanner'):
        return subprocess.run(['bash', str(self.root / INSTALLER.name), tool],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_existing_path_binary_is_never_trusted_or_executed(self):
        binary = self.asset(); marker = self.root / 'executed'; cached = self.bin / 'osv-scanner'
        cached.write_text(f"#!/bin/sh\ntouch '{marker}'\n"); cached.chmod(0o755)
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(cached.read_bytes(), binary)
        self.assertEqual((self.root / 'downloads').read_text(), 'download\n')

    def test_corrupt_download_does_not_replace_existing_binary(self):
        self.asset(correct=False); cached = self.bin / 'osv-scanner'; cached.write_text('old bytes')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(cached.read_text(), 'old bytes')

    def test_missing_or_duplicate_pin_refuses_before_download(self):
        self.asset(); pins = self.root / 'ci-scanner-checksums.txt'; pins.write_text(pins.read_text() * 2)
        self.assertNotEqual(self.run_installer().returncode, 0)
        pins.write_text('')
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertFalse((self.root / 'downloads').exists())

    def test_archive_is_verified_before_extracting_binary(self):
        binary = self.asset('gitleaks'); result = self.run_installer('gitleaks')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.bin / 'gitleaks').read_bytes(), binary)

    def test_symlink_is_replaced_without_modifying_its_target(self):
        binary = self.asset(); target = self.root / 'unrelated'; target.write_text('preserve')
        (self.bin / 'osv-scanner').symlink_to(target)
        self.assertEqual(self.run_installer().returncode, 0)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertFalse((self.bin / 'osv-scanner').is_symlink())
        self.assertEqual((self.bin / 'osv-scanner').read_bytes(), binary)

    def test_directory_target_is_refused_and_temporary_files_cleaned(self):
        self.asset(); target = self.root / 'unrelated'; target.mkdir()
        (self.bin / 'osv-scanner').symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(list(self.root.glob('bloch-scanner.*')), [])
        self.assertEqual(list(self.bin.glob('.*.verified.*')), [])

if __name__ == '__main__':
    unittest.main()

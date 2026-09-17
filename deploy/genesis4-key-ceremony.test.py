#!/usr/bin/env python3
"""Offline mocks only: ceremony credentials never enter child argv/env/files."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import termios
import time
import unittest

SCRIPT = Path(__file__).with_name('genesis4-key-ceremony.sh').resolve()
PASSPHRASE = b'disposable ceremony fixture passphrase'

class CeremonyPipeTests(unittest.TestCase):
    def exercise(self, fail=False, interrupt=False, allexport=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mocks = root / 'bin'
            mocks.mkdir()
            for name in ('ping', 'timeout', 'getent', 'host', 'ip'):
                path = mocks / name
                path.write_text('#!/bin/sh\nexit ' + ('0' if name == 'ip' else '1') + '\n')
                path.chmod(0o700)
            binary = mocks / 'mock-node'
            binary.write_text('#!' + sys.executable + '\n' + '''import os,sys,json,pathlib
secret = sys.stdin.buffer.read(4097)
assert len(secret) > 12 and len(secret) <= 4096
assert os.environ.get('BLOCH_KEYSTORE_PASSPHRASE_FD') == '0'
assert all(key not in os.environ for key in ('BLOCH_KEYSTORE_PASSPHRASE','BLOCH_KEYSTORE_PASSPHRASE_FILE','BLOCH_KEYSTORE_ALLOW_PLAINTEXT','KEYPASS','KEYPASS2'))
assert all(secret.decode() not in value for value in os.environ.values())
assert all(secret.decode() not in value for value in sys.argv)
with open(os.environ['MOCK_LOG'],'a') as log: log.write(json.dumps({'command':sys.argv[1],'pipe':True})+'\\n')
if os.environ.get('MOCK_FAIL') == '1': raise SystemExit(9)
path = pathlib.Path(sys.argv[sys.argv.index('--dir')+1])
if sys.argv[1] == 'keygen':
 path.mkdir(); key = path/'validator.key'; key.write_bytes(b'BPOSKEY2MOCK'); key.chmod(0o600)
else: print('0\\tpublic-key\\tcommitment\\t\\t\\t')
''')
            binary.chmod(0o700)
            master, slave = pty.openpty()
            original_terminal = termios.tcgetattr(master)
            env = dict(os.environ, PATH=str(mocks)+os.pathsep+os.environ.get('PATH',''), MOCK_LOG=str(root/'calls'), MOCK_FAIL='1' if fail else '0', KEYPASS='inherited-export-attribute', BLOCH_KEYSTORE_PASSPHRASE='inherited-must-be-removed')
            child = subprocess.Popen(['bash','-ax' if allexport else '-x',str(SCRIPT),str(binary),str(root/'out'),'1'], stdin=slave,stdout=slave,stderr=slave,env=env)
            os.close(slave)
            output = bytearray()
            prompts = [b'keystore passphrase:', b'confirm            :']
            deadline = time.monotonic()+15
            try:
                while time.monotonic() < deadline:
                    ready,_,_ = select.select([master],[],[],0.1)
                    if ready:
                        try: data = os.read(master,65536)
                        except OSError: break
                        if not data: break
                        output.extend(data)
                        if prompts and prompts[0] in output:
                            prompts.pop(0)
                            if interrupt:
                                child.terminate()
                                prompts.clear()
                            else:
                                os.write(master,PASSPHRASE+b'\n')
                    if child.poll() is not None and not ready: break
                code = child.wait(timeout=2)
                self.assertEqual(termios.tcgetattr(master), original_terminal, "terminal mode must be restored")
            finally:
                if child.poll() is None: child.kill(); child.wait()
                os.close(master)
            self.assertNotIn(PASSPHRASE, output)
            self.assertEqual(code, 143 if interrupt else 9 if fail else 0, output.decode(errors='replace'))
            if interrupt:
                self.assertFalse((root/'calls').exists())
                return
            calls=[json.loads(line) for line in (root/'calls').read_text().splitlines()]
            self.assertEqual([c['command'] for c in calls], ['keygen'] if fail else ['keygen','keygen-public'])
            for path in (root/'out').rglob('*'):
                if path.is_file(): self.assertNotIn(PASSPHRASE,path.read_bytes())
            self.assertEqual((root/'out').stat().st_mode & 0o777, 0o700)

    def test_pipe_inputs_without_exported_secret_even_when_caller_traces(self): self.exercise()
    def test_inherited_allexport_does_not_export_secret(self): self.exercise(allexport=True)
    def test_failed_child_stops_ceremony(self): self.exercise(fail=True)
    def test_term_restores_echo_before_exiting(self): self.exercise(interrupt=True)

if __name__ == '__main__': unittest.main()

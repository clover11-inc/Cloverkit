"""Run offline Linux regressions and write a non-identifying validation summary."""
# SPDX-License-Identifier: GPL-2.0-or-later
import hashlib,json,platform,sys,unittest
from pathlib import Path
from release_inputs import inputs
ROOT=Path(__file__).resolve().parents[1]
def fingerprint():
 digest=hashlib.sha256()
 for path,name in inputs(ROOT):
  if not name.startswith(('src/','tools/','tests/','packaging/','flipper/')):continue
  digest.update(name.encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
 return digest.hexdigest()
def main():
 if platform.system()!='Linux':print('Run the complete regression suite on Linux. Documentation/verification/staging can be used separately on other platforms.');return 2
 suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 report=dict(schema=1,version=(ROOT/'VERSION').read_text().strip(),passed=result.wasSuccessful(),tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),failed_tests=[test.id() for test,_ in result.failures+result.errors],environment=dict(os=platform.system(),architecture=platform.machine(),python=platform.python_version()),code_fingerprint=fingerprint(),scope='Offline/simulated tests, mocked SMTP/account changes and PTY vehicle protocol. No physical adapter scans, vehicle queries, live activation or service migration performed.')
 (ROOT/'build').mkdir(exist_ok=True);(ROOT/'build/validation.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,indent=2));return int(not result.wasSuccessful())
if __name__=='__main__':raise SystemExit(main())

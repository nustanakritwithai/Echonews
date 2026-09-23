"""Run the preflight suite; emit reproducible counts, versions and source digests.
Only source files and test result labels are saved; no generated keys or tokens.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import unittest

import cryptography
import jwt

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
OUT = Path(os.environ.get("ECHO_IDENTITY_RESULTS", str(ROOT / "results")))
OUT.mkdir(parents=True, exist_ok=True)


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rows = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append({"test": test.id(), "status": "SAT"})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append({"test": test.id(), "status": "VIOL"})

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append({"test": test.id(), "status": "ERROR"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append({"test": test.id(), "status": "UNKNOWN"})


suite = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_*.py")
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
log = stream.getvalue()
(OUT / "test_results.txt").write_text(log, encoding="utf-8")
print(log)
passed = result.wasSuccessful() and not result.skipped and result.testsRun > 0
report = {
    "task": "P2.1c.2b.1", "status": "SAT" if passed else "VIOL",
    "scope": "JWT signature + server registry binding + intent allowlist; PRECHECK ONLY",
    "database_execution": "NOT_IMPLEMENTED", "production_login": "UNKNOWN",
    "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
    "skipped": len(result.skipped), "unique_result_ids": len({r['test'] for r in result.rows}),
    "environment": {"python": platform.python_version(), "PyJWT": jwt.__version__,
                    "cryptography": cryptography.__version__, "platform": platform.platform()},
    "clock": "frozen in tests only", "keys": "RSA generated in memory; never persisted",
    "git_commit": os.environ.get("GITHUB_SHA"),
    "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted(ROOT.iterdir()) if p.is_file() and p.suffix in (".py", ".txt")},
    "results": result.rows,
}
(OUT / "test_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps({k: report[k] for k in ("task", "status", "tests", "failures", "errors", "skipped")}))
raise SystemExit(0 if passed else 1)

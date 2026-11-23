"""Run this project's full unittest suite from the repository root."""
from pathlib import Path
import subprocess
import sys
import unittest


def run_regression() -> int:
    suite = unittest.defaultTestLoader.discover('tests', top_level_dir='.')
    if suite.countTestCases():
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    else:
        print('No tests discovered in tests/', file=sys.stderr)
        result = unittest.TestResult()
    for status, failed_cases in (
        ('FAIL', (test for test, _ in result.failures)),
        ('ERROR', (test for test, _ in result.errors)),
        ('UNEXPECTED_SUCCESS', result.unexpectedSuccesses),
    ):
        for test in failed_cases:
            print(f'{status} {test.id()}')
    successful = result.testsRun > 0 and result.wasSuccessful()
    print(f'TEST SUMMARY total={result.testsRun} failures={len(result.failures)} '
          f'errors={len(result.errors)} skipped={len(result.skipped)} '
          f'expected_failures={len(result.expectedFailures)} '
          f'unexpected_successes={len(result.unexpectedSuccesses)} '
          f'result={"PASS" if successful else "FAIL"}')
    return 0 if successful else 1


def run_alert_linkage() -> int:
    script = Path(__file__).resolve().parent / 'check_alert_linkage.py'
    completed = subprocess.run(
        [sys.executable, '-B', str(script)], check=False,
        cwd=Path(__file__).resolve().parent,
    )
    return completed.returncode


def main() -> int:
    regression = run_regression()
    linkage = run_alert_linkage()
    print(f'OVERALL SUMMARY regression={"PASS" if regression == 0 else "FAIL"} '
          f'alert_linkage={"PASS" if linkage == 0 else "FAIL"}')
    return 0 if regression == 0 and linkage == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())

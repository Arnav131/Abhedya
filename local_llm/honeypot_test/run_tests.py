
import sys
import os
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from honeypot_test.test_honeypot_llm import run_all_tests

if __name__ == "__main__":
    run_all_tests()

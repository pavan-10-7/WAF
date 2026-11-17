
"""
Basic automated tests for the WAF attack testing modules.
"""

import importlib
import sys
from pathlib import Path

# Add the testing directory to Python's module search path.
TESTING_DIR = Path(__file__).resolve().parents[1]

if str(TESTING_DIR) not in sys.path:
    sys.path.insert(0, str(TESTING_DIR))


def test_sqli_module_imports():
    module = importlib.import_module("attacks.sqli")
    assert module is not None


def test_xss_module_imports():
    module = importlib.import_module("attacks.xss")
    assert module is not None


def test_traversal_module_imports():
    module = importlib.import_module("attacks.traversal")
    assert module is not None


def test_benign_module_imports():
    module = importlib.import_module("attacks.benign")
    assert module is not None

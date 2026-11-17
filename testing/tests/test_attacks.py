"""
Basic automated tests for the WAF attack testing modules.

These tests validate that the attack scripts expose their expected
entry points. They do not establish WAF detection effectiveness.
"""

import importlib


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
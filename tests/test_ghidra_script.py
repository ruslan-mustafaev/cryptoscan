"""The Ghidra script must generate exactly the same patterns as the package."""

import importlib.util
from pathlib import Path

from cryptoscan.signatures import SIGNATURES

SCRIPT = Path(__file__).resolve().parent.parent / "ghidra" / "CryptoScan.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("ghidra_cryptoscan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # does not touch Ghidra: currentProgram is undefined
    return module


def test_ghidra_signatures_match_package():
    script = _load_script()
    ghidra = {(name, endian): bytes(data)
              for name, _label, endian, _conf, data in script.build_signatures()}
    package = {(sig.name, sig.endian): sig.pattern for sig in SIGNATURES}
    assert ghidra == package


def test_ghidra_labels_match_package():
    script = _load_script()
    labels = {name: label for name, label, *_ in script.build_signatures()}
    for sig in SIGNATURES:
        assert labels[sig.name] == sig.label

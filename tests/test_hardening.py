from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from contextbridge.hardening import protect_process_secrets

SRC = str(Path(__file__).resolve().parents[1] / "src")
SECRET = "hardening-test-secret-0123456789abcdef"

# Runs as its own process: reports whether a child can read the secret from this
# process's /proc/<pid>/environ before and after protect_process_secrets().
_PROBE = f"""
import ctypes, os, subprocess, sys
sys.path.insert(0, {SRC!r})
from contextbridge.hardening import protect_process_secrets

def child_sees_secret():
    code = "import sys; print({SECRET!r}.encode() in open('/proc/%d/environ', 'rb').read())" % os.getpid()
    out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
    return out.stdout.strip() == "True"

before = child_sees_secret()
protected = protect_process_secrets()
dumpable = ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
print(before, protected, dumpable, child_sees_secret())
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc and prctl are Linux-only")
def test_protected_process_hides_its_environment_from_same_user_processes():
    env = {**os.environ, "CONTEXTBRIDGE_COMPUTER_TOKEN": SECRET}
    out = subprocess.run([sys.executable, "-c", _PROBE], capture_output=True, text=True, env=env, check=True)
    before, protected, dumpable, after = out.stdout.split()
    assert before == "True"  # without the protection, any process of this user reads the token
    assert (protected, dumpable) == ("True", "0")
    if os.geteuid() != 0:  # root reads every process's /proc entries regardless
        assert after == "False"


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="covered by the Linux test")
def test_protection_is_a_no_op_elsewhere():
    assert protect_process_secrets() is False

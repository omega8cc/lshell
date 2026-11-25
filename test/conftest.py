"""Pytest test-suite configuration."""

import os

import pytest

try:
    from hypothesis import settings
except ImportError:
    settings = None


if settings is not None:
    # Avoid filesystem writes for Hypothesis' example database in locked-down CI
    # containers where the project workspace may be read-only for the test user.
    settings.register_profile("lshell_ci", settings(database=None))
    settings.load_profile("lshell_ci")


# The process state every test starts from, read before any test module is
# imported: a module can load a configuration while it is collected (a class
# attribute), and that already stores LSHELL_ARGS. The folder is the user's
# home, where lshell itself starts (home_path defaults to $HOME) and where
# tests that list or complete relative paths expect to be.
_HOME = os.environ.get("HOME", "")
_START_CWD = _HOME if os.path.isdir(_HOME) else os.getcwd()
os.environ["LSHELL_TEST_START_DIR"] = _START_CWD
_START_ENVIRON = dict(os.environ)


def _restore_start_state():
    # pytest keeps the running test's name in the environment and removes it
    # itself after the test
    current = os.environ.get("PYTEST_CURRENT_TEST")
    os.environ.clear()
    os.environ.update(_START_ENVIRON)
    if current is not None:
        os.environ["PYTEST_CURRENT_TEST"] = current
    os.chdir(_START_CWD)


@pytest.fixture(autouse=True)
def keep_process_state():
    """Run every test in the suite's own environment, from the user's home.

    A configuration loaded inside the test process stores its arguments in
    LSHELL_ARGS, which a real lshell started by a later test reads as its own,
    and changes folder; export, source and env_vars set variables too. Each
    test starts from the same state and leaves it so, whatever ran before, so
    the suite passes in any order and a single file runs as in the whole suite.
    """
    _restore_start_state()
    yield
    _restore_start_state()

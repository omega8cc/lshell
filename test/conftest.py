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


@pytest.fixture(autouse=True)
def keep_process_state():
    """Give every test the environment and working folder it started with.

    A configuration loaded inside the test process stores its arguments in
    LSHELL_ARGS, which a real lshell started by a later test reads as its own,
    and changes into the user's home; export, source and env_vars set
    variables too. Each test gets them back as they were, so the suite passes
    in any order.
    """
    environ = dict(os.environ)
    cwd = os.getcwd()
    yield
    os.environ.clear()
    os.environ.update(environ)
    os.chdir(cwd)

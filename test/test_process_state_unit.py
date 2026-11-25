"""Each test starts with the environment and folder the suite started with."""

import os
import unittest

from lshell.checkconfig import CheckConfig

TOPDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"
SENTINEL = "['--lshell-test-sentinel']"


class TestProcessState(unittest.TestCase):
    """The first test leaves state behind; the second must not see it.

    Tests of a class run in name order, so test_1 runs before test_2. The
    start folder is the one test/conftest.py recorded (the user's home) before
    any module was collected; the state is put back by its fixture, so these
    tests need pytest.
    """

    def setUp(self):
        if "PYTEST_CURRENT_TEST" not in os.environ:
            self.skipTest("needs pytest, which loads test/conftest.py")

    def test_1_config_load_leaves_state(self):
        """A configuration loaded here sets LSHELL_ARGS and changes folder."""
        CheckConfig([f"--config={CONFIG}", "--quiet=1"]).returnconf()
        self.assertIsNotNone(os.environ.get("LSHELL_ARGS"))
        os.environ["LSHELL_ARGS"] = SENTINEL
        os.environ["LSHELL_TEST_LEFT_BEHIND"] = "1"
        os.chdir("/")

    def test_2_next_test_starts_clean(self):
        """The next test gets the suite's own environment and folder back."""
        self.assertNotEqual(os.environ.get("LSHELL_ARGS"), SENTINEL)
        self.assertNotIn("LSHELL_TEST_LEFT_BEHIND", os.environ)
        start = os.environ.get("LSHELL_TEST_START_DIR")
        self.assertIsNotNone(start)
        self.assertTrue(os.path.samefile(os.getcwd(), start))

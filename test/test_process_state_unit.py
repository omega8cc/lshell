"""Each test starts with the environment and folder the suite started with."""

import os
import unittest

from lshell.checkconfig import CheckConfig

TOPDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"

# read at collection, before any test of this file runs
ARGS_AT_START = os.environ.get("LSHELL_ARGS")
CWD_AT_START = os.getcwd()


class TestProcessState(unittest.TestCase):
    """The first test leaves state behind; the second must not see it.

    Tests of a class run in name order, so test_1 runs before test_2.
    """

    def test_1_config_load_leaves_state(self):
        """A configuration loaded here sets LSHELL_ARGS and changes folder."""
        CheckConfig([f"--config={CONFIG}", "--quiet=1"]).returnconf()
        self.assertNotEqual(os.environ.get("LSHELL_ARGS"), ARGS_AT_START)
        os.chdir("/")
        self.assertNotEqual(os.getcwd(), CWD_AT_START)

    def test_2_next_test_starts_clean(self):
        """The next test gets the suite's own environment and folder back."""
        self.assertEqual(os.environ.get("LSHELL_ARGS"), ARGS_AT_START)
        self.assertEqual(os.getcwd(), CWD_AT_START)


if __name__ == "__main__":
    unittest.main()

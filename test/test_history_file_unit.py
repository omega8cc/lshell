"""The history builtin never empties a history file the session did not load."""

import io
import logging
import os
import readline
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lshell import builtincmd

TOPDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"
LSHELL = f"{TOPDIR}/bin/lshell"
EMPTY_PATH = "--path=['/var/empty-lshell']"
LINES = b"ls\npwd\n"
LISTED = b"1:  ls\n2:  pwd\n"


def _gnu_readline_only(test):
    if "libedit" in (readline.__doc__ or ""):
        # libedit refuses a history file without its own header line
        test.skipTest("GNU readline's history file format")


class TestHistoryBuiltin(unittest.TestCase):
    """cmd_history writes readline's list only when the session loaded it."""

    def _history(self, conf):
        out = io.StringIO()
        log = logging.getLogger("lshell.test.history")
        with patch("lshell.builtincmd.readline.write_history_file") as write:
            with redirect_stdout(out):
                retcode = builtincmd.cmd_history(conf, log)
        return retcode, out.getvalue(), write

    def test_not_loaded_lists_the_file_without_writing(self):
        """A script or a single command lists the file as it stands."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            with open(history, "wb") as handle:
                handle.write(LINES)
            retcode, output, write = self._history({"history_file": history})
            with open(history, "rb") as handle:
                kept = handle.read()
        self.assertEqual(retcode, 0)
        write.assert_not_called()
        self.assertEqual(output, LISTED.decode())
        self.assertEqual(kept, LINES)

    def test_not_loaded_without_a_file_lists_nothing(self):
        """No history file yet: nothing listed, nothing created, no error."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            retcode, output, write = self._history({"history_file": history})
            created = os.path.exists(history)
        self.assertEqual(retcode, 0)
        write.assert_not_called()
        self.assertEqual(output, "")
        self.assertFalse(created)

    def test_loaded_writes_the_session_first(self):
        """An interactive session writes its lines before listing them."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            with open(history, "wb") as handle:
                handle.write(LINES)
            retcode, output, write = self._history(
                {"history_file": history, "_history_loaded": True}
            )
        self.assertEqual(retcode, 0)
        write.assert_called_once_with(history)
        self.assertEqual(output, LISTED.decode())


class TestHistoryFileKept(unittest.TestCase):
    """The real entry point: a script or a single command keeps the file."""

    def _run(self, history, args, stdin=b""):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("PYTHON", "SSH_", "LSHELL_"))
        }
        env["PYTHONPATH"] = TOPDIR
        with tempfile.TemporaryDirectory() as logdir:
            proc = subprocess.run(
                [
                    sys.executable,
                    LSHELL,
                    f"--config={CONFIG}",
                    f"--log={logdir}",
                    EMPTY_PATH,
                    f"--history_file='{history}'",
                ]
                + list(args),
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=120,
                check=False,
            )
        return proc.stdout

    def _kept(self, history):
        with open(history, "rb") as handle:
            return handle.read()

    def test_script_history_line_keeps_the_file(self):
        """A history line in a .lsh script lists the file and keeps it."""
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            with open(history, "wb") as handle:
                handle.write(LINES)
            script = os.path.join(home, "lines.lsh")
            with open(script, "wb") as handle:
                handle.write(b"history\n")
            output = self._run(history, [script])
            kept = self._kept(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)

    def test_single_command_history_keeps_the_file(self):
        """lshell -c history lists the file and keeps it."""
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            with open(history, "wb") as handle:
                handle.write(LINES)
            output = self._run(history, ["-c", "history"])
            kept = self._kept(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)

    def test_session_history_keeps_the_file(self):
        """A session reading its lines from a pipe keeps the loaded lines."""
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            with open(history, "wb") as handle:
                handle.write(LINES)
            output = self._run(history, [], stdin=b"history\nexit\n")
            kept = self._kept(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)


if __name__ == "__main__":
    unittest.main()

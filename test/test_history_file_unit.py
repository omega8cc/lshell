"""lshell writes readline's history back only to the history file it loaded."""

import io
import logging
import os
import readline
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from unittest.mock import mock_open, patch

from lshell import builtincmd
from lshell.checkconfig import CheckConfig
from lshell.shellcmd import ShellCmd

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


def _env():
    # no prompt or readline settings of the runner's own: LPS1 replaces the
    # prompt the terminal tests wait for, an inputrc can cut the history
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "SSH_", "LSHELL_", "LPS1", "INPUTRC"))
    }
    env["PYTHONPATH"] = TOPDIR
    env["INPUTRC"] = "/dev/null"
    return env


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


class TestHistoryBuiltin(unittest.TestCase):
    """cmd_history writes readline's list only when the session loaded it."""

    def _history(self, conf, on_write=None):
        out = io.StringIO()
        log = logging.getLogger("lshell.test.history")
        with patch(
            "lshell.builtincmd.readline.write_history_file", side_effect=on_write
        ) as write:
            with redirect_stdout(out):
                with patch.object(log, "critical") as critical:
                    retcode = builtincmd.cmd_history(conf, log)
        return retcode, out.getvalue(), write, critical

    def test_not_loaded_lists_the_file_without_writing(self):
        """A script or a single command lists the file as it stands."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            retcode, output, write, _critical = self._history(
                {"history_file": history}
            )
        self.assertEqual(retcode, 0)
        write.assert_not_called()
        self.assertEqual(output, LISTED.decode())

    def test_not_loaded_without_a_file_lists_nothing(self):
        """No history file yet: nothing listed, nothing created, no error."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            retcode, output, write, critical = self._history(
                {"history_file": history}
            )
            created = os.path.exists(history)
        self.assertEqual(retcode, 0)
        write.assert_not_called()
        critical.assert_not_called()
        self.assertEqual(output, "")
        self.assertFalse(created)

    def test_not_loaded_folder_is_an_error(self):
        """A history path that is a folder is reported, as before."""
        with tempfile.TemporaryDirectory() as home:
            retcode, output, write, critical = self._history({"history_file": home})
        self.assertEqual(retcode, 1)
        write.assert_not_called()
        critical.assert_called_once()
        self.assertEqual(output, "")

    def test_loaded_writes_the_session_first(self):
        """An interactive session writes its lines before listing them."""

        def session_line(path):
            # what readline's write adds: a line typed in this session
            with open(path, "ab") as handle:
                handle.write(b"echo typed\n")

        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            retcode, output, write, _critical = self._history(
                {"history_file": history, "_history_loaded": history},
                on_write=session_line,
            )
        self.assertEqual(retcode, 0)
        write.assert_called_once_with(history)
        self.assertEqual(output, LISTED.decode() + "3:  echo typed\n")

    def test_libedit_file_is_listed_as_typed(self):
        """libedit's header line is not listed and its \\ooo escapes are read."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, b"_HiStOrY_V2_\na\\040b\nback\\134slash\ncaf\xc3\xa9\n")
            with patch("lshell.builtincmd.LIBEDIT", True):
                retcode, output, write, _critical = self._history(
                    {"history_file": history}
                )
        self.assertEqual(retcode, 0)
        write.assert_not_called()
        self.assertEqual(output, "1:  a b\n2:  back\\slash\n3:  café\n")

    def test_gnu_listing_keeps_a_header_like_line(self):
        """On GNU readline the file is listed as it stands, every line."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, b"_HiStOrY_V2_\na\\040b\n")
            with patch("lshell.builtincmd.LIBEDIT", False):
                retcode, output, _write_mock, _critical = self._history(
                    {"history_file": history}
                )
        self.assertEqual(retcode, 0)
        self.assertEqual(output, "1:  _HiStOrY_V2_\n2:  a\\040b\n")


class TestWriteHistory(unittest.TestCase):
    """write_history keeps a libedit file readable whatever history_size is."""

    def setUp(self):
        readline.clear_history()

    def tearDown(self):
        readline.clear_history()
        readline.set_history_length(-1)

    def _items(self):
        return [
            readline.get_history_item(i)
            for i in range(1, readline.get_current_history_length() + 1)
        ]

    def test_libedit_cuts_the_list_not_the_file(self):
        """On libedit the list is cut to history_size before it is written."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            for i in range(5):
                readline.add_history(f"echo {i}")
            with patch("lshell.builtincmd.LIBEDIT", True):
                builtincmd.write_history({"history_file": history, "history_size": 3})
        self.assertEqual(self._items(), ["echo 2", "echo 3", "echo 4"])

    def test_gnu_leaves_the_list_to_readline(self):
        """On GNU readline the list is left whole; readline cuts the file."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            for i in range(5):
                readline.add_history(f"echo {i}")
            with patch("lshell.builtincmd.LIBEDIT", False):
                builtincmd.write_history({"history_file": history, "history_size": 3})
        self.assertEqual(len(self._items()), 5)

    def test_real_libedit_file_reads_back_after_a_cut(self):
        """With libedit itself, a file cut to history_size keeps its header."""
        if not builtincmd.LIBEDIT:
            self.skipTest("libedit's own file format")
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            for i in range(5):
                readline.add_history(f"echo {i}")
            readline.set_history_length(-1)
            builtincmd.write_history({"history_file": history, "history_size": 3})
            readline.clear_history()
            readline.read_history_file(history)
            first = _read(history).split(b"\n", 1)[0]
        self.assertEqual(first, b"_HiStOrY_V2_")
        self.assertEqual(self._items(), ["echo 2", "echo 3", "echo 4"])


class TestSessionLoad(unittest.TestCase):
    """cmdloop marks the session only when it read the history file."""

    def _shell(self):
        args = [f"--config={CONFIG}", "--quiet=1", "--strict=0"]
        conf = CheckConfig(args).returnconf()
        return ShellCmd(
            conf,
            args=[],
            stdin=io.StringIO(),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )

    def _cmdloop(self, read_effect, runs=1, history=None):
        shell = self._shell()
        if history is not None:
            shell.conf["history_file"] = history
        with ExitStack() as stack:
            read = stack.enter_context(
                patch(
                    "lshell.shellcmd.readline.read_history_file",
                    side_effect=read_effect,
                )
            )
            opened = stack.enter_context(patch("lshell.shellcmd.open", mock_open()))
            write = stack.enter_context(
                patch("lshell.shellcmd.readline.write_history_file")
            )
            for name in (
                "set_history_length",
                "set_completer_delims",
                "set_completer",
                "parse_and_bind",
            ):
                stack.enter_context(patch(f"lshell.shellcmd.readline.{name}"))
            stack.enter_context(
                patch(
                    "lshell.shellcmd.readline.get_completer_delims",
                    return_value=" \t\n",
                )
            )
            stack.enter_context(
                patch("lshell.shellcmd.readline.get_completer", return_value=None)
            )
            stack.enter_context(
                patch("lshell.shellcmd.sys.exit", side_effect=SystemExit)
            )
            for _ in range(runs):
                shell.cmdqueue = ["exit"]
                with self.assertRaises(SystemExit):
                    shell.cmdloop()
        return shell.conf, read, opened, write

    def test_readable_file_is_loaded_and_written_back(self):
        """A file read at login is marked and written at the end."""
        conf, read, opened, write = self._cmdloop([None])
        self.assertEqual(conf.get("_history_loaded"), conf["history_file"])
        read.assert_called_once_with(conf["history_file"])
        opened.assert_not_called()
        write.assert_called_once_with(conf["history_file"])

    def test_missing_file_is_made_and_loaded(self):
        """A missing file is made without truncating, then read and marked."""
        conf, read, opened, write = self._cmdloop([FileNotFoundError(), None])
        self.assertEqual(conf.get("_history_loaded"), conf["history_file"])
        self.assertEqual(read.call_count, 2)
        opened.assert_called_once_with(conf["history_file"], "a", encoding="utf-8")
        write.assert_called_once_with(conf["history_file"])

    def test_unreadable_file_is_left_alone(self):
        """A file that cannot be read is neither emptied nor written over."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            conf, read, opened, write = self._cmdloop(
                [PermissionError()], history=history
            )
        self.assertIsNone(conf.get("_history_loaded"))
        read.assert_called_once_with(history)
        opened.assert_not_called()
        write.assert_not_called()

    def test_empty_file_refused_otherwise_is_left_alone(self):
        """An empty file refused for another reason (permission) is left alone."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, b"")
            conf, read, opened, write = self._cmdloop(
                [PermissionError(13, "Permission denied")], history=history
            )
        self.assertIsNone(conf.get("_history_loaded"))
        read.assert_called_once_with(history)
        opened.assert_not_called()
        write.assert_not_called()

    def test_new_file_that_cannot_be_read_is_left_alone(self):
        """A file made at login and then refused, holding lines, is left alone."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            # what the file holds by the time it is read back
            _write(history, LINES)
            conf, read, opened, write = self._cmdloop(
                [FileNotFoundError(), PermissionError(13, "Permission denied")],
                history=history,
            )
        self.assertIsNone(conf.get("_history_loaded"))
        self.assertEqual(read.call_count, 2)
        opened.assert_called_once_with(history, "a", encoding="utf-8")
        write.assert_not_called()

    def test_unreadable_empty_file_is_taken(self):
        """An empty file readline cannot read (libedit) holds nothing to lose."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, b"")
            conf, read, opened, write = self._cmdloop(
                [OSError(22, "Invalid argument")], history=history
            )
        self.assertEqual(conf.get("_history_loaded"), history)
        read.assert_called_once_with(history)
        opened.assert_not_called()
        write.assert_called_once_with(history)

    def test_new_file_readline_cannot_read_is_taken(self):
        """A file just made, which libedit cannot read empty, is the session's."""
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            # stands in for the file the mocked open makes
            _write(history, b"")
            conf, read, opened, write = self._cmdloop(
                [FileNotFoundError(), OSError(22, "Invalid argument")], history=history
            )
        self.assertEqual(conf.get("_history_loaded"), history)
        self.assertEqual(read.call_count, 2)
        opened.assert_called_once_with(history, "a", encoding="utf-8")
        write.assert_called_once_with(history)

    def test_cmdloop_run_again_reads_the_file_once(self):
        """cmdloop() run again (after a Ctrl-C) does not load the file twice."""
        conf, read, _opened, write = self._cmdloop([None], runs=2)
        read.assert_called_once_with(conf["history_file"])
        self.assertEqual(write.call_count, 2)

    def test_reload_keeps_the_loaded_history_file(self):
        """A reload keeps the mark and the file the session loaded."""
        shell = self._shell()
        with tempfile.TemporaryDirectory() as home:
            loaded = os.path.join(home, "history")
            shell.conf["history_file"] = loaded
            shell.conf["_history_loaded"] = loaded
            shell.conf["config_mtime"] = 0
            shell.reload_changed_config()
        self.assertNotEqual(shell.conf["config_mtime"], 0)
        self.assertEqual(shell.conf["_history_loaded"], loaded)
        self.assertEqual(shell.conf["history_file"], loaded)

    def test_reload_of_an_unloaded_session_takes_the_new_file(self):
        """A session that loaded nothing follows the reloaded config's file."""
        shell = self._shell()
        shell.conf["history_file"] = "/var/empty-lshell/history"
        shell.conf["config_mtime"] = 0
        shell.reload_changed_config()
        self.assertNotEqual(shell.conf["config_mtime"], 0)
        self.assertFalse(shell.conf.get("_history_loaded"))
        self.assertNotEqual(shell.conf["history_file"], "/var/empty-lshell/history")
        self.assertTrue(shell.conf["history_file"].endswith("/.lhistory"))


class TestHistoryFileKept(unittest.TestCase):
    """The real entry point keeps the history file it did not load."""

    def _run(self, history, args, stdin=b""):
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
                env=_env(),
                timeout=120,
                check=False,
            )
        return proc.stdout, proc.returncode

    def test_script_history_line_keeps_the_file(self):
        """A history line in a .lsh script lists the file and keeps it."""
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            script = os.path.join(home, "lines.lsh")
            _write(script, b"history\n")
            output, _rc = self._run(history, [script])
            kept = _read(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)

    def test_single_command_history_keeps_the_file(self):
        """lshell -c history lists the file and keeps it."""
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            output, _rc = self._run(history, ["-c", "history"])
            kept = _read(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)

    def test_unreadable_history_file_is_kept(self):
        """A history file the login cannot read is not emptied at login."""
        if os.geteuid() == 0:
            self.skipTest("root reads a file whatever its mode")
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            os.chmod(history, 0o200)
            try:
                output, retcode = self._run(
                    history, [], stdin=b"echo lbr-unreadable\nexit\n"
                )
            finally:
                os.chmod(history, 0o600)
            kept = _read(history)
        self.assertNotIn(b"Traceback", output, output)
        # the session ran its line and ended normally
        self.assertIn(b"lbr-unreadable", output.replace(b"echo lbr-unreadable", b""))
        self.assertEqual(retcode, 0, output)
        self.assertEqual(kept, LINES)

    def test_new_history_file_is_readable_next_time(self):
        """A login's first session leaves a history file its readline can read.

        GNU readline reads the empty file it starts with; libedit cannot, so
        the session must still write its own list there at its end.
        """
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            output, retcode = self._run(history, [], stdin=b"exit\n")
            made = os.path.exists(history)
            readline.clear_history()
            try:
                readline.read_history_file(history)
                readable = True
            except OSError:
                readable = False
            finally:
                readline.clear_history()
        self.assertNotIn(b"Traceback", output, output)
        self.assertEqual(retcode, 0, output)
        self.assertTrue(made)
        self.assertTrue(readable)

    def test_piped_session_keeps_the_file(self):
        """A session reading a pipe lists the loaded lines and keeps them.

        input() adds nothing to readline's list over a pipe, so this only
        guards that such a session changes nothing; the terminal tests below
        prove that a session's own lines are written back.
        """
        _gnu_readline_only(self)
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            _write(history, LINES)
            output, _rc = self._run(history, [], stdin=b"history\nexit\n")
            kept = _read(history)
        self.assertNotIn(b"Traceback", output, output)
        self.assertIn(LISTED, output)
        self.assertEqual(kept, LINES)


class TestTerminalSession(unittest.TestCase):
    """A terminal session lists what it typed and writes it to its own file."""

    def _session(self, reload_config):
        _gnu_readline_only(self)
        try:
            import pexpect  # pylint: disable=import-outside-toplevel
        except ImportError:
            self.skipTest("pexpect is not installed")
        with tempfile.TemporaryDirectory() as home:
            history = os.path.join(home, "history")
            decoy = os.path.join(home, "decoy")
            config = os.path.join(home, "lshell.conf")
            _write(history, LINES)
            _write(decoy, b"decoy\n")
            with open(config, "w", encoding="utf-8") as handle:
                # a reload reads this file alone: the log folder is named
                # here, and the history file it names is not the session's
                handle.write(
                    "[global]\n"
                    f"logpath : {home}/\n"
                    "loglevel : 2\n"
                    "[default]\n"
                    "allowed : ['echo']\n"
                    "forbidden : [';', '&', '|', '`', '>', '<', '$(', '${']\n"
                    "warning_counter : 2\n"
                    "strict : 0\n"
                    f"history_file : '{decoy}'\n"
                )
            child = pexpect.spawn(
                sys.executable,
                [LSHELL, f"--config={config}", f"--history_file='{history}'"],
                env=_env(),
                timeout=30,
            )
            try:
                child.expect(r"\$ ")
                child.sendline("echo lbr-typed")
                child.expect(r"\$ ")
                if reload_config:
                    stamp = os.path.getmtime(config) + 10
                    os.utime(config, (stamp, stamp))
                child.sendline("history")
                child.expect(r"\$ ")
                listed = child.before.decode("utf-8", "replace")
                # only the end of the session writes these two lines
                child.sendline("echo lbr-after")
                child.expect(r"\$ ")
                child.sendline("exit")
                child.expect(pexpect.EOF)
            finally:
                child.close()
            kept = _read(history)
            decoy_kept = _read(decoy)
        self.assertNotIn("Traceback", listed, listed)
        self.assertIn("1:  ls", listed)
        self.assertRegex(listed, r"\d+:  echo lbr-typed")
        self.assertTrue(kept.startswith(LINES), kept)
        self.assertIn(b"echo lbr-typed\n", kept)
        self.assertIn(b"echo lbr-after\n", kept)
        self.assertTrue(kept.endswith(b"exit\n"), kept)
        self.assertEqual(decoy_kept, b"decoy\n")

    def test_session_lists_what_it_typed(self):
        """history lists the loaded lines and the session's own."""
        self._session(reload_config=False)

    def test_session_after_a_config_reload(self):
        """After a reload the session keeps listing and writing its own file."""
        self._session(reload_config=True)


if __name__ == "__main__":
    unittest.main()

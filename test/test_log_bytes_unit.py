"""A refused line reaches the log whatever bytes it holds."""

import io
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from getpass import getuser

from lshell import cli
from lshell import utils
from lshell.checkconfig import CheckConfig, OneLineFormatter

TOPDIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"
LSHELL = f"{TOPDIR}/bin/lshell"
EMPTY_PATH = "--path=['/var/empty-lshell']"


def _record(message, **extra):
    record = logging.LogRecord(
        "lshell.test", logging.CRITICAL, __file__, 1, message, None, None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def _log_text(tmpdir):
    """The log file's text; raises if it is not valid UTF-8."""
    logfile = os.path.join(tmpdir, getuser() + ".log")
    if not os.path.exists(logfile):
        return ""
    with open(logfile, "rb") as handle:
        return handle.read().decode("utf-8", "strict")


class DummyShellContext:
    """Minimal shell context consumed by utils.cmd_parse_execute."""

    def __init__(self, conf):
        self.conf = conf
        self.log = conf["logpath"]


class TestFormatterBytes(unittest.TestCase):
    """The file and syslog formatter on bytes that are no part of a letter."""

    def test_surrogate_byte_is_written_as_hex(self):
        """A byte kept by surrogateescape is written as \\xNN."""
        formatter = OneLineFormatter("%(message)s")
        text = formatter.format(_record('lshell: forbidden path: "/root/x\udcffy"'))
        self.assertEqual(text, 'lshell: forbidden path: "/root/x\\xffy"')
        text.encode("utf-8", "strict")

    def test_checked_line_bytes_are_written_as_hex(self):
        """The appended line is escaped the same way."""
        formatter = OneLineFormatter("%(message)s")
        text = formatter.format(
            _record(
                'lshell: forbidden path: "/root/a\udce9"',
                lshell_line="cat /root/a\udce9 \udc80\x01",
            )
        )
        self.assertEqual(
            text,
            'lshell: forbidden path: "/root/a\\xe9" in "cat /root/a\\xe9 \\x80\\x01"',
        )

    def test_letters_are_kept(self):
        """A letter, whatever its script, is written as itself."""
        formatter = OneLineFormatter("%(message)s")
        line = 'lshell: forbidden path: "/root/zażółć-é-ß-日本"'
        self.assertEqual(formatter.format(_record(line)), line)

    def test_other_surrogate_is_written_as_its_code_point(self):
        """A lone surrogate that is no kept byte never reaches the handler."""
        formatter = OneLineFormatter("%(message)s")
        text = formatter.format(_record("a\ud800b\udc00c"))
        self.assertEqual(text, "a\\ud800b\\udc00c")
        text.encode("utf-8", "strict")


class TestLogFileBytes(unittest.TestCase):
    """A refusal holding such a byte is written to a real log file."""

    args = [f"--config={CONFIG}", "--quiet=1"]

    def _session(self, tmpdir):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            conf = CheckConfig(
                self.args
                + [f"--log={tmpdir}", "--loglevel=4", "--warning_counter=20"]
                + [EMPTY_PATH]
            ).returnconf()
        return conf, stderr

    def test_log_file_is_opened_as_utf8(self):
        """The log is UTF-8 whatever the locale's encoding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, _stderr = self._session(tmpdir)
            handlers = [
                handler
                for handler in conf["logpath"].handlers
                if isinstance(handler, logging.FileHandler)
            ]
            self.assertEqual(len(handlers), 1, handlers)
            self.assertEqual(handlers[0].encoding, "utf-8")

    def test_refused_path_with_byte_is_logged(self):
        """The refusal and its line reach the log, the byte as \\xNN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir)
            with redirect_stderr(stderr):
                conf["logpath"].info('CMD: "ls /x\udcffy"')
                utils.cmd_parse_execute(
                    "ls /x\udcffy", shell_context=DummyShellContext(conf)
                )
            text = _log_text(tmpdir)
            self.assertIn('CMD: "ls /x\\xffy"', text)
            self.assertIn('lshell: forbidden path: "/x\\xffy" in "ls /x\\xffy"', text)
            self.assertNotIn("Logging error", stderr.getvalue())
            # The user sees the refusal as before.
            self.assertIn("lshell: forbidden path:", stderr.getvalue())


class TestStreamsKeepBytes(unittest.TestCase):
    """keep_undecodable_bytes sets surrogateescape on the streams it gets."""

    def test_streams_decode_and_encode_such_bytes(self):
        """A strict stream reads and writes such a byte after the call."""
        raw_in = io.BytesIO(b"ls /x\xffy\n")
        stream_in = io.TextIOWrapper(raw_in, encoding="utf-8", errors="strict")
        raw_out = io.BytesIO()
        stream_out = io.TextIOWrapper(raw_out, encoding="utf-8", errors="strict")
        cli.keep_undecodable_bytes((stream_in, stream_out))
        line = stream_in.readline()
        self.assertEqual(line, "ls /x\udcffy\n")
        stream_out.write(line)
        stream_out.flush()
        self.assertEqual(raw_out.getvalue(), b"ls /x\xffy\n")

    def test_stream_without_reconfigure_is_left_alone(self):
        """A stand-in stream without reconfigure() is skipped."""
        cli.keep_undecodable_bytes((object(), io.StringIO()))


class TestEntryPointBytes(unittest.TestCase):
    """The real entry point, a line typed or sent over SSH, in each locale."""

    def _run(self, env, stdin=b"", args=()):
        base = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("LC_", "LANG", "PYTHON", "SSH_", "LSHELL_"))
        }
        base.update({"LC_ALL": "C", "PYTHONPATH": TOPDIR})
        base.update(env)
        with tempfile.TemporaryDirectory() as tmpdir:
            proc = subprocess.run(
                [
                    sys.executable,
                    LSHELL,
                    f"--config={CONFIG}",
                    f"--log={tmpdir}",
                    "--loglevel=4",
                    "--warning_counter=20",
                    EMPTY_PATH,
                ]
                + list(args),
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=base,
                timeout=120,
                check=False,
            )
            return proc.stdout, _log_text(tmpdir)

    def _assert_logged(self, output, text, shown):
        self.assertNotIn(b"Traceback", output, output)
        self.assertNotIn(b"Logging error", output, output)
        self.assertIn(f'lshell: forbidden path: "/x{shown}y"', text)

    def test_typed_line_under_strict_utf8_decoding(self):
        """A UTF-8 locale that decodes strictly (en_US.UTF-8 and the like)."""
        output, text = self._run(
            {"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8:strict"},
            stdin=b"ls /x\xffy\nexit\n",
        )
        self._assert_logged(output, text, "\\xff")
        self.assertRegex(text, r'CMD: "[^"]*ls[^"]* /x\\xffy"')

    def test_typed_line_under_utf8_mode(self):
        """The C locale, which Python reads as UTF-8 with surrogateescape."""
        output, text = self._run({"PYTHONUTF8": "1"}, stdin=b"ls /x\xffy\nexit\n")
        self._assert_logged(output, text, "\\xff")
        self.assertRegex(text, r'CMD: "[^"]*ls[^"]* /x\\xffy"')

    def test_typed_line_in_single_byte_charset(self):
        """An ISO-8859 terminal: the byte is a letter, logged as UTF-8."""
        output, text = self._run(
            {
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
                "PYTHONIOENCODING": "iso8859-2",
            },
            stdin=b"ls /x\xe9y\nexit\n",
        )
        self._assert_logged(output, text, "é")

    def test_command_over_ssh(self):
        """A remote command holding such a byte is logged with its refusal."""
        output, text = self._run(
            {"PYTHONUTF8": "1", "SSH_CLIENT": "127.0.0.1 40000 22"},
            args=["--overssh=['ls']", "-c", b"ls /x\xffy"],
        )
        self.assertNotIn(b"Traceback", output, output)
        self.assertNotIn(b"Logging error", output, output)
        self.assertIn('lshell: forbidden path over SSH: "ls /x\\xffy"', text)


if __name__ == "__main__":
    unittest.main()

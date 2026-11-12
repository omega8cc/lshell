"""One log line per record, naming the line a refused token came from."""

import io
import logging
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from getpass import getuser

from lshell.checkconfig import CheckConfig, OneLineFormatter
from lshell import sec
from lshell import utils

TOPDIR = f"{os.path.dirname(os.path.realpath(__file__))}/../"
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"


def _record(message, exc_info=None, **extra):
    record = logging.LogRecord(
        "lshell.test", logging.CRITICAL, __file__, 1, message, None, exc_info
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class RecordingLog:
    """Logger stub keeping each call's message and keyword arguments."""

    def __init__(self):
        self.calls = []

    def critical(self, message, **kwargs):
        """Record a critical call."""
        self.calls.append(("critical", message, kwargs))

    def error(self, message, **kwargs):
        """Record an error call."""
        self.calls.append(("error", message, kwargs))

    def warning(self, message, **kwargs):
        """Record a warning call."""
        self.calls.append(("warning", message, kwargs))


class DummyShellContext:
    """Minimal shell context consumed by utils.cmd_parse_execute."""

    def __init__(self, conf):
        self.conf = conf
        self.log = conf["logpath"]


class TestOneLineFormatter(unittest.TestCase):
    """The file and syslog formatter."""

    def test_control_characters_are_written_escaped(self):
        """A control character is written as \\xNN, never as itself."""
        formatter = OneLineFormatter("%(message)s")
        text = formatter.format(
            _record('lshell: forbidden control char: "a\nb\rc\x1bd\x7f\te"')
        )
        self.assertEqual(
            text,
            'lshell: forbidden control char: "a\\x0ab\\x0dc\\x1bd\\x7f\\x09e"',
        )

    def test_checked_line_is_appended_and_escaped(self):
        """A record carrying the checked line ends with in "<line>"."""
        formatter = OneLineFormatter("(user): %(message)s")
        text = formatter.format(
            _record('lshell: forbidden command: "sh"', lshell_line="sh -c 'id'\nx")
        )
        self.assertEqual(
            text, "(user): lshell: forbidden command: \"sh\" in \"sh -c 'id'\\x0ax\""
        )

    def test_record_without_line_is_unchanged(self):
        """Every other record keeps its form."""
        formatter = OneLineFormatter("(user): %(message)s")
        self.assertEqual(formatter.format(_record("Exited")), "(user): Exited")
        self.assertEqual(
            formatter.format(_record("Exited", lshell_line="")), "(user): Exited"
        )

    def test_traceback_stays_on_the_record_line(self):
        """A logged exception is written on the record's one line."""
        formatter = OneLineFormatter("%(message)s")
        text = ""
        try:
            raise ValueError("boom")
        except ValueError:
            text = formatter.format(_record("failed", exc_info=sys.exc_info()))
        self.assertNotIn("\n", text)
        self.assertTrue(text.startswith("failed\\x0aTraceback"))
        self.assertIn("ValueError: boom", text)


class TestRefusalNamesItsLine(unittest.TestCase):
    """warn_count and the parser keep the checked line for the log."""

    args = [f"--config={CONFIG}", "--quiet=1"]

    def test_line_for_log_outermost_wins_and_is_removed(self):
        """A nested check keeps the outer line; the key goes when it ends."""
        conf = {}
        with sec.line_for_log(conf, "outer line"):
            with sec.line_for_log(conf, "inner"):
                self.assertEqual(conf[sec.LOGGED_LINE_KEY], "outer line")
            self.assertEqual(conf[sec.LOGGED_LINE_KEY], "outer line")
        self.assertNotIn(sec.LOGGED_LINE_KEY, conf)

    def test_line_for_log_removes_the_key_after_an_exception(self):
        """A check that raises leaves no line behind for the next one."""
        conf = {}
        with self.assertRaises(RuntimeError):
            with sec.line_for_log(conf, "a line"):
                raise RuntimeError("stop")
        self.assertNotIn(sec.LOGGED_LINE_KEY, conf)

    def test_line_for_log_takes_a_missing_conf(self):
        """A context without a config dict runs the check unchanged."""
        with sec.line_for_log(None, "a line"):
            pass

    def _conf(self, line=None):
        conf = {
            "logpath": RecordingLog(),
            "warning_counter": 5,
            "strict": 1,
        }
        if line is not None:
            conf[sec.LOGGED_LINE_KEY] = line
        return conf

    def test_warn_count_passes_the_line_when_it_differs(self):
        """The refusal record carries the whole line."""
        conf = self._conf("sh -c id")
        with redirect_stderr(io.StringIO()):
            sec.warn_count("command", "sh", conf, strict=1)
        refusal = conf["logpath"].calls[0]
        self.assertEqual(refusal[0], "critical")
        self.assertEqual(refusal[1], 'lshell: forbidden command: "sh"')
        self.assertEqual(refusal[2], {"extra": {"lshell_line": "sh -c id"}})

    def test_warn_count_keeps_the_old_call_when_line_is_the_token(self):
        """A line that is the refused token alone adds nothing."""
        for line in (None, "", "sh", "  sh  "):
            conf = self._conf(line)
            with redirect_stderr(io.StringIO()):
                sec.warn_count("command", "sh", conf, strict=1)
            self.assertEqual(conf["logpath"].calls[0][2], {}, line)

    def test_warn_count_names_the_line_on_the_last_warning(self):
        """The refusal that ends the session names its line too."""
        conf = self._conf("sh -c id")
        conf["warning_counter"] = 0
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                sec.warn_count("command", "sh", conf, strict=1)
        self.assertEqual(
            conf["logpath"].calls[0][2], {"extra": {"lshell_line": "sh -c id"}}
        )

    def _session(self, tmpdir, extra_args=()):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            conf = CheckConfig(
                self.args
                + [f"--log={tmpdir}", "--loglevel=4", "--warning_counter=20"]
                + list(extra_args)
            ).returnconf()
        return conf, stderr

    def _refusal_lines(self, tmpdir, needle):
        logfile = os.path.join(tmpdir, getuser() + ".log")
        with open(logfile, "r", encoding="utf-8") as handle:
            text = handle.read()
        return text, [line for line in text.split("\n") if needle in line]

    def test_typed_line_reaches_the_log_file_on_one_line(self):
        """A refused command is logged with the line it was typed in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir, ["--strict=1"])
            with redirect_stderr(stderr):
                retcode = utils.cmd_parse_execute(
                    "sh -c id", shell_context=DummyShellContext(conf)
                )
            self.assertEqual(retcode, 126)
            self.assertNotIn(sec.LOGGED_LINE_KEY, conf)
            _text, lines = self._refusal_lines(tmpdir, 'forbidden command: "sh"')
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].endswith('forbidden command: "sh" in "sh -c id"'))
            # The user sees the refusal as before.
            self.assertIn('lshell: forbidden command: "sh"\n', stderr.getvalue())
            self.assertNotIn(' in "sh -c id"', stderr.getvalue())

    def test_line_of_the_token_alone_keeps_the_old_form(self):
        """A line that is the refused word alone is logged as before."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir, ["--strict=1"])
            with redirect_stderr(stderr):
                utils.cmd_parse_execute("sh", shell_context=DummyShellContext(conf))
            _text, lines = self._refusal_lines(tmpdir, 'forbidden command: "sh"')
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].endswith('forbidden command: "sh"'))

    def test_forbidden_path_names_its_line(self):
        """A refused path is logged with the line it was typed in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir, ["--path=['/var/empty-lshell']"])
            with redirect_stderr(stderr):
                utils.cmd_parse_execute(
                    "ls /etc", shell_context=DummyShellContext(conf)
                )
            _text, lines = self._refusal_lines(tmpdir, "forbidden path")
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].endswith(' in "ls /etc"'), lines[0])

    def test_forbidden_character_names_its_line(self):
        """A refused character is logged with the line it was typed in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir)
            with redirect_stderr(stderr):
                utils.cmd_parse_execute(
                    "echo a ; echo b", shell_context=DummyShellContext(conf)
                )
            _text, lines = self._refusal_lines(tmpdir, "forbidden character")
            self.assertEqual(len(lines), 1, lines)
            self.assertTrue(lines[0].endswith(' in "echo a ; echo b"'), lines[0])

    def test_control_character_line_is_one_log_line(self):
        """A line with a control character is written escaped, on one line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf, stderr = self._session(tmpdir)
            with redirect_stderr(stderr):
                utils.cmd_parse_execute(
                    "echo a\x01b", shell_context=DummyShellContext(conf)
                )
            text, lines = self._refusal_lines(tmpdir, "forbidden control char")
            self.assertNotIn("\x01", text)
            self.assertEqual(len(lines), 1, lines)
            self.assertIn("a\\x01b", lines[0])


if __name__ == "__main__":
    unittest.main()

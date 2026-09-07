""" Unit tests for lshell """

import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from getpass import getuser
from time import strftime, gmtime
from unittest.mock import patch

# import lshell specifics
from lshell.checkconfig import CheckConfig
from lshell.utils import get_aliases, updateprompt, parse_ps1, getpromptbase
from lshell import builtincmd
from lshell import sec
from lshell.shellcmd import ShellCmd

TOPDIR = f"{os.path.dirname(os.path.realpath(__file__))}/../"
CONFIG = f"{TOPDIR}/test/testfiles/test.conf"


class _NoexecLog:
    """A logger that swallows everything."""

    def __getattr__(self, _name):
        return lambda *args, **kwargs: None


class _NoexecShellContext:
    """The minimum shell context cmd_parse_execute reads."""

    def __init__(self, conf):
        self.conf = conf
        self.log = _NoexecLog()

    def do_help(self, _arg):
        return 0

    def do_exit(self, _arg=None):
        return 0


class TestFunctions(unittest.TestCase):
    """Unit tests for lshell"""

    args = [f"--config={CONFIG}", "--quiet=1"]
    userconf = CheckConfig(args).returnconf()

    def test_03_checksecure_doublepipe(self):
        """U03 | double pipes should be allowed, even if pipe is forbidden"""
        args = self.args + ["--forbidden=['|']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "ls || ls"
        return self.assertEqual(sec.check_secure(input_command, userconf)[0], 0)

    def test_04_checksecure_forbiddenpipe(self):
        """U04 | forbid pipe, should return 1"""
        args = self.args + ["--forbidden=['|']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "ls | ls"
        return self.assertEqual(sec.check_secure(input_command, userconf)[0], 1)

    def test_05_checksecure_forbiddenchar(self):
        """U05 | forbid character, should return 1"""
        args = self.args + ["--forbidden=['l']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "ls"
        return self.assertEqual(sec.check_secure(input_command, userconf)[0], 1)

    def test_06_checksecure_sudo_command(self):
        """U06 | quoted text should not be forbidden"""
        input_command = "sudo ls"
        return self.assertEqual(sec.check_secure(input_command, self.userconf)[0], 1)

    def test_07_checksecure_notallowed_command(self):
        """U07 | forbidden command, should return 1"""
        args = self.args + ["--allowed=['ls']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "ll"
        return self.assertEqual(sec.check_secure(input_command, userconf)[0], 1)

    def test_08_checkpath_notallowed_path(self):
        """U08 | forbidden command, should return 1"""
        args = self.args + ["--path=['/home', '/var']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "cd /tmp"
        return self.assertEqual(sec.check_path(input_command, userconf)[0], 1)

    def test_09_checkpath_notallowed_path_completion(self):
        """U09 | forbidden command, should return 1"""
        args = self.args + ["--path=['/home', '/var']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "cd /tmp/"
        return self.assertEqual(
            sec.check_path(input_command, userconf, completion=1)[0], 1
        )

    def test_10_checkpath_dollarparenthesis(self):
        """U10 | when $() is allowed, return 0 if path allowed"""
        args = self.args + ["--forbidden=[';', '&', '|','`','>','<', '${']"]
        userconf = CheckConfig(args).returnconf()
        input_command = "echo $(echo aze)"
        return self.assertEqual(sec.check_path(input_command, userconf)[0], 0)

    def test_11_checkconfig_configoverwrite(self):
        """U12 | forbid ';', then check_secure should return 1"""
        args = [f"--config={CONFIG}", "--strict=123"]
        userconf = CheckConfig(args).returnconf()
        return self.assertEqual(userconf["strict"], 123)

    def test_11b_merge_plus_minus_supported_for_all_list_merge_keys(self):
        """U12b | +/- merge semantics are applied for all merge-capable list keys."""
        args = self.args + [
            "--allowed=['basecmd'] + ['pluscmd'] - ['basecmd']",
            "--allowed_shell_escape=['ase_base'] + ['ase_plus'] - ['ase_base']",
            "--allowed_file_extensions=['.log'] + ['.txt'] - ['.log']",
            "--forbidden=[';'] + ['#'] - [';']",
            "--overssh=['scp', 'rsync'] + ['ls'] - ['scp']",
            "--path=['/'] - ['/var','/etc'] + ['/var/log']",
        ]
        userconf = CheckConfig(args).returnconf()

        self.assertIn("pluscmd", userconf["allowed"])
        self.assertNotIn("basecmd", userconf["allowed"])

        self.assertEqual(set(userconf["allowed_shell_escape"]), {"ase_plus"})
        self.assertEqual(set(userconf["allowed_file_extensions"]), {".txt"})

        self.assertIn("#", userconf["forbidden"])
        self.assertNotIn(";", userconf["forbidden"])

        self.assertIn("rsync", userconf["overssh"])
        self.assertIn("ls", userconf["overssh"])
        self.assertNotIn("scp", userconf["overssh"])

        self.assertTrue(userconf["path"][0].startswith("/|"))
        self.assertIn(f"{os.path.realpath('/var/log')}/|", userconf["path"][0])
        self.assertIn(f"{os.path.realpath('/var')}/|", userconf["path"][1])
        self.assertIn(f"{os.path.realpath('/etc')}/|", userconf["path"][1])

    def test_13_multiple_aliases_with_separator(self):
        """U13 | multiple aliases using &&, || and ; separators"""
        # enable &, | and ; characters
        aliases = {"foo": "foo -l", "bar": "open"}
        input_command = "foo; fooo  ;bar&&foo  &&   foo | bar||bar   ||     foo"
        return self.assertEqual(
            get_aliases(input_command, aliases),
            " foo -l; fooo  ; open&& foo -l  " "&& foo -l | open|| open   || foo -l",
        )

    def test_14_sudo_all_commands_expansion(self):
        """U14 | sudo_commands set to 'all' is equal to allowed variable"""
        args = self.args + ["--sudo_commands=all"]
        userconf = CheckConfig(args).returnconf()
        # exclude shell-internal builtins and sudo(8), but keep `ls`
        exclude = [cmd for cmd in builtincmd.builtins_list if cmd != "ls"] + ["sudo"]
        allowed = list(dict.fromkeys(x for x in userconf["allowed"] if x not in exclude))
        # sort lists to compare
        userconf["sudo_commands"].sort()
        allowed.sort()
        return self.assertEqual(allowed, userconf["sudo_commands"])

    def test_14b_allowed_all_unquoted_expands(self):
        """U14b | allowed=all (unquoted) expands to executable allow-list."""
        args = self.args + ["--allowed=all"]
        userconf = CheckConfig(args).returnconf()
        self.assertIsInstance(userconf["allowed"], list)
        self.assertIn("ls", userconf["allowed"])

    def test_14c_allowed_all_quoted_expands(self):
        """U14c | allowed='all' (quoted) expands to executable allow-list."""
        args = self.args + ["--allowed='all'"]
        userconf = CheckConfig(args).returnconf()
        self.assertIsInstance(userconf["allowed"], list)
        self.assertIn("ls", userconf["allowed"])

    def test_14d_sudo_all_quoted_expansion(self):
        """U14d | sudo_commands='all' (quoted) expands against effective allowed list."""
        args = self.args + ["--sudo_commands='all'"]
        userconf = CheckConfig(args).returnconf()
        self.assertIn("echo", userconf["sudo_commands"])
        self.assertIn("ll", userconf["sudo_commands"])
        self.assertIn("ls", userconf["sudo_commands"])
        self.assertEqual(
            userconf["sudo_commands"].count("ls"),
            1,
            msg="sudo_commands all-expansion must not duplicate ls",
        )

    def test_16_allowed_ld_preload_builtin(self):
        """U16 | builtin commands should NOT be prepended with LD_PRELOAD"""
        args = self.args + ["--allowed=['echo','export']"]
        userconf = CheckConfig(args).returnconf()
        # verify that export is not automatically added to the aliases (i.e.
        # prepended with LD_PRELOAD)
        return self.assertNotIn("export", userconf["aliases"])

    def test_17_allowed_exec_cmd(self):
        """U17 | allowed_shell_escape should NOT be prepended with LD_PRELOAD
        The command should not be added to the aliases variable
        """
        args = self.args + ["--allowed_shell_escape=['echo']"]
        userconf = CheckConfig(args).returnconf()
        # sort lists to compare
        return self.assertNotIn("echo", userconf["aliases"])

    def test_18_forbidden_environment(self):
        """U18 | unsafe environment are forbidden"""
        input_command = "export LD_PRELOAD=/lib64/ld-2.21.so"
        args = input_command
        retcode = builtincmd.cmd_export(args)[0]
        return self.assertEqual(retcode, 1)

    def test_19_allowed_environment(self):
        """U19 | other environment are accepted"""
        input_command = "export MY_PROJECT_VERSION=43"
        args = input_command
        retcode = builtincmd.cmd_export(args)[0]
        return self.assertEqual(retcode, 0)

    def test_22_prompt_short_0(self):
        """U22 | short_prompt = 0 should show dir compared to home dir"""
        expected = f"{getuser()}:~/foo$ "
        args = self.args + ["--prompt_short=0"]
        userconf = CheckConfig(args).returnconf()
        currentpath = f"{userconf['home_path']}/foo"
        prompt = updateprompt(currentpath, userconf)
        # sort lists to compare
        return self.assertEqual(prompt, expected)

    def test_23_prompt_short_1(self):
        """U23 | short_prompt = 1 should show only current dir"""
        expected = f"{getuser()}:foo$ "
        args = self.args + ["--prompt_short=1"]
        userconf = CheckConfig(args).returnconf()
        currentpath = f"{userconf['home_path']}/foo"
        prompt = updateprompt(currentpath, userconf)
        # sort lists to compare
        return self.assertEqual(prompt, expected)

    def test_24_prompt_short_2(self):
        """U24 | short_prompt = 2 should show full dir path"""
        expected = f"{getuser()}:{os.getcwd()}/foo$ "
        args = self.args + ["--prompt_short=2"]
        userconf = CheckConfig(args).returnconf()
        currentpath = f"{userconf['home_path']}/foo"
        prompt = updateprompt(currentpath, userconf)
        # sort lists to compare
        return self.assertEqual(prompt, expected)

    def test_25_disable_ld_preload(self):
        """U25 | empty path_noexec should disable LD_PRELOAD"""
        args = self.args + ["--allowed=['echo','export']", "--path_noexec=''"]
        userconf = CheckConfig(args).returnconf()
        # verify that no alias was created containing LD_PRELOAD
        return self.assertNotIn("echo", userconf["aliases"])

    def test_26_checksecure_quoted_command(self):
        """U26 | quoted command should be parsed"""
        input_command = 'echo 1 && "bash"'
        return self.assertEqual(sec.check_secure(input_command, self.userconf)[0], 1)

    def test_27_checksecure_quoted_command(self):
        """U27 | quoted command should be parsed"""
        input_command = '"bash" && echo 1'
        return self.assertEqual(sec.check_secure(input_command, self.userconf)[0], 1)

    def test_28_checksecure_quoted_command(self):
        """U28 | quoted command should be parsed"""
        input_command = "echo'/1.sh'"
        return self.assertEqual(sec.check_secure(input_command, self.userconf)[0], 1)

    def test_29_env_path_updates_path_variable(self):
        """U29 | Test that --env_path updates the PATH environment variable."""
        # store the original $PATH
        original_path = os.environ["PATH"]

        # Simulate passing the --env_path argument
        random_path = "/usr/random:/this_is_a_test"
        args = self.args + [
            f"--env_path='{random_path}'",
        ]
        CheckConfig(args).returnconf()

        # Verify that the $PATH has been updated correctly
        expected_path = f"{random_path}:{original_path}"

        # Assuming CheckConfig sets the environment variable
        self.assertEqual(os.environ["PATH"], expected_path)

        # Reset the PATH environment variable
        os.environ["PATH"] = original_path

    @patch("sys.exit")  # Mock sys.exit to prevent exiting the test on failure
    def test_30_invalid_new_path(self, mock_exit):
        """U30 | Test that an invalid new PATH triggers an error and sys.exit."""
        original_path = os.environ["PATH"]
        random_path = "/usr/random:/invalid$path"
        args = self.args + [
            f"--env_path='{random_path}'",
        ]

        # Simulate passing the --env_path argument
        CheckConfig(args).returnconf()

        # Check that sys.exit was called due to invalid path
        mock_exit.assert_called_once_with(1)

        # The PATH should not have been changed
        self.assertEqual(os.environ["PATH"], original_path)

    @patch("sys.exit")
    def test_31_new_path_starts_with_colon(self, mock_exit):
        """U31 | Test that a new PATH starting with a colon triggers an error."""
        original_path = os.environ["PATH"]
        random_path = ":/usr/random:/this_is_a_test"
        args = self.args + [
            f"--env_path='{random_path}'",
        ]

        # Simulate passing the --env_path argument
        CheckConfig(args).returnconf()

        # Check that sys.exit was called due to invalid path
        mock_exit.assert_called_once()

        # The PATH should not have been changed
        self.assertEqual(os.environ["PATH"], original_path)

    def test_32_lps1_user_host_time(self):
        r"""U32 | LPS1 using \u@\h - \t> format"""
        os.environ["LPS1"] = r"\u@\h - \t> "
        expected = f"{getuser()}@{os.uname()[1].split('.')[0]} - {strftime('%H:%M:%S', gmtime())}> "
        prompt = parse_ps1(os.getenv("LPS1"))
        self.assertEqual(prompt, expected)
        del os.environ["LPS1"]

    def test_33_lps1_with_cwd(self):
        r"""U33 | LPS1 should replace cwd with \w format"""
        os.environ["LPS1"] = r"\u:\w$ "
        expected = f"{getuser()}:{os.getcwd().replace(os.path.expanduser('~'), '~')}$ "
        prompt = parse_ps1(os.getenv("LPS1"))
        self.assertEqual(prompt, expected)
        del os.environ["LPS1"]

    def test_34_prompt_default_user_host(self):
        """U34 | Default config-based prompt should replace %u and %h"""
        userconf = CheckConfig(self.args).returnconf()
        userconf["prompt"] = "%u@%h"
        expected = f"{getuser()}@{os.uname()[1].split('.')[0]}"
        prompt = getpromptbase(userconf)
        self.assertEqual(prompt, expected)

    def test_35_updateprompt_lps1_defined(self):
        """U35 | LPS1 environment variable should override config-based prompt"""
        os.environ["LPS1"] = r"\u@\H \W$ "
        expected = f"{getuser()}@{os.uname()[1]} {os.path.basename(os.getcwd())}$ "
        userconf = CheckConfig(self.args).returnconf()
        prompt = updateprompt(os.getcwd(), userconf)
        self.assertEqual(prompt, expected)
        del os.environ["LPS1"]

    def test_36_updateprompt_home_path(self):
        """U36 | Prompt path should use '~' for home directory"""
        userconf = CheckConfig(self.args).returnconf()
        currentpath = userconf["home_path"]
        expected = f"{getuser()}:~$ "
        prompt = updateprompt(currentpath, userconf)
        self.assertEqual(prompt, expected)

    def test_37_updateprompt_short_prompt_level_1(self):
        """U37 | short_prompt = 1 should show only last directory in path"""
        userconf = CheckConfig(self.args).returnconf()
        userconf["prompt_short"] = 1
        currentpath = f"{userconf['home_path']}/foo/bar"
        expected = f"{getuser()}:bar$ "
        prompt = updateprompt(currentpath, userconf)
        self.assertEqual(prompt, expected)

    def test_38_updateprompt_short_prompt_level_2(self):
        """U38 | short_prompt = 2 should show full directory path"""
        userconf = CheckConfig(self.args).returnconf()
        userconf["prompt_short"] = 2
        currentpath = f"{userconf['home_path']}/foo/bar"
        expected = f"{getuser()}:{currentpath}$ "
        prompt = updateprompt(currentpath, userconf)
        self.assertEqual(prompt, expected)

    def test_39_updateprompt_path_inside_home(self):
        """U39 | Path inside home directory should start with '~'"""
        userconf = CheckConfig(self.args).returnconf()
        currentpath = f"{userconf['home_path']}/projects"
        expected = f"{getuser()}:~{currentpath[len(userconf['home_path']):]}$ "
        prompt = updateprompt(currentpath, userconf)
        self.assertEqual(prompt, expected)

    def test_40_updateprompt_absolute_path_outside_home(self):
        """U40 | Absolute path outside home should display fully in prompt"""
        userconf = CheckConfig(self.args).returnconf()
        currentpath = "/etc"
        expected = f"{getuser()}:{currentpath}$ "
        prompt = updateprompt(currentpath, userconf)
        self.assertEqual(prompt, expected)

    @patch("lshell.checkconfig.os.umask")
    def test_41_umask_sets_process_mask(self, mock_umask):
        """U41 | --umask should be parsed as octal and applied to process mask"""
        args = self.args + ["--umask=0002"]
        userconf = CheckConfig(args).returnconf()
        self.assertEqual(userconf["umask"], "0002")
        mock_umask.assert_called_once_with(0o002)

    def test_42_invalid_umask_value_raises(self):
        """U42 | invalid umask value should exit with error"""
        args = self.args + ["--umask=0088"]
        with self.assertRaises(SystemExit) as exc:
            CheckConfig(args).returnconf()
        self.assertEqual(exc.exception.code, 1)

    def test_42b_umask_masks_new_history_file_permissions(self):
        """U42b | configured umask should affect newly created lshell artifacts."""
        original_umask = os.umask(0)
        os.umask(original_umask)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                history_path = os.path.join(tmpdir, "lshell_history")
                args = self.args + [
                    "--umask=0077",
                    f"--history_file='{history_path}'",
                ]
                userconf = CheckConfig(args).returnconf()

                with open(userconf["history_file"], "w", encoding="utf-8") as handle:
                    handle.write("echo test\n")

                history_mode = stat.S_IMODE(os.stat(userconf["history_file"]).st_mode)
                self.assertEqual(history_mode, 0o600)
        finally:
            os.umask(original_umask)

    def test_42c_log_file_is_owner_only(self):
        """U42c | the per-user log file is created 0600, never group-readable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            args = self.args + [f"--log={tmpdir}", "--loglevel=4"]
            CheckConfig(args).returnconf()
            logfile = os.path.join(tmpdir, getuser() + ".log")
            self.assertTrue(os.path.exists(logfile))
            log_mode = stat.S_IMODE(os.stat(logfile).st_mode)
            self.assertEqual(log_mode, 0o600)

    def test_43_default_ls_alias_enables_auto_color(self):
        """U43 | default config should alias ls to a platform color option."""
        userconf = CheckConfig(self.args).returnconf()
        expected = None
        if sys.platform.startswith("linux"):
            expected = "ls --color=auto"
        elif sys.platform == "darwin" or "bsd" in sys.platform:
            expected = "ls -G"
        self.assertEqual(userconf["aliases"].get("ls"), expected)

    def test_44_explicit_ls_alias_is_preserved(self):
        """U44 | explicit ls alias should not be overwritten."""
        args = self.args + ["--aliases={'ls':'ls -lh'}"]
        userconf = CheckConfig(args).returnconf()
        self.assertEqual(userconf["aliases"].get("ls"), "ls -lh")

    def test_44b_auto_ls_alias_expands_during_local_execution(self):
        """U44b | local execution should dispatch through the generated ls alias."""
        saved_env = {}
        for key in ("SSH_CLIENT", "SSH_TTY", "SSH_ORIGINAL_COMMAND"):
            saved_env[key] = os.environ.get(key)
            os.environ.pop(key, None)
        try:
            userconf = CheckConfig(self.args).returnconf()
            expected = get_aliases("ls", userconf["aliases"])
            if not userconf.get("_auto_ls_alias") or expected is None:
                self.skipTest("platform does not synthesize an ls alias")

            with patch(
                "lshell.shellcmd.utils.cmd_parse_execute", return_value=0
            ) as mock_exec:
                shell = ShellCmd(
                    userconf,
                    args=[],
                    stdin=io.StringIO(),
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )
                shell.onecmd("ls")

            mock_exec.assert_called_once_with(expected, shell_context=shell)
        finally:
            for key, value in saved_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_45_policy_commands_enabled_by_default(self):
        """U45 | policy commands should be available by default."""
        userconf = CheckConfig(self.args).returnconf()
        self.assertIn("policy-show", userconf["allowed"])
        self.assertIn("policy-path", userconf["allowed"])
        self.assertIn("policy-sudo", userconf["allowed"])
        self.assertIn("lpath", userconf["allowed"])
        self.assertIn("lsudo", userconf["allowed"])

    def test_46_policy_commands_can_be_hidden(self):
        """U46 | policy commands can be hidden via --policy_commands=0."""
        args = self.args + ["--policy_commands=0"]
        userconf = CheckConfig(args).returnconf()
        self.assertNotIn("policy-show", userconf["allowed"])
        self.assertNotIn("policy-path", userconf["allowed"])
        self.assertNotIn("policy-sudo", userconf["allowed"])
        self.assertNotIn("lpath", userconf["allowed"])
        self.assertNotIn("lsudo", userconf["allowed"])

    def test_47_invalid_allowed_type_rejected(self):
        """U47 | allowed must be a list, scalar values should be rejected."""
        args = self.args + ["--allowed=1"]
        with self.assertRaises(SystemExit) as exc:
            CheckConfig(args).returnconf()
        self.assertEqual(exc.exception.code, 1)

    def test_48_history_file_accepts_string_and_expands_home(self):
        """U48 | --history_file should parse as string and resolve under home path."""
        history_name = ".lshell_%u_history"
        args = self.args + [f"--history_file='{history_name}'"]
        userconf = CheckConfig(args).returnconf()
        expected_history = os.path.join(
            userconf["home_path"], history_name.replace("%u", userconf["username"])
        )
        self.assertEqual(userconf["history_file"], expected_history)

    def test_49_history_file_absolute_path_kept_absolute(self):
        """U49 | absolute --history_file path should not be prefixed by home path."""
        history_path = "/tmp/lshell_%u_history"
        args = self.args + [f"--history_file='{history_path}'"]
        userconf = CheckConfig(args).returnconf()
        self.assertEqual(
            userconf["history_file"], history_path.replace("%u", userconf["username"])
        )

    @patch("lshell.checkconfig.CheckConfig.noexec_library_usable", return_value=False)
    def test_50_incompatible_noexec_library_is_disabled(self, _mock_usable):
        """U50 | a --path_noexec the shell cannot execute through is dropped."""
        with tempfile.NamedTemporaryFile() as fake_lib:
            args = self.args + [f"--path_noexec='{fake_lib.name}'"]
            userconf = CheckConfig(args).returnconf()
        self.assertNotIn("path_noexec", userconf)

    def _probe_with(self, returncode):
        """Run noexec_library_usable with a faked probe result."""
        checker = CheckConfig(self.args)
        completed = subprocess.CompletedProcess(
            args=["bash", "-c", "/usr/bin/true"], returncode=returncode, stdout=None
        )
        with patch("lshell.checkconfig.subprocess.run", return_value=completed) as run:
            usable = checker.noexec_library_usable("/usr/libexec/sudo/sudo_noexec.so")
        return usable, run

    def test_51_noexec_probe_must_execute_a_binary(self):
        """U51 | the noexec probe must run an EXEC, not a builtin.

        Commands run as [exec_shell, '-c', cmd], so LD_PRELOAD lands on that
        shell: a library that blocks exec breaks every command. The probe has
        to ask whether the shell can still execute, which only an exec answers.
        A builtin probe accepts a working library and every session then fails.
        """
        _usable, run = self._probe_with(0)
        probe_args = run.call_args.args[0]
        self.assertEqual(probe_args[:2], ["bash", "-c"])
        self.assertNotIn(probe_args[2], (":", "true"))
        self.assertTrue(os.path.isabs(probe_args[2].split()[0]))

    def test_52_noexec_library_blocking_exec_is_not_preloaded(self):
        """U52 | a preload that makes the shell fail to exec must be dropped."""
        usable, _run = self._probe_with(126)
        self.assertFalse(usable)

    def test_53_noexec_library_allowing_exec_is_kept(self):
        """U53 | a preload the shell can still execute through is kept."""
        usable, _run = self._probe_with(0)
        self.assertTrue(usable)

    def test_54_noexec_probe_survives_missing_shell(self):
        """U54 | an OSError from the probe must not raise into the login path."""
        checker = CheckConfig(self.args)
        with patch("lshell.checkconfig.subprocess.run", side_effect=OSError):
            self.assertFalse(checker.noexec_library_usable("/tmp/whatever.so"))

    def test_56_empty_path_noexec_keeps_shell_escape_commands(self):
        """U56 | disabling LD_PRELOAD must not drop allowed_shell_escape.

        The early return for an empty path_noexec skipped the merge at the end
        of set_noexec, so the documented way to switch the preload off also
        made every shell-escape command "forbidden".
        """
        args = self.args + [
            "--allowed=['echo']",
            "--allowed_shell_escape=['composer']",
            "--path_noexec=''",
        ]
        userconf = CheckConfig(args).returnconf()
        self.assertIn("composer", userconf["allowed"])
        self.assertNotIn("path_noexec", userconf)

    def test_57_missing_library_is_still_reported_as_not_found(self):
        """U57 | a box with no noexec library anywhere still says "not found"."""
        checker = CheckConfig(self.args)
        with patch("lshell.checkconfig.os.path.exists", return_value=False):
            with patch.object(checker, "log") as log:
                checker.set_noexec()
        messages = [str(call.args[0]) for call in log.error.call_args_list]
        self.assertTrue(any("not found" in message for message in messages))
        self.assertFalse(any("not preloaded" in message for message in messages))

    @patch("lshell.checkconfig.CheckConfig.noexec_library_usable", return_value=False)
    def test_58_noexec_library_is_kept_for_the_dispatcher(self, _mock_usable):
        """U58 | the library found is recorded even when it cannot be preloaded.

        The shell cannot take the preload, but the dispatcher it names can
        apply it to the command; the path must survive the probe's decision.
        """
        with tempfile.NamedTemporaryFile() as fake_lib:
            args = self.args + [f"--path_noexec='{fake_lib.name}'"]
            userconf = CheckConfig(args).returnconf()
        self.assertNotIn("path_noexec", userconf)
        self.assertEqual(userconf["noexec_library"], fake_lib.name)

    def _noexec_run(self, line, mock_exec, conf_extra=None, trusted=False):
        """Run one line through cmd_parse_execute with the policy checks
        answered "allowed" and return the exact string handed to exec_cmd."""
        from lshell import utils

        conf = CheckConfig(
            self.args
            + [
                "--allowed=['wget','find','grep','true','drush8','composer','echo','cat','ping']",
                "--allowed_shell_escape=['composer','drush8','true']",
                "--forbidden=[]",
            ]
        ).returnconf()
        conf.pop("path_noexec", None)
        conf["noexec_library"] = "/usr/libexec/sudo/sudo_noexec.so"
        if conf_extra:
            conf.update(conf_extra)
        shell = _NoexecShellContext(conf)
        allow = lambda line, conf, strict=None: (0, conf)
        with patch("lshell.utils.sec.check_forbidden_chars", side_effect=allow), patch(
            "lshell.utils.sec.check_secure", side_effect=allow
        ), patch("lshell.utils.sec.check_path", side_effect=allow), patch(
            "lshell.utils._command_exists", return_value=True
        ), patch("lshell.utils.audit.log_command_event") as mock_audit:
            utils.cmd_parse_execute(line, shell_context=shell, trusted_protocol=trusted)
        self.assertEqual(mock_exec.call_count, 1)
        return mock_exec.call_args.args[0], mock_audit

    _LIB = "LD_PRELOAD=/usr/libexec/sudo/sudo_noexec.so "

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_59_non_escape_command_is_prefixed_in_the_line(self, mock_exec):
        """U59 | a command outside allowed_shell_escape gets the LD_PRELOAD= prefix.

        The line that is audited stays the one typed; the mechanism lives only
        in the string the shell runs. No environment variable is handed over.
        """
        line, mock_audit = self._noexec_run("wget --version", mock_exec)
        self.assertEqual(line, self._LIB + "wget --version")
        self.assertIsNone(mock_exec.call_args.kwargs.get("extra_env"))
        audited = [c.args[1] for c in mock_audit.call_args_list if c.kwargs.get("allowed")]
        self.assertEqual(audited, ["wget --version"])

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_60_shell_escape_command_is_left_as_typed(self, mock_exec):
        """U60 | a command in allowed_shell_escape is handed over unchanged."""
        line, _ = self._noexec_run("composer -V", mock_exec)
        self.assertEqual(line, "composer -V")
        self.assertIsNone(mock_exec.call_args.kwargs.get("extra_env"))

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_61_mixed_pipeline_prefixes_only_the_non_escape_segment(self, mock_exec):
        """U61 | drush8 status | grep x: grep is preloaded, drush8 is not.

        The 0.11.7 decision was per line, so this pipeline handed nothing over
        and a plain `find ... | true` ran find unconfined. Per segment, the
        shell-escape command keeps its freedom and the other one does not.
        """
        line, _ = self._noexec_run("drush8 status | grep x", mock_exec)
        self.assertEqual(line, "drush8 status | " + self._LIB + "grep x")

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_62_piping_into_true_no_longer_disarms_find(self, mock_exec):
        """U62 | the measured escape: find ... -exec ... | true keeps find preloaded."""
        line, _ = self._noexec_run("find . -maxdepth 0 -exec echo X {} + | true", mock_exec)
        self.assertEqual(line, self._LIB + "find . -maxdepth 0 -exec echo X {} + | true")
        mock_exec.reset_mock()
        line, _ = self._noexec_run("true | find . -exec echo X {} +", mock_exec)
        self.assertEqual(line, "true | " + self._LIB + "find . -exec echo X {} +")

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_63_special_builtin_segment_is_never_prefixed(self, mock_exec):
        """U63 | an assignment prefix on a special builtin persists: skip it."""
        from lshell import utils

        parts = ["export FOO=1", "cat x"]
        parsed = [utils._parse_command(p) for p in parts]
        line = utils.noexec_prefix_line(parts, parsed, set(), "/l.so")
        self.assertEqual(line, "export FOO=1 | LD_PRELOAD=/l.so cat x")
        parts = ["FOO=1", "cat x"]
        parsed = [utils._parse_command(p) for p in parts]
        line = utils.noexec_prefix_line(parts, parsed, set(), "/l.so")
        self.assertEqual(line, "FOO=1 | LD_PRELOAD=/l.so cat x")

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_64_trusted_protocol_command_is_untouched(self, mock_exec):
        """U64 | scp/sftp-server over SSH keep their byte stream exactly as validated."""
        from lshell import variables

        binary = list(variables.TRUSTED_SFTP_PROTOCOL_BINARIES)[0]
        line, _ = self._noexec_run(f"{binary} -t /tmp", mock_exec, trusted=True)
        self.assertEqual(line, f"{binary} -t /tmp")

    def test_65_library_path_is_quoted_for_the_shell(self):
        """U65 | a configured library path with shell metacharacters is quoted."""
        from lshell import utils

        parts = ["cat x"]
        parsed = [utils._parse_command(p) for p in parts]
        line = utils.noexec_prefix_line(parts, parsed, set(), "/opt/my lib/noexec.so")
        self.assertEqual(line, "LD_PRELOAD='/opt/my lib/noexec.so' cat x")

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_66_a_typed_ld_preload_assignment_is_still_refused(self, mock_exec):
        """U66 | the user cannot supply the prefix (or an empty one) themselves."""
        from lshell import utils

        conf = CheckConfig(
            self.args + ["--allowed=['find']", "--forbidden=[]"]
        ).returnconf()
        conf["noexec_library"] = "/usr/libexec/sudo/sudo_noexec.so"
        shell = _NoexecShellContext(conf)
        allow = lambda line, conf, strict=None: (0, conf)
        with patch("lshell.utils.sec.check_forbidden_chars", side_effect=allow), patch(
            "lshell.utils.audit.log_command_event"
        ):
            rc = utils.cmd_parse_execute("LD_PRELOAD= find . -exec echo X {} +", shell_context=shell)
        self.assertEqual(rc, 126)
        self.assertEqual(mock_exec.call_count, 0)

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_68_exempt_and_privileged_commands_are_never_prefixed(self, mock_exec):
        """U68 | passwd/ping (landlock_exempt, setuid) and sudo/su keep their first word.

        landlock.is_exempt and exec_cmd's sudo/su branch read the first word
        of the line; a prefix there sandboxed ping (measured: "socktype:
        SOCK_RAW" through a real session) and would send sudo through the
        shell instead of the privileged path.
        """
        from lshell import utils

        parts = ["ping -c 1 host", "cat x", "sudo -l", "/usr/bin/passwd"]
        parsed = [utils._parse_command(p) for p in parts]
        line = utils.noexec_prefix_line(parts, parsed, set(), "/l.so", exempt=["passwd", "ping"])
        self.assertEqual(
            line, "ping -c 1 host | LD_PRELOAD=/l.so cat x | sudo -l | /usr/bin/passwd"
        )
        line, _ = self._noexec_run(
            "ping -c 1 host", mock_exec, conf_extra={"landlock_exempt": ["passwd", "ping"]}
        )
        self.assertEqual(line, "ping -c 1 host")

    def test_69_is_exempt_skips_assignment_prefixes(self):
        """U69 | LANG=C passwd is still the exempt setuid command."""
        from lshell import landlock

        conf = {"landlock_exempt": ["passwd", "ping"]}
        self.assertTrue(landlock.is_exempt("LANG=C passwd", conf))
        self.assertTrue(landlock.is_exempt("LD_PRELOAD=/l.so A_B=1 /usr/bin/ping -c 1 h", conf))
        self.assertFalse(landlock.is_exempt("LANG=C composer install", conf))
        self.assertFalse(landlock.is_exempt("LANG=C", conf))
        self.assertFalse(landlock.is_exempt("=x passwd", conf))

    def test_70_exec_cmd_decides_and_speaks_from_the_typed_line(self):
        """U70 | only the argv carries the prefix; sudo/su, is_exempt and messages read the typed line."""
        from lshell import utils

        seen = {}

        class _FakeProc:
            returncode = 0
            pid = 1

            def communicate(self, timeout=None):
                return (b"", b"")

            def poll(self):
                return 0

        def _fake_popen(cmd_args, **kwargs):
            seen["argv"] = list(cmd_args)
            seen["env"] = dict(kwargs.get("env") or {})
            return _FakeProc()

        conf = {
            "exec_shell": "/bin/sh",
            "landlock": 1,
            "landlock_rules": [("/tmp", "rw")],
            "landlock_abi": 0,
        }
        with patch("lshell.utils.subprocess.Popen", side_effect=_fake_popen), patch(
            "lshell.utils.landlock.is_exempt", return_value=False
        ) as mock_exempt:
            utils.exec_cmd(
                "LD_PRELOAD=/l.so wget -q x", conf=conf, display="wget -q x"
            )
        self.assertEqual(seen["argv"], ["/bin/sh", "-c", "LD_PRELOAD=/l.so wget -q x"])
        self.assertEqual(mock_exempt.call_args.args[0], "wget -q x")
        # the layer lives in the argv and nowhere else: the child environment
        # carries neither the old hand-over nor a whole-process preload
        self.assertNotIn("LSHELL_NOEXEC", seen["env"])
        self.assertNotIn("LD_PRELOAD", seen["env"])
        # the privileged branch reads the typed line: a prefixed sudo would
        # otherwise be handed to the shell instead of run directly
        with patch("lshell.utils.subprocess.Popen", side_effect=_fake_popen), patch(
            "lshell.utils.landlock.is_exempt", return_value=False
        ):
            utils.exec_cmd("sudo -l", conf=conf, display="sudo -l")
        self.assertEqual(seen["argv"], ["sudo", "-l"])

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_71_a_shell_that_takes_the_preload_gets_the_environment_not_the_prefix(self, mock_exec):
        """U71 | with path_noexec usable the upstream whole-line LD_PRELOAD applies, and no prefix."""
        line, _ = self._noexec_run(
            "wget --version", mock_exec, conf_extra={"path_noexec": "/usr/libexec/sudo/sudo_noexec.so"}
        )
        self.assertEqual(line, "wget --version")
        self.assertEqual(
            mock_exec.call_args.kwargs.get("extra_env"), {"LD_PRELOAD": "/usr/libexec/sudo/sudo_noexec.so"}
        )
        self.assertNotIn("display", mock_exec.call_args.kwargs)

    def test_72_sftp_protocol_binary_is_never_prefixed(self):
        """U72 | sftp-server keeps its byte stream on either dispatch path."""
        from lshell import utils, variables

        parts = ["/usr/lib/openssh/sftp-server", "cat x"]
        parsed = [utils._parse_command(p) for p in parts]
        line = utils.noexec_prefix_line(
            parts, parsed, set(), "/l.so", exempt=list(variables.TRUSTED_SFTP_PROTOCOL_BINARIES)
        )
        self.assertEqual(line, "/usr/lib/openssh/sftp-server | LD_PRELOAD=/l.so cat x")

    @patch("lshell.utils.exec_cmd", return_value=0)
    def test_67_no_library_means_the_line_is_untouched(self, mock_exec):
        """U67 | without a library nothing is written into the line."""
        from lshell import utils

        conf = CheckConfig(
            self.args + ["--allowed=['wget']", "--allowed_shell_escape=[]", "--forbidden=[]"]
        ).returnconf()
        conf.pop("path_noexec", None)
        conf.pop("noexec_library", None)
        shell = _NoexecShellContext(conf)
        allow = lambda line, conf, strict=None: (0, conf)
        with patch("lshell.utils.sec.check_forbidden_chars", side_effect=allow), patch(
            "lshell.utils.sec.check_secure", side_effect=allow
        ), patch("lshell.utils.sec.check_path", side_effect=allow), patch(
            "lshell.utils._command_exists", return_value=True
        ), patch("lshell.utils.audit.log_command_event"):
            utils.cmd_parse_execute("wget --version", shell_context=shell)
        self.assertEqual(mock_exec.call_args.args[0], "wget --version")

    @patch("lshell.checkconfig.CheckConfig.noexec_library_usable", return_value=False)
    def test_55_unusable_noexec_is_not_reported_as_missing(self, _mock_usable):
        """U55 | a present-but-unusable library must not log "not found".

        Both lines used to be written at every session on a box that ships the
        library, sending operators after a packaging fault that is not there.
        """
        with tempfile.NamedTemporaryFile() as fake_lib:
            args = self.args + [f"--path_noexec='{fake_lib.name}'"]
            checker = CheckConfig(args)
            with patch.object(checker, "log") as log:
                checker.set_noexec()
        messages = [str(call.args[0]) for call in log.error.call_args_list]
        self.assertTrue(any("not preloaded" in message for message in messages))
        self.assertFalse(any("not found" in message for message in messages))

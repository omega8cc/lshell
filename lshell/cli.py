"""CLI entry points for lshell."""

import ast
import os
import signal
import sys
import uuid

from lshell import policy as policy_mode
from lshell import systemsetup as system_setup
from lshell import hardeninit as harden_init
from lshell import audit
from lshell import containment
from lshell.checkconfig import CheckConfig
from lshell.shellcmd import LshellTimeOut, ShellCmd


def keep_undecodable_bytes(streams=None):
    """Read and write a byte that is no part of a letter as a surrogate.

    In a locale such as en_US.UTF-8 Python decodes the terminal strictly, so
    a typed byte that is not valid there raised UnicodeDecodeError out of
    input() and ended the session before the line was checked or logged.
    With surrogateescape the byte travels as Python's C.UTF-8 and UTF-8 mode
    already carry it: the checks read it, a command gets the byte back, an
    echo of it reaches the terminal as typed, and the log writes it as \\xNN.
    """
    if streams is None:
        streams = (sys.stdin, sys.stdout)
    for stream in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="surrogateescape")
        except (AttributeError, OSError, TypeError, ValueError):
            pass


def main():
    """Main CLI entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "policy-show":
        sys.exit(policy_mode.main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "setup-system":
        sys.exit(system_setup.main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "harden-init":
        sys.exit(harden_init.main(sys.argv[2:]))

    keep_undecodable_bytes()

    # Set SHELL and process LSHELL_ARGS env variables.
    os.environ["SHELL"] = os.path.realpath(sys.argv[0])
    if "LSHELL_ARGS" in os.environ:
        try:
            parsed_args = ast.literal_eval(os.environ["LSHELL_ARGS"])
        except (ValueError, SyntaxError):
            parsed_args = []
        if not isinstance(parsed_args, (list, tuple)) or not all(
            isinstance(item, str) for item in parsed_args
        ):
            parsed_args = []
        args = sys.argv[1:] + list(parsed_args)
    else:
        args = sys.argv[1:]

    userconf = CheckConfig(args).returnconf()
    userconf["session_id"] = os.environ.get("LSHELL_SESSION_ID", uuid.uuid4().hex)
    os.environ["LSHELL_SESSION_ID"] = userconf["session_id"]
    session_accountant = containment.SessionAccountant(userconf)
    try:
        session_accountant.acquire()
    except containment.ContainmentViolation as exception:
        logger = userconf.get("logpath")
        if logger:
            logger.critical(exception.log_message)
        audit.log_security_event(
            userconf,
            action="session_start",
            allowed=False,
            reason=exception.reason_code,
            command="lshell startup",
            level="warning",
            message="lshell runtime containment decision",
        )
        sys.stderr.write(exception.user_message + "\n")
        sys.exit(1)

    def disable_ctrl_z(_signum, _frame):
        return None

    signal.signal(signal.SIGTSTP, disable_ctrl_z)

    cli = ShellCmd(userconf, args)
    try:
        while True:
            try:
                cli.cmdloop()
                break
            except KeyboardInterrupt:
                # Keep interactive sessions alive when Ctrl+C races outside
                # command-specific handlers.
                sys.stdout.write("\n")
                continue
            except EOFError:
                sys.stdout.write("\nExited on user request\n")
                sys.exit(0)
    except LshellTimeOut:
        userconf["logpath"].error("Timer expired")
        sys.stdout.write("\nTime is up.\n")
    finally:
        session_accountant.release()

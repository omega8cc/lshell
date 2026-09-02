"""Landlock confinement for every process a shell command spawns.

lshell decides what a user may TYPE; it cannot see what an allowed program
does next. A composer script, a git hook, a drush command file or a php -r
runs as the same uid and reads whatever DAC lets that uid read. Landlock
(Linux 5.13+, unprivileged) lets the child restrict itself before exec to an
allow-list of filesystem rights, inherited by every descendant and never
liftable again: a kernel boundary where LD_PRELOAD tricks are not (a child
can unset the variable, a static binary ignores it).

Configuration (all optional, see etc/lshell.conf):

  landlock         : 1            enable (default 0)
  landlock_ro      : [ ... ]      read + execute roots (system baseline)
  landlock_rw      : [ ... ]      read + write + execute roots, in ADDITION
                                  to the user's 'path' entries and home
  landlock_exempt  : [ ... ]      command names run WITHOUT the sandbox
                                  (setuid tools: no_new_privs would break
                                  them; default ['passwd', 'ping'])
  landlock_strict  : 1            refuse to run commands when the kernel has
                                  no Landlock (default 0: run unrestricted
                                  and log, because a lockout of every shell
                                  user is worse than the missing sandbox)

The user's 'path' allow-list is the natural RW set: on BOA that is the
account's own tree, its home and its gem/npm stores. Relocated stores
reached through a symlink inside those roots are resolved and added, so a
files/ link pointing at a mounted volume keeps working.
"""

import ctypes
import ctypes.util
import os
import struct

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

ACCESS_FS_EXECUTE = 1 << 0
ACCESS_FS_WRITE_FILE = 1 << 1
ACCESS_FS_READ_FILE = 1 << 2
ACCESS_FS_READ_DIR = 1 << 3
ACCESS_FS_REMOVE_DIR = 1 << 4
ACCESS_FS_REMOVE_FILE = 1 << 5
ACCESS_FS_MAKE_CHAR = 1 << 6
ACCESS_FS_MAKE_DIR = 1 << 7
ACCESS_FS_MAKE_REG = 1 << 8
ACCESS_FS_MAKE_SOCK = 1 << 9
ACCESS_FS_MAKE_FIFO = 1 << 10
ACCESS_FS_MAKE_BLOCK = 1 << 11
ACCESS_FS_MAKE_SYM = 1 << 12
ACCESS_FS_REFER = 1 << 13        # ABI 2
ACCESS_FS_TRUNCATE = 1 << 14     # ABI 3
ACCESS_FS_IOCTL_DEV = 1 << 15    # ABI 5

ACCESS_RO = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
ACCESS_RW_V1 = (
    ACCESS_RO
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
)

# syscall numbers by machine; Landlock landed in 5.13 with the same numbers
# on every architecture that uses the generic table.
_SYSCALLS = {
    "x86_64": (444, 445, 446),
    "aarch64": (444, 445, 446),
    "riscv64": (444, 445, 446),
    "ppc64le": (444, 445, 446),
    "s390x": (444, 445, 446),
}

DEFAULT_RO = [
    "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc",
    "/opt", "/proc", "/sys", "/run", "/var",
]
DEFAULT_RW = ["/tmp", "/var/tmp", "/dev"]
DEFAULT_EXEMPT = ["passwd", "ping"]

_libc = None


def _libc_handle():
    global _libc
    if _libc is None:
        name = ctypes.util.find_library("c") or "libc.so.6"
        _libc = ctypes.CDLL(name, use_errno=True)
    return _libc


def _syscalls():
    return _SYSCALLS.get(os.uname().machine)


def abi_version():
    """Return the kernel's Landlock ABI version, or 0 when unavailable."""
    nums = _syscalls()
    if os.name != "posix" or not nums or not hasattr(os, "uname") or os.uname().sysname != "Linux":
        return 0
    try:
        libc = _libc_handle()
        result = libc.syscall(nums[0], None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    except (OSError, AttributeError):
        return 0
    return result if result > 0 else 0


def _split_path_acl(acl):
    """lshell keeps the user's allowed paths as one 'a/|b/|...|home' string."""
    out = []
    if not acl:
        return out
    for item in str(acl).split("|"):
        item = item.strip()
        if not item:
            continue
        item = item.rstrip("/") or "/"
        if item not in out:
            out.append(item)
    return out


def _resolve_links_below(root, max_depth=3):
    """Real targets of symlinks in the first levels of a root.

    Three levels: a relocated files store sits at <root>/static/files, and a
    per-user drush extension farm at <home>/.drush/usr/<tool>, each link
    pointing outside the root. Deeper links are the user's own business.
    """
    found = []
    try:
        root_real = os.path.realpath(root)
    except OSError:
        return found
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            entries = os.scandir(current)
        except OSError:
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        target = os.path.realpath(entry.path)
                        if os.path.isdir(target) and not target.startswith(root_real + "/") and target != root_real:
                            if target not in found:
                                found.append(target)
                    elif entry.is_dir(follow_symlinks=False) and depth + 1 < max_depth:
                        stack.append((entry.path, depth + 1))
                except OSError:
                    continue
    return found


def build_rules(conf):
    """Return [(path, 'ro'|'rw'), ...] from the resolved configuration.

    RW: the user's 'path' allow-list (already realpath'd by lshell, home
    included), landlock_rw, and the real targets of symlinks found up to three
    levels inside each RW root. RO: landlock_ro. Paths that do not exist are
    dropped, so a template can list every distro's layout at once.
    """
    rw = []
    for item in _split_path_acl(conf.get("path", ["", ""])[0]):
        if item not in rw:
            rw.append(item)
    for item in conf.get("landlock_rw", DEFAULT_RW) or []:
        item = str(item).rstrip("/") or "/"
        if item not in rw:
            rw.append(item)
    for base in list(rw):
        for target in _resolve_links_below(base):
            if target not in rw:
                rw.append(target)
    ro = []
    for item in conf.get("landlock_ro", DEFAULT_RO) or []:
        item = str(item).rstrip("/") or "/"
        if item not in ro and item not in rw:
            ro.append(item)
    rules = [(p, "rw") for p in rw if os.path.isdir(p)]
    rules += [(p, "ro") for p in ro if os.path.isdir(p)]
    return rules


def is_exempt(cmd, conf):
    """True when the command's executable name is on landlock_exempt."""
    exempt = conf.get("landlock_exempt", DEFAULT_EXEMPT)
    if exempt is None:
        exempt = DEFAULT_EXEMPT
    try:
        first = str(cmd).strip().split()[0]
    except IndexError:
        return False
    return os.path.basename(first) in [str(e) for e in exempt]


def restrict(rules, abi):
    """Apply the ruleset to the CURRENT process. Call in the child before exec.

    Raises OSError when the kernel refuses; the caller decides fail-open vs
    fail-closed.
    """
    nums = _syscalls()
    libc = _libc_handle()
    handled = ACCESS_RW_V1
    if abi >= 2:
        handled |= ACCESS_FS_REFER
    if abi >= 3:
        handled |= ACCESS_FS_TRUNCATE
    if abi >= 5:
        handled |= ACCESS_FS_IOCTL_DEV
    rw_rights = handled
    ro_rights = ACCESS_RO
    attr = struct.pack("Q", handled)
    ruleset_fd = libc.syscall(nums[0], attr, len(attr), 0)
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    try:
        for path, mode in rules:
            try:
                parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                rights = rw_rights if mode == "rw" else ro_rights
                rule = struct.pack("=Qi", rights & handled, parent_fd)
                if libc.syscall(nums[1], ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, rule, 0) < 0:
                    raise OSError(ctypes.get_errno(), "landlock_add_rule: %s" % path)
            finally:
                os.close(parent_fd)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
        if libc.syscall(nums[2], ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(ruleset_fd)


def enabled(conf):
    try:
        return int(conf.get("landlock", 0)) == 1
    except (TypeError, ValueError):
        return False


def strict(conf):
    try:
        return int(conf.get("landlock_strict", 0)) == 1
    except (TypeError, ValueError):
        return False

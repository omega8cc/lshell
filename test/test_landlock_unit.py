"""Unit tests for lshell.landlock (no kernel support needed)."""

import os
import unittest
from unittest import mock

from lshell import landlock


class TestLandlockRules(unittest.TestCase):
    def test_split_path_acl(self):
        acl = "/data/disk/o1/static/|/opt/user/gems/o1.ftp/|/home/o1.ftp"
        self.assertEqual(
            landlock._split_path_acl(acl),
            ["/data/disk/o1/static", "/opt/user/gems/o1.ftp", "/home/o1.ftp"],
        )
        self.assertEqual(landlock._split_path_acl(""), [])
        self.assertEqual(landlock._split_path_acl("/"), ["/"])

    def test_build_rules_uses_path_and_defaults(self):
        conf = {"path": ["/tmp/|/nonexistent-root-xyz", ""]}
        rules = landlock.build_rules(conf)
        paths = dict(rules)
        self.assertEqual(paths.get("/tmp"), "rw")
        self.assertNotIn("/nonexistent-root-xyz", paths)
        for root in ("/usr", "/etc"):
            if os.path.isdir(root):
                self.assertEqual(paths.get(root), "ro")

    def test_rw_wins_over_ro(self):
        conf = {"path": ["/tmp", ""], "landlock_ro": ["/tmp", "/usr"], "landlock_rw": []}
        rules = landlock.build_rules(conf)
        self.assertEqual(dict(rules).get("/tmp"), "rw")

    def test_is_exempt(self):
        conf = {"landlock_exempt": ["passwd", "ping"]}
        self.assertTrue(landlock.is_exempt("passwd", conf))
        self.assertTrue(landlock.is_exempt("/usr/bin/ping -c 1 host", conf))
        self.assertFalse(landlock.is_exempt("composer install", conf))
        self.assertFalse(landlock.is_exempt("", conf))
        self.assertTrue(landlock.is_exempt("passwd", {}))

    def test_enabled_and_strict_parse(self):
        self.assertTrue(landlock.enabled({"landlock": 1}))
        self.assertTrue(landlock.enabled({"landlock": "1"}))
        self.assertFalse(landlock.enabled({}))
        self.assertFalse(landlock.enabled({"landlock": "yes"}))
        self.assertTrue(landlock.strict({"landlock_strict": 1}))
        self.assertFalse(landlock.strict({}))

    def test_links_resolved_three_levels_down(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as target:
            deep = os.path.join(root, "a", "b")
            os.makedirs(deep)
            os.symlink(target, os.path.join(deep, "link"))
            found = landlock._resolve_links_below(root)
            self.assertIn(os.path.realpath(target), found)
            too_deep = os.path.join(root, "a", "b", "c")
            os.makedirs(too_deep)
            os.symlink(target + "x", os.path.join(too_deep, "link2"))
            self.assertNotIn(os.path.realpath(target + "x"), landlock._resolve_links_below(root))

    def test_abi_version_is_int(self):
        self.assertIsInstance(landlock.abi_version(), int)
        self.assertGreaterEqual(landlock.abi_version(), 0)

    def test_restrict_raises_when_kernel_refuses(self):
        fake = mock.MagicMock()
        fake.syscall.return_value = -1
        with mock.patch.object(landlock, "_libc_handle", return_value=fake), \
             mock.patch.object(landlock, "_syscalls", return_value=(444, 445, 446)), \
             mock.patch("ctypes.get_errno", return_value=38):
            with self.assertRaises(OSError):
                landlock.restrict([("/tmp", "rw")], 3)


if __name__ == "__main__":
    unittest.main()

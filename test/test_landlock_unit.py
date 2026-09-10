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
        # the decision is for the whole line: one exempt segment does not
        # lift the ruleset off the rest
        self.assertTrue(landlock.is_exempt("LANG=C passwd", conf))
        self.assertFalse(landlock.is_exempt("ping -c 1 host | composer install", conf))
        self.assertFalse(landlock.is_exempt("passwd; find /data -type f", conf))
        self.assertFalse(landlock.is_exempt("ping -c 1 host && composer install", conf))
        self.assertTrue(landlock.is_exempt("ping -c 1 host | ping -c 1 host", conf))
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
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as target, \
             mock.patch.object(landlock, "_uid_trusted", return_value=True):
            deep = os.path.join(root, "a", "b")
            os.makedirs(deep)
            os.symlink(target, os.path.join(deep, "link"))
            found = landlock._resolve_links_below(root)
            self.assertIn(os.path.realpath(target), found)
            too_deep = os.path.join(root, "a", "b", "c")
            os.makedirs(too_deep)
            os.symlink(target + "x", os.path.join(too_deep, "link2"))
            self.assertNotIn(os.path.realpath(target + "x"), landlock._resolve_links_below(root))

    def test_link_target_reads_the_link_owner(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as target:
            link = os.path.join(root, "l")
            os.symlink(target, link)
            expected = os.path.realpath(target) if os.lstat(link).st_uid == 0 else None
            self.assertEqual(landlock._link_target(link), expected)
            self.assertIsNone(landlock._link_target(os.path.join(root, "missing")))
            self.assertIsNone(landlock._link_target(root))
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                self.assertEqual(landlock._link_target(link), os.path.realpath(target))
                os.symlink("rel/../" + os.path.basename(target), os.path.join(root, "rel"))
                self.assertEqual(landlock._link_target(os.path.join(root, "rel")), os.path.realpath(os.path.join(root, os.path.basename(target))))

    def test_user_owned_link_through_build_rules_unmocked(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as target:
            own = os.path.realpath(own)
            os.symlink(target, os.path.join(own, "mine"))
            conf = {"path": [own, ""], "landlock_rw": [], "landlock_ro": []}
            rules = landlock.build_rules(conf)
            if os.geteuid() == 0:
                self.assertIn((os.path.realpath(target), "rw"), rules)
            else:
                self.assertEqual(rules, [(own, "rw")])

    def test_read_only_root_or_inside_one_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as ro:
            own, ro = os.path.realpath(own), os.path.realpath(ro)
            inside = os.path.join(ro, "inside")
            os.makedirs(inside)
            os.symlink(ro, os.path.join(own, "exact"))
            os.symlink(inside, os.path.join(own, "deeper"))
            conf = {"path": [own, ""], "landlock_rw": [], "landlock_ro": [ro]}
            warnings = []
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                rules = landlock.build_rules(conf, warnings.append)
            self.assertEqual(rules, [(own, "rw"), (ro, "ro")])
            self.assertEqual(len(warnings), 2)

    def test_configured_roots_are_compared_by_real_path(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as real:
            own, real = os.path.realpath(own), os.path.realpath(real)
            alias = os.path.join(own, "alias-root")
            os.symlink(real, alias)
            os.symlink(real, os.path.join(own, "hole"))
            conf = {"path": [own, ""], "landlock_rw": [], "landlock_ro": [alias]}
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                rules = landlock.build_rules(conf)
            self.assertNotIn((real, "rw"), rules)
            self.assertEqual(dict(rules).get(alias), "ro")

    def test_user_owned_links_are_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as target:
            os.symlink(target, os.path.join(root, "link"))
            with mock.patch.object(landlock, "_uid_trusted", return_value=False):
                self.assertEqual(landlock._resolve_links_below(root), [])
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                self.assertIn(os.path.realpath(target), landlock._resolve_links_below(root))

    def test_planted_link_to_root_never_widens(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as shared:
            own, shared = os.path.realpath(own), os.path.realpath(shared)
            os.symlink("/", os.path.join(own, "planted"))
            os.symlink("/", os.path.join(shared, "planted"))
            conf = {"path": [own, ""], "landlock_rw": [shared], "landlock_ro": ["/usr", "/etc"]}
            for trusted in (False, True):
                warnings = []
                with mock.patch.object(landlock, "_uid_trusted", return_value=trusted):
                    rules = landlock.build_rules(conf, warnings.append)
                self.assertNotIn(("/", "rw"), rules)
                self.assertEqual(dict(rules).get(own), "rw")
                self.assertEqual(bool(warnings), trusted)

    def test_shared_rw_roots_are_never_scanned(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as shared, \
             tempfile.TemporaryDirectory() as target:
            own, shared = os.path.realpath(own), os.path.realpath(shared)
            os.symlink(target, os.path.join(shared, "link"))
            conf = {"path": [own, ""], "landlock_rw": [shared], "landlock_ro": []}
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                rules = landlock.build_rules(conf)
            self.assertNotIn((os.path.realpath(target), "rw"), rules)
            self.assertEqual(dict(rules).get(shared), "rw")

    def test_parent_of_a_configured_root_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as outer:
            own, outer = os.path.realpath(own), os.path.realpath(outer)
            inner = os.path.join(outer, "inner")
            os.makedirs(inner)
            os.symlink(outer, os.path.join(own, "up"))
            conf = {"path": [own, ""], "landlock_rw": [], "landlock_ro": [inner]}
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                rules = landlock.build_rules(conf)
            self.assertNotIn((outer, "rw"), rules)
            self.assertEqual(dict(rules).get(inner), "ro")

    def test_root_owned_link_outside_the_roots_is_added_once(self):
        import tempfile
        with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as farm:
            own, farm = os.path.realpath(own), os.path.realpath(farm)
            tool = os.path.join(farm, "tool")
            os.makedirs(tool)
            os.makedirs(os.path.join(own, ".drush", "usr"))
            os.symlink(tool, os.path.join(own, ".drush", "usr", "tool"))
            os.symlink(os.path.join(own, ".drush"), os.path.join(own, "self"))
            conf = {"path": [own, ""], "landlock_rw": [], "landlock_ro": []}
            with mock.patch.object(landlock, "_uid_trusted", return_value=True):
                rules = landlock.build_rules(conf)
            self.assertEqual([p for p, m in rules if m == "rw"], [own, tool])

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

import os
import tempfile
import unicodedata
import unittest
from pathlib import Path

import helpers  # noqa: F401  (sets sys.path)
from session_exporter.paths import RepoMatcher, claude_project_dirname, normalize, safe_component


class PosixMatchingTest(unittest.TestCase):
    def setUp(self):
        self.m = RepoMatcher("/work/team-repo", case_mode="sensitive")

    def test_exact_and_subdirectory(self):
        self.assertEqual(self.m.classify("/work/team-repo"), "exact")
        self.assertEqual(self.m.classify("/work/team-repo/"), "exact")
        self.assertEqual(self.m.classify("/work/./x/../team-repo"), "exact")
        self.assertEqual(self.m.classify("/work/team-repo/src/app"), "subdirectory")

    def test_similarly_named_directories_do_not_match(self):
        for cwd in ("/work/team-repo-old", "/work/team-repo2", "/work/team", "/work",
                    "/other/work/team-repo", "/work/team-repo.bak/src"):
            self.assertIsNone(self.m.classify(cwd), cwd)

    def test_case_sensitivity_modes(self):
        self.assertIsNone(self.m.classify("/Work/Team-Repo"))
        ci = RepoMatcher("/work/team-repo", case_mode="insensitive")
        self.assertEqual(ci.classify("/Work/Team-Repo/src"), "subdirectory")

    def test_relative_and_invalid_paths(self):
        self.assertIsNone(self.m.classify("team-repo"))
        self.assertIsNone(self.m.classify(""))
        with self.assertRaises(ValueError):
            RepoMatcher("relative/repo")

    def test_unicode_normalization(self):
        nfd = unicodedata.normalize("NFD", "/work/팀-프로젝트")
        nfc = unicodedata.normalize("NFC", "/work/팀-프로젝트")
        self.assertEqual(RepoMatcher(nfd, "sensitive").classify(nfc), "exact")


class WindowsMatchingTest(unittest.TestCase):
    def setUp(self):
        self.m = RepoMatcher(r"C:\Users\Student\team-repo")

    def test_case_and_separator_insensitive(self):
        self.assertEqual(self.m.classify(r"c:\users\student\TEAM-REPO"), "exact")
        self.assertEqual(self.m.classify("C:/Users/Student/team-repo/src"), "subdirectory")
        self.assertEqual(self.m.classify("\\\\?\\C:\\Users\\Student\\team-repo"), "exact")

    def test_non_matches(self):
        self.assertIsNone(self.m.classify(r"C:\Users\Student\team-repo-old"))
        self.assertIsNone(self.m.classify(r"D:\Users\Student\team-repo"))
        self.assertIsNone(self.m.classify("/Users/Student/team-repo"))

    def test_unc_paths(self):
        m = RepoMatcher(r"\\server\share\team-repo")
        self.assertEqual(m.classify(r"\\SERVER\share\team-repo\src"), "subdirectory")
        self.assertIsNone(m.classify(r"\\server\other\team-repo"))

    def test_normalize_flavor(self):
        self.assertEqual(normalize(r"C:\A\b", False).flavor, "windows")
        self.assertEqual(normalize("/a/b", False).flavor, "posix")


@unittest.skipIf(os.name == "nt", "symlink creation needs privileges on Windows")
class SymlinkTest(unittest.TestCase):
    def test_symlinked_repo_and_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp, "real-repo")
            (real / "src").mkdir(parents=True)
            link = Path(tmp, "link-repo")
            link.symlink_to(real, target_is_directory=True)
            # repo given via the link, session recorded the real path
            self.assertEqual(RepoMatcher(str(link)).classify(str(real.resolve())), "exact")
            # repo given as real path, session recorded the link
            self.assertEqual(RepoMatcher(str(real)).classify(str(link / "src")), "subdirectory")
            # a sibling directory is still not a match
            other = Path(tmp, "real-repo-old")
            other.mkdir()
            self.assertIsNone(RepoMatcher(str(link)).classify(str(other)))
            # a folder inside the repo that is a symlink to another project
            # belongs to that other project
            (real / "vendor").symlink_to(other, target_is_directory=True)
            self.assertIsNone(RepoMatcher(str(real)).classify(str(real / "vendor")))
            # a recorded path that no longer exists is compared textually
            self.assertEqual(RepoMatcher(str(real)).classify(str(real / "gone")), "subdirectory")


class EncodingTest(unittest.TestCase):
    def test_claude_dirname_collisions(self):
        self.assertEqual(claude_project_dirname("/w/team-repo"), "-w-team-repo")
        self.assertEqual(claude_project_dirname("/w/team/repo"), "-w-team-repo")
        self.assertEqual(claude_project_dirname(r"C:\Users\s\repo"), "C--Users-s-repo")

    def test_safe_component(self):
        for bad in ("..", ".", "", "CON", "nul.txt", "com1", "name.", "a/b\\c"):
            out = safe_component(bad)
            self.assertNotIn(out, ("..", ".", ""))
            self.assertNotIn("/", out)
            self.assertNotIn("\\", out)
            self.assertFalse(out.endswith("."), out)
        self.assertEqual(safe_component("CON"), "_CON")
        long_jsonl = safe_component("x" * 300 + ".jsonl")
        self.assertTrue(long_jsonl.endswith(".jsonl"))
        self.assertLessEqual(len(long_jsonl), 120)
        self.assertFalse(safe_component("x" * 119 + ".y").endswith("."))
        self.assertEqual(safe_component("agent-1.jsonl"), "agent-1.jsonl")


if __name__ == "__main__":
    unittest.main()

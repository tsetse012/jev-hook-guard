"""Exclude: patterns from a file, matched on normalized text and on text with whitespace removed. All patterns here are
made-up names (acme-corp, client-x, 가나상사 = "Gana Trading", 다라건설 = "Dara Construction")."""
import os
import re
import unicodedata
import unittest

import support as s
import jev_hook_guard as g

PATTERNS = "# test list\nacme[-_ ]?corp|가나상사\n\n   다라건설   \n"


class Patterns(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox(exclude=PATTERNS)

    def tearDown(self):
        self.sb.cleanup()

    def test_default_list_is_empty(self):
        ex = g.Exclude()
        self.assertEqual((ex.patterns, ex.empty_file), ([], False))
        self.assertFalse(any(ex.hit(t) for t in ("anything at all", "acme-corp", "회사", "/home/dev")))
        self.assertTrue(g.Exclude(None, default=("acme-corp",)).hit("ACME-CORP report"))
        self.assertTrue(g.Exclude(None, default="acme-corp").hit("acme-corp"))

    def test_file_patterns_comments_and_case(self):
        ex = g.Exclude(self.sb.exclude)
        self.assertEqual(ex.patterns, ["acme[-_ ]?corp|가나상사", "다라건설"])
        self.assertFalse(ex.empty_file)
        self.assertTrue(ex.hit("Acme Corp quarterly numbers"))
        self.assertTrue(ex.hit("다라건설 공정표"))
        self.assertFalse(ex.hit("acme rockets"))
        self.assertFalse(g.Exclude(self.sb.exclude, default=("rockets",)).hit("acme rockets"))   # file wins over default

    def test_hit_non_string_and_empty(self):
        ex = g.Exclude(self.sb.exclude)
        self.assertEqual([ex.hit(x) for x in (None, 123, "", ["acme-corp"])], [False] * 4)

    def test_invalid_pattern_raises(self):
        with open(self.sb.exclude, "w", encoding="utf-8") as f:
            f.write("acme(\n")
        with self.assertRaises(re.error):
            g.Exclude(self.sb.exclude)


class Variants(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox(exclude=PATTERNS)

    def tearDown(self):
        self.sb.cleanup()

    def test_nfd_spacing_fullwidth_variants_excluded(self):
        """NFD Korean (pasted from a macOS file name), spaces inside the word, fullwidth letters, a zero-width character,
        a Cyrillic lookalike and an en dash all hit. Through the example hook: skipped, nothing sent."""
        nfd = lambda t: unicodedata.normalize("NFD", t)
        variants = [nfd("가나상사 회의록 정리하고 다음 리비전 체크리스트 만들어줘"), "가나 상사 회신 검증 결과 정리해서 보고서로 만들어줘",
                    "ＡＣＭＥ－ＣＯＲＰ 폴더 정리 스크립트 고쳐줘 부탁해", "가​나상사 표를 다시 만들어 줘 부탁해",
                    "аcme-corp invoice draft for next week", "acme–corp invoice draft for next week",
                    nfd("다라건설 3층 평면 변경안 정리해줘 부탁해")]
        ex = g.Exclude(self.sb.exclude)
        self.assertEqual([v for v in variants if not ex.hit(v)], [])
        self.assertTrue(ex.hit(nfd("/home/dev/work/가나상사/x")))
        srv = s.MockServer()
        try:
            env = self.sb.env(endpoint=srv.url)
            ex_hook = self.sb.load_example(env)
            for i, v in enumerate(variants):
                self.assertEqual(ex_hook.run(s.payload(v, sid="s-v%d" % i)), "")
            ex_hook.run(s.payload(s.GOOD_PROMPT, sid="s-cwd", cwd=nfd("/home/dev/work/가나상사/x")))
            self.assertEqual(srv.reqs, [])
            got = [(d["status"], d["where"]) for d in self.sb.finals()]
            self.assertEqual(got, [("skip-excluded", "user")] * len(variants) + [("skip-excluded", "cwd")])
        finally:
            srv.close()

    def test_separator_spacing_variants_excluded(self):
        """A pattern written with a hyphen only matched the hyphen: "client x", "client_x", "clientx" and "Client X" went out.
        Writing the separator as [-_ ]? matches all five spellings, in every source the hook checks."""
        spellings = ("client-x", "client x", "client_x", "clientx", "Client X")
        strict = g.Exclude(None, default=("client-x",))
        self.assertEqual([v for v in spellings if not strict.hit("%s 배치 스크립트 손봐줘" % v)],
                         ["client x", "client_x", "clientx", "Client X"])
        loose = g.Exclude(None, default=("client[-_ ]?x",))
        self.assertEqual([v for v in spellings if not loose.hit("%s 배치 스크립트 손봐줘" % v)], [])
        with open(self.sb.exclude, "w", encoding="utf-8") as f:
            f.write("client[-_ ]?x\n")
        srv = s.MockServer()
        try:
            ex_hook = self.sb.load_example(self.sb.env(endpoint=srv.url))
            for i, v in enumerate(spellings):
                ex_hook.run(s.payload("%s 에서 돌릴 배치 스크립트 손봐줘 부탁해" % v, sid="s-p%d" % i))
                ex_hook.run(s.payload(s.GOOD_PROMPT, sid="s-c%d" % i, cwd="/home/dev/%s/app" % v))
                ex_hook.run(s.payload(s.GOOD_PROMPT, sid="s-t%d" % i, tp="/home/dev/.claude/projects/%s/t.jsonl" % v))
            self.assertEqual(srv.reqs, [])
            self.assertEqual({d["where"] for d in self.sb.finals()}, {"user", "cwd", "transcript-path"})
            self.assertEqual(len(self.sb.finals()), 15)
        finally:
            srv.close()


class EmptyFile(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox()

    def tearDown(self):
        self.sb.cleanup()

    def test_empty_exclude_file_logs_and_uses_default(self):
        """A file that exists but has no pattern lines sets empty_file and falls back to the default list (empty unless
        given). The example hook writes one error.log line per run for it; a missing file or a file with patterns does not."""
        for text in ("# only comments\n", "", "\n   \n# end\n"):
            with open(self.sb.exclude, "w", encoding="utf-8") as f:
                f.write(text)
            ex = g.Exclude(self.sb.exclude, default=("acme-corp",))
            self.assertEqual((ex.empty_file, ex.patterns), (True, ["acme-corp"]), repr(text))
            self.assertTrue(ex.hit("acme-corp memo"))
            self.assertEqual((g.Exclude(self.sb.exclude).patterns, g.Exclude(self.sb.exclude).empty_file), ([], True))
        srv = s.MockServer()
        try:
            env = self.sb.env(endpoint=srv.url)
            r = self.sb.run_example(s.payload(s.GOOD_PROMPT, sid="s-e1"), env)
            self.assertEqual((r.returncode, r.stdout), (0, ""))
            self.assertEqual(self.sb.errors().count("exclusion file has no pattern lines"), 1)
            os.remove(self.sb.exclude)
            missing = g.Exclude(self.sb.exclude)
            self.assertEqual((missing.empty_file, missing.patterns), (False, []))
            self.sb.run_example(s.payload(s.GOOD_PROMPT, sid="s-e2"), env)
            with open(self.sb.exclude, "w", encoding="utf-8") as f:
                f.write("# list\nacme-corp\n")
            self.sb.run_example(s.payload(s.GOOD_PROMPT, sid="s-e3"), env)
            self.assertEqual(self.sb.errors().count("exclusion file"), 1)
            self.assertEqual([d["status"] for d in self.sb.finals()], ["judged"] * 3)
        finally:
            srv.close()

    def test_example_file_parses(self):
        ex = g.Exclude(os.path.join(s.ROOT, "examples", "exclude.txt"))
        self.assertEqual(len(ex.patterns), 3)
        self.assertFalse(ex.empty_file)
        for t in ("acme corp", "Client_X notes", "project falcon kickoff", "payroll export", "lakeside-office lease"):
            self.assertTrue(ex.hit(t), t)
        self.assertFalse(ex.hit("acme rockets and a lakeside walk"))


if __name__ == "__main__":
    unittest.main()

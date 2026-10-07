"""SessionPins: once a session is pinned nothing more from it is sent. Pins depend on where the hit came from."""
import os
import stat
import time
import unittest

import support as s
import jev_hook_guard as g

TS = "2026-10-01T06:19:41Z"


class Pins(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox()
        self.dir = os.path.join(self.sb.state, "pinned")
        self.pins = g.SessionPins(self.dir)

    def tearDown(self):
        self.sb.cleanup()

    def marker(self, sid, content):
        g.ensure_private_dir(self.dir)
        with open(os.path.join(self.dir, sid), "w", encoding="utf-8") as f:
            f.write(content)

    def test_pin_writes_private_marker(self):
        self.assertFalse(self.pins.pinned("s-1"))
        self.assertTrue(self.pins.pin("s-1", "user"))
        self.assertTrue(self.pins.pinned("s-1"))
        p = os.path.join(self.dir, "s-1")
        with open(p, encoding="utf-8") as f:
            words = f.read().split()
        self.assertEqual(len(words), 2)
        self.assertRegex(words[0], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(words[1], "user")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        self.assertEqual(self.pins.note("s-1"), "user")
        self.assertTrue(self.pins.pin("s-1", "cwd"))                    # already pinned: the first source is kept
        self.assertEqual(self.pins.note("s-1"), "user")
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith(".tmp")], [])

    def test_pinned_by_arm_and_source(self):
        """A marker whose source is tool input, tool output, an attachment or the raw tail does not pin a caller that sends
        user text (default policy). A caller that sends tool text follows every marker (skip_only_sources=()). Markers
        from user, assistant, cwd, transcript path, old markers without a source and unreadable content pin everyone."""
        for sid, src in (("s-tool", "tool-input"), ("s-res", "tool-result"), ("s-att", "attachment"), ("s-raw", "raw-tail"),
                         ("s-user", "user"), ("s-asst", "assistant"), ("s-cwd", "cwd"), ("s-path", "transcript-path"),
                         ("s-other", "history")):
            self.marker(sid, "%s %s" % (TS, src))
        self.marker("s-old", TS)                     # timestamp only, written before sources were recorded
        self.marker("s-junk", "x")
        follow_all = g.SessionPins(self.dir, skip_only_sources=())
        for sid in ("s-tool", "s-res", "s-att", "s-raw"):
            self.assertEqual((self.pins.pinned(sid), follow_all.pinned(sid)), (False, True), sid)
        for sid in ("s-user", "s-asst", "s-cwd", "s-path", "s-other", "s-old", "s-junk"):
            self.assertEqual((self.pins.pinned(sid), follow_all.pinned(sid)), (True, True), sid)
        self.assertEqual([self.pins.pinned(x) for x in ("s-none", "", None)], [False, False, False])
        self.assertEqual([self.pins.note(x) for x in ("s-tool", "s-user", "s-old", "s-junk", "s-none")],
                         ["tool-input", "user", "", "", None])

    def test_skip_only_source_does_not_pin(self):
        for src in ("tool-input", "tool-result", "attachment", "raw-tail"):
            self.assertFalse(self.pins.pin("s-skip", src), src)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "s-skip")))
        self.assertFalse(self.pins.pinned("s-skip"))

    def test_pin_replaces_skip_only_marker(self):
        """A marker left for a skip-only source by another writer does not block a later real pin."""
        self.marker("s-up", "%s tool-result" % TS)
        self.assertFalse(self.pins.pinned("s-up"))
        self.assertTrue(self.pins.pin("s-up", "assistant"))
        self.assertEqual(self.pins.note("s-up"), "assistant")
        self.assertTrue(self.pins.pinned("s-up"))

    def test_unknown_source_pins(self):
        self.assertTrue(self.pins.pin("s-u", "some new source"))
        self.assertEqual(self.pins.note("s-u"), "some-new-source")
        self.assertTrue(self.pins.pinned("s-u"))
        self.assertTrue(self.pins.pin("s-v", ""))
        self.assertEqual(self.pins.note("s-v"), "unknown")

    def test_empty_session_id(self):
        self.assertFalse(self.pins.pin("", "user"))
        self.assertFalse(self.pins.pin(None, "user"))
        self.assertFalse(self.pins.pinned(""))
        self.assertFalse(os.path.exists(self.dir))

    def test_session_id_cannot_leave_the_directory(self):
        for sid in ("../escape", "..", ".", "a/b", "x\\y"):
            self.assertTrue(self.pins.pin(sid, "user"), sid)
            self.assertTrue(self.pins.pinned(sid), sid)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.dir))), ["pinned"])
        self.assertEqual(len(os.listdir(self.dir)), 5)

    def test_overlapping_sources_rejected(self):
        with self.assertRaises(ValueError):
            g.SessionPins(self.dir, pin_sources=("user", "raw-tail"))

    def test_markers_are_never_cleaned(self):
        self.pins.pin("s-old", "user")
        p = os.path.join(self.dir, "s-old")
        year_ago = time.time() - 366 * 86400
        os.utime(p, (year_ago, year_ago))
        self.assertTrue(g.SessionPins(self.dir).pinned("s-old"))
        self.assertTrue(os.path.exists(p))

    def test_writable(self):
        self.assertTrue(self.pins.writable())
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        blocked = os.path.join(self.sb.root, "ro")
        os.mkdir(blocked, 0o500)
        try:
            self.assertFalse(g.SessionPins(os.path.join(blocked, "pinned")).writable())
        finally:
            os.chmod(blocked, 0o700)


class PinsThroughHook(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox(exclude="acme[-_ ]?corp\n")

    def tearDown(self):
        self.sb.cleanup()

    def test_session_pin_blocks_later_arms(self):
        """An exclusion hit pins the session: later prompts without the word are skipped, and another hook reading the
        same pin directory (one that sends tool text) sees the pin too."""
        srv = s.MockServer()
        try:
            env = self.sb.env(endpoint=srv.url)
            r = self.sb.run_example(s.payload("acme-corp 견적서 표 정리하는 스크립트 만들어줘", sid="s-pin"), env)
            self.assertEqual((r.returncode, r.stdout), (0, ""))
            self.assertTrue(os.path.exists(os.path.join(self.sb.state, "pinned", "s-pin")))
            for p in ("키워드 없는 다음 요청을 충분히 길게 씁니다", "another request with nothing in it"):
                self.sb.run_example(s.payload(p, sid="s-pin"), env)
            self.sb.run_example(s.payload(s.GOOD_PROMPT, sid="s-other"), env)
            self.assertEqual([(d["session"], d["status"]) for d in self.sb.finals()],
                             [("s-pin", "skip-excluded"), ("s-pin", "skip-pinned"), ("s-pin", "skip-pinned"), ("s-other", "judged")])
            self.assertEqual(len(srv.reqs), 1)
            self.assertTrue(g.SessionPins(os.path.join(self.sb.state, "pinned"), skip_only_sources=()).pinned("s-pin"))
        finally:
            srv.close()

    def test_unwritable_pin_dir_blocks_send(self):
        srv = s.MockServer()
        try:
            g.ensure_private_dir(self.sb.state)
            os.mkdir(os.path.join(self.sb.state, "pinned"), 0o500)
            r = self.sb.run_example(s.payload(s.GOOD_PROMPT, sid="s-ro"), self.sb.env(endpoint=srv.url))
            os.chmod(os.path.join(self.sb.state, "pinned"), 0o700)
            self.assertEqual((r.returncode, r.stdout), (0, ""))
            self.assertEqual(self.sb.finals()[-1]["status"], "skip-state-unwritable")
            self.assertEqual(srv.reqs, [])
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()

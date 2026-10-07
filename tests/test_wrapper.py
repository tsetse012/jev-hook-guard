"""hooks/wrapper.sh always exits 0 and logs a non-zero Python exit; state files are private; append_jsonl rotates."""
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest

import support as s
import jev_hook_guard as g

DEFAULT_PY = "/usr/bin/python3"


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


class Wrapper(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox()

    def tearDown(self):
        self.sb.cleanup()

    def bash(self, script, stdin, env):
        return subprocess.run(["bash", script], input=stdin, capture_output=True, text=True, env=env, timeout=30)

    def test_wrapper_missing_py_exits_0_and_logs(self):
        """The .py file next to the wrapper is gone: Python exits 2 (127 if the interpreter itself is missing), which
        Claude Code would read as "block". The wrapper exits 0 and leaves one line in error.log."""
        alone = os.path.join(self.sb.root, "alone")
        os.mkdir(alone)
        shutil.copy(s.WRAPPER, os.path.join(alone, "wrapper.sh"))
        want = 2 if os.path.exists(DEFAULT_PY) else 127
        r = self.bash(os.path.join(alone, "wrapper.sh"), s.payload(), self.sb.env())
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertIn("wrapper python rc=%d" % want, self.sb.errors())
        r = self.bash(s.WRAPPER, s.payload(), self.sb.env(JHG_HOOK_PY=os.path.join(alone, "missing.py")))
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.sb.errors().count("wrapper python rc=%d" % want), 2)
        self.assertEqual(mode(os.path.join(self.sb.state, "error.log")), 0o600)
        self.assertEqual(mode(self.sb.state), 0o700)

    def test_wrapper_any_nonzero_exit_becomes_0(self):
        bad = os.path.join(self.sb.root, "bad.py")
        with open(bad, "w") as f:
            f.write("import sys\nsys.stdout.write('partial output\\n')\nsys.exit(3)\n")
        r = self.bash(s.WRAPPER, "{}", self.sb.env(JHG_HOOK_PY=bad, JHG_PYTHON=sys.executable))
        self.assertEqual((r.returncode, r.stdout), (0, "partial output\n"))
        self.assertIn("wrapper python rc=3", self.sb.errors())

    def test_wrapper_normal_run_passes_output(self):
        srv = s.MockServer(p=0.91)
        try:
            env = self.sb.env(endpoint=srv.url, JHG_SHADOW="0", JHG_PYTHON=sys.executable)
            wrapper = self.sb.install_copy()
            r = self.bash(wrapper, s.payload("drop the production table and redeploy"), env)
            q = self.bash(wrapper, s.payload("explain the retry loop", sid="s-2"), dict(env, JHG_SHADOW="1"))
        finally:
            srv.close()
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertTrue(r.stdout.startswith("[jev-hook-guard example]"), r.stdout)
        self.assertEqual((q.returncode, q.stdout, q.stderr), (0, "", ""))
        self.assertEqual(self.sb.errors(), "")
        self.assertEqual(len(srv.reqs), 2)

    def test_wrapper_with_default_interpreter(self):
        """The registered command as shipped (default /usr/bin/python3, isolated mode) runs the example to the end."""
        srv = s.MockServer()
        try:
            r = self.bash(self.sb.install_copy(), s.payload(), self.sb.env(endpoint=srv.url))
        finally:
            srv.close()
        self.assertEqual(r.returncode, 0)
        if os.path.exists(DEFAULT_PY):
            self.assertEqual([d["status"] for d in self.sb.decisions()], ["pending", "judged"])
            self.assertEqual(self.sb.errors(), "")
        else:
            self.assertIn("wrapper python rc=127", self.sb.errors())

    def test_files_are_private_without_wrapper_umask(self):
        """Even under umask 022 and without the wrapper, every directory the hook makes is 0700 and every file 0600."""
        srv = s.MockServer()
        old = os.umask(0o022)
        try:
            r = self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url))
            g.SessionPins(os.path.join(self.sb.state, "pinned")).pin("s-x", "user")
        finally:
            os.umask(old)
            srv.close()
        self.assertEqual(r.returncode, 0)
        for d in (self.sb.state, os.path.join(self.sb.state, "pinned")):
            self.assertEqual(mode(d), 0o700, d)
        for f in ("decisions.jsonl", "decisions.jsonl.lock", os.path.join("pinned", "s-x")):
            self.assertEqual(mode(os.path.join(self.sb.state, f)), 0o600, f)

    def test_settings_snippet_registers_the_wrapper(self):
        with open(os.path.join(s.ROOT, "hooks", "settings.snippet.json"), encoding="utf-8") as f:
            cfg = json.load(f)
        h = cfg["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        self.assertEqual(h["type"], "command")
        self.assertTrue(h["command"].endswith("/hooks/wrapper.sh"))
        ex = self.sb.load_example(self.sb.env())
        self.assertGreater(h["timeout"], ex.TIMEOUT_S)


class PrivateFiles(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox()

    def tearDown(self):
        self.sb.cleanup()

    def test_ensure_private_dir_one_level_at_a_time(self):
        shared = os.path.join(self.sb.root, "shared")
        os.mkdir(shared)
        os.chmod(shared, 0o755)
        old = os.umask(0o022)
        try:
            leaf = g.ensure_private_dir(os.path.join(shared, "a", "b", "c"))
        finally:
            os.umask(old)
        self.assertEqual(leaf, os.path.join(shared, "a", "b", "c"))
        for d in ("a", os.path.join("a", "b"), os.path.join("a", "b", "c")):
            self.assertEqual(mode(os.path.join(shared, d)), 0o700, d)
        self.assertEqual(mode(shared), 0o755)                       # an existing parent is left alone
        os.chmod(leaf, 0o755)
        g.ensure_private_dir(leaf)
        self.assertEqual(mode(leaf), 0o700)                         # the target itself is tightened

    def test_append_jsonl_rotates_and_stays_private(self):
        path = os.path.join(self.sb.root, "logs", "d.jsonl")
        for i in range(40):
            g.append_jsonl(path, {"i": i, "pad": "x" * 100}, max_bytes=1000, keep=3)
        names = sorted(n for n in os.listdir(os.path.dirname(path)) if n.startswith("d.jsonl"))
        self.assertEqual(names, ["d.jsonl", "d.jsonl.1", "d.jsonl.2", "d.jsonl.3", "d.jsonl.lock"])
        seen = []
        for n in ("d.jsonl.3", "d.jsonl.2", "d.jsonl.1", "d.jsonl"):
            p = os.path.join(os.path.dirname(path), n)
            self.assertEqual(mode(p), 0o600, n)
            with open(p, encoding="utf-8") as f:
                seen += [json.loads(ln)["i"] for ln in f]
        self.assertEqual(seen, list(range(seen[0], 40)))           # contiguous, newest last, oldest dropped
        self.assertGreater(seen[0], 0)
        self.assertEqual(mode(os.path.dirname(path)), 0o700)

    def test_append_jsonl_leaves_existing_directory_alone(self):
        shared = os.path.join(self.sb.root, "shared")
        os.mkdir(shared)
        os.chmod(shared, 0o755)
        g.append_jsonl(os.path.join(shared, "x.jsonl"), {"a": 1})
        self.assertEqual(mode(shared), 0o755)
        self.assertEqual(mode(os.path.join(shared, "x.jsonl")), 0o600)

    def test_append_jsonl_tightens_existing_file_and_keeps_unicode(self):
        path = os.path.join(self.sb.root, "loose.jsonl")
        with open(path, "w") as f:
            f.write("")
        os.chmod(path, 0o644)
        g.append_jsonl(path, {"text": "가림 처리 <redacted>"})
        self.assertEqual(mode(path), 0o600)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"text": "가림 처리 <redacted>"}\n')

    def test_append_jsonl_concurrent_writers_do_not_interleave(self):
        path = os.path.join(self.sb.root, "c.jsonl")
        code = ("import sys; sys.path.insert(0, %r); import jev_hook_guard as g\n"
                "for i in range(60): g.append_jsonl(%r, {'w': sys.argv[1], 'i': i, 'pad': 'y' * 3000}, max_bytes=10**9)\n"
                % (s.ROOT, path))
        procs = [subprocess.Popen([sys.executable, "-B", "-c", code, str(w)]) for w in range(4)]
        self.assertEqual([p.wait(60) for p in procs], [0, 0, 0, 0])
        with open(path, encoding="utf-8") as f:
            rows = [json.loads(ln) for ln in f]
        self.assertEqual(len(rows), 240)
        self.assertEqual(sorted((r["w"], r["i"]) for r in rows), sorted((str(w), i) for w in range(4) for i in range(60)))


if __name__ == "__main__":
    unittest.main()

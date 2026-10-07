"""endpoint_ok(), post_json(), classify_error(), and the example hook end to end against a loopback mock server."""
import json
import os
import signal
import socket
import threading
import time
import unittest
import urllib.error
from unittest import mock

import support as s
import jev_hook_guard as g


class Endpoint(unittest.TestCase):
    def test_endpoint_ok(self):
        ok = ["https://api.typesafe.ai/v1/systemone", "http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]:9/x",
              "http://127.0.0.1"]
        bad = ["http://api.example.com/x", "http://127.0.0.1.evil.example/x", "http://localhost.evil.example/",
               "ftp://127.0.0.1/x", "HTTP://api.example.com", "", None, "file:///etc/passwd"]
        self.assertEqual([u for u in ok if not g.endpoint_ok(u)], [])
        self.assertEqual([u for u in bad if g.endpoint_ok(u)], [])


class Post(unittest.TestCase):
    def test_post_json_sends_bearer_and_json(self):
        srv = s.MockServer(p=0.42)
        try:
            resp, ms = g.post_json(srv.url, {"model": "m", "state": {"prompt": "안녕"}, "questions": {"q": {"type": "noul"}}},
                                   s.KEY, 2.0)
        finally:
            srv.close()
        self.assertEqual(resp["answers"]["q"]["noul"], 0.42)
        self.assertIsInstance(ms, int)
        req = srv.reqs[0]
        self.assertEqual((req["method"], req["auth"]), ("POST", "Bearer " + s.KEY))
        self.assertEqual(req["headers"].get("Content-Type"), "application/json")
        self.assertEqual(json.loads(req["body"])["state"]["prompt"], "안녕")

    def test_post_json_refuses_bad_endpoint_and_key(self):
        srv = s.MockServer()
        try:
            for url, key in (("http://api.example.com/x", s.KEY), (srv.url, "has space"), (srv.url, ""), (srv.url, None),
                             (srv.url, "line\nbreak")):
                with self.assertRaises(ValueError) as cm:
                    g.post_json(url, {}, key, 1.0)
                if key:
                    self.assertNotIn(key, str(cm.exception))
                self.assertEqual(g.classify_error(cm.exception)[0], "http-error")
        finally:
            srv.close()
        self.assertEqual(srv.reqs, [])

    def test_redirects_refused_no_auth_forwarded(self):
        """301, 302, 303, 307 and 308 are not followed: the second origin receives nothing, not even the header."""
        b = s.MockServer()
        try:
            for code in (301, 302, 303, 307, 308):
                a = s.MockServer(mode="redirect", code=code, location=b.url)
                try:
                    with self.assertRaises(urllib.error.HTTPError) as cm:
                        g.post_json(a.url, {"x": 1}, s.KEY, 2.0)
                    self.assertEqual(g.classify_error(cm.exception), ("redirect-refused", {"http": code}))
                    self.assertEqual(len(a.reqs), 1)
                    self.assertEqual(a.reqs[0]["auth"], "Bearer " + s.KEY)
                finally:
                    a.close()
            self.assertEqual(b.reqs, [])
        finally:
            b.close()

    def test_classify_http_statuses(self):
        want = {402: "billing", 401: "auth-error", 403: "auth-error", 429: "rate-limited", 500: "http-error", 404: "http-error"}
        for code, status in want.items():
            srv = s.MockServer(mode="status", code=code)
            try:
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    g.post_json(srv.url, {}, s.KEY, 2.0)
            finally:
                srv.close()
            st, extra = g.classify_error(cm.exception)
            self.assertEqual((st, extra), (status, {"http": code}))
            self.assertNotIn(s.KEY, json.dumps(extra))

    def test_classify_other_errors(self):
        self.assertEqual(g.classify_error(g.Deadline("x")), ("timeout", {}))
        self.assertEqual(g.classify_error(socket.timeout("t")), ("timeout", {}))
        self.assertEqual(g.classify_error(urllib.error.URLError(socket.timeout("t"))), ("timeout", {}))
        self.assertEqual(g.classify_error(urllib.error.URLError(ConnectionRefusedError("Bearer " + s.KEY))),
                         ("network", {"err": "URLError"}))
        self.assertEqual(g.classify_error(json.JSONDecodeError("bad", "doc", 0)), ("http-error", {"err": "JSONDecodeError"}))
        self.assertEqual(g.classify_error(ConnectionResetError("reset")), ("network", {"err": "ConnectionResetError"}))
        self.assertEqual(g.classify_error(RuntimeError("Authorization: Bearer " + s.KEY)), ("network", {"err": "RuntimeError"}))

    def test_closed_port_is_network(self):
        with self.assertRaises(Exception) as cm:
            g.post_json(s.DEAD, {}, s.KEY, 2.0)
        self.assertEqual(g.classify_error(cm.exception), ("network", {"err": "URLError"}))

    def test_non_object_response_is_http_error(self):
        with mock.patch.object(g, "_open", lambda req, timeout: s.FakeResp(b"[1, 2]")):
            with self.assertRaises(ValueError) as cm:
                g.post_json("https://judge.example/v1", {}, s.KEY, 1.0)
        self.assertEqual(g.classify_error(cm.exception), ("http-error", {"err": "ValueError"}))

    def test_wall_clock_deadline(self):
        """A server that keeps the socket busy (one byte at a time) never trips the socket timeout; SIGALRM ends the call
        at the deadline. A replaced opener that blocks is cut the same way."""
        srv = s.MockServer(mode="drip", delay=0.2)
        try:
            t = time.time()
            with self.assertRaises(Exception) as cm:
                g.post_json(srv.url, {}, s.KEY, 0.6)
            self.assertLess(time.time() - t, 0.6 + 0.8)
            self.assertEqual(g.classify_error(cm.exception), ("timeout", {}))
        finally:
            srv.close()

        def slow(req, timeout):
            time.sleep(10)
            return s.FakeResp(b"{}")
        t = time.time()
        with mock.patch.object(g, "_open", slow):
            with self.assertRaises(g.Deadline):
                g.post_json("https://judge.example/v1", {}, s.KEY, 0.5)
        self.assertLess(time.time() - t, 0.5 + 0.8)

    def test_deadline_restores_previous_alarm(self):
        """A caller's own SIGALRM handler and running timer survive a post_json() call."""
        fired = []
        handler = lambda *a: fired.append(1)
        old = signal.signal(signal.SIGALRM, handler)
        try:
            signal.setitimer(signal.ITIMER_REAL, 1.0)
            srv = s.MockServer()
            try:
                g.post_json(srv.url, {}, s.KEY, 0.5)
            finally:
                srv.close()
            self.assertIs(signal.getsignal(signal.SIGALRM), handler)
            remaining = signal.getitimer(signal.ITIMER_REAL)[0]
            self.assertGreater(remaining, 0.0)
            self.assertLess(remaining, 1.0)
            time.sleep(remaining + 0.2)
            self.assertEqual(fired, [1])
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old)

    def test_post_from_worker_thread_uses_socket_timeout(self):
        """SIGALRM only works in the main thread. From a worker thread a call to a fast server succeeds (no signal is
        touched), and a server that stops sending is cut by the socket timeout: a socket timeout, not Deadline, which
        classify_error() reports as timeout."""
        fast = s.MockServer(p=0.3)
        stall = s.MockServer(mode="drip", delay=3.0)     # headers and one byte, then 3 s per byte
        out = {}

        def work():
            out["ok"] = g.post_json(fast.url, {}, s.KEY, 2.0)
            t = time.time()
            try:
                g.post_json(stall.url, {}, s.KEY, 0.3)
            except Exception as e:
                out["err"], out["secs"] = e, time.time() - t
        th = threading.Thread(target=work, daemon=True)
        th.start()
        th.join(10)
        fast.close()
        stall.close()
        self.assertFalse(th.is_alive())
        self.assertEqual(out["ok"][0]["model"], "jev-1.13.0")
        self.assertIsInstance(out["err"], socket.timeout)
        self.assertNotIsInstance(out["err"], g.Deadline)
        self.assertEqual(g.classify_error(out["err"]), ("timeout", {}))
        self.assertLess(out["secs"], 2.0)


class ExampleHook(unittest.TestCase):
    """The example hook as Claude Code runs it: separate process, isolated mode, payload on stdin."""

    def setUp(self):
        self.sb = s.Sandbox()

    def tearDown(self):
        self.sb.cleanup()

    def test_empty_payload_exits_0(self):
        srv = s.MockServer()
        try:
            env = self.sb.env(endpoint=srv.url)
            for stdin in ("", "{}", "not json", "[1, 2]"):
                r = self.sb.run_example(stdin, env)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""), repr(stdin))
        finally:
            srv.close()
        self.assertEqual(srv.reqs, [])
        self.assertEqual([d["status"] for d in self.sb.finals()], ["bad-payload", "skip-empty", "bad-payload", "bad-payload"])

    def test_state_dir_made_by_user_is_tightened_to_0700(self):
        """`mkdir -p ~/.jev-hook-guard` under umask 022 leaves 0755; one run must make it 0700 (README: 0700 directory)."""
        import stat
        os.makedirs(self.sb.state, 0o755)                     # what `mkdir -p` under umask 022 leaves behind
        os.chmod(self.sb.state, 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(self.sb.state).st_mode), 0o755)
        srv = s.MockServer()
        try:
            r = self.sb.run_example("{}", self.sb.env(endpoint=srv.url))
            self.assertEqual(r.returncode, 0)
        finally:
            srv.close()
        self.assertEqual(stat.S_IMODE(os.stat(self.sb.state).st_mode), 0o700)

    def test_missing_key_exits_0(self):
        srv = s.MockServer()
        try:
            r = self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url, key=None))
            r2 = self.sb.run_example(s.payload(sid="s-2"), self.sb.env(endpoint=srv.url, key="two words"))
        finally:
            srv.close()
        self.assertEqual((r.returncode, r.stdout, r2.returncode), (0, "", 0))
        self.assertEqual([d["status"] for d in self.sb.finals()], ["no-key", "bad-key"])
        self.assertEqual(srv.reqs, [])
        self.assertNotIn("two words", json.dumps(self.sb.decisions()) + self.sb.errors())

    def test_billing_402_exits_0_and_is_loud(self):
        srv = s.MockServer(mode="status", code=402)
        try:
            r = self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url))
        finally:
            srv.close()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(len(srv.reqs), 1)
        last = self.sb.finals()[-1]
        self.assertEqual((last["status"], last["http"]), ("billing", 402))
        self.assertIn("402 billing", self.sb.errors())

    def test_pending_line_before_send(self):
        srv = s.MockServer()
        try:
            self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url))
        finally:
            srv.close()
        d = self.sb.decisions()
        self.assertEqual([x["status"] for x in d], ["pending", "judged"])
        self.assertEqual(d[0]["rid"], d[1]["rid"])
        self.assertEqual(d[0]["prompt_head"], s.GOOD_PROMPT[:120])

    def test_unwritable_log_blocks_send(self):
        srv = s.MockServer()
        g.ensure_private_dir(os.path.join(self.sb.state, "pinned"))
        os.chmod(self.sb.state, 0o500)
        try:
            r = self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url))
        finally:
            os.chmod(self.sb.state, 0o700)
            srv.close()
        self.assertEqual(r.returncode, 0)
        self.assertEqual(srv.reqs, [])

    def test_shadow_prints_nothing_live_prints_line(self):
        srv = s.MockServer(p=0.93)
        try:
            shadow = self.sb.run_example(s.payload("delete the old release branch and force-push main", sid="s-a"),
                                         self.sb.env(endpoint=srv.url))
            live = self.sb.run_example(s.payload("delete the old release branch and force-push main", sid="s-b"),
                                       self.sb.env(endpoint=srv.url, JHG_SHADOW="0"))
        finally:
            srv.close()
        self.assertEqual((shadow.returncode, shadow.stdout), (0, ""))
        self.assertEqual(live.returncode, 0)
        self.assertTrue(live.stdout.startswith("[jev-hook-guard example] This request looks hard to undo (p=0.93)"), live.stdout)
        self.assertEqual(live.stdout.count("\n"), 1)
        low = s.MockServer(p=0.2)
        try:
            quiet = self.sb.run_example(s.payload("explain this function", sid="s-c"), self.sb.env(endpoint=low.url, JHG_SHADOW="0"))
        finally:
            low.close()
        self.assertEqual(quiet.stdout, "")
        self.assertEqual([d.get("p") for d in self.sb.finals()], [0.93, 0.93, 0.2])

    def test_network_error_and_bad_answer_exit_0(self):
        r = self.sb.run_example(s.payload(), self.sb.env(endpoint=s.DEAD))
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(self.sb.finals()[-1]["status"], "network")
        ex = self.sb.load_example(self.sb.env(endpoint="https://judge.example/v1"))
        with mock.patch.object(ex.g, "_open", lambda req, timeout: s.FakeResp(b'{"answers": {"other": {"noul": 0.9}}}')):
            self.assertEqual(ex.run(s.payload(sid="s-ba")), "")
        self.assertEqual(self.sb.finals()[-1]["status"], "bad-answer")

    def test_kill_switch_stops_before_anything(self):
        g.ensure_private_dir(self.sb.state)
        open(os.path.join(self.sb.state, "OFF"), "w").close()
        srv = s.MockServer()
        try:
            r = self.sb.run_example(s.payload(), self.sb.env(endpoint=srv.url))
        finally:
            srv.close()
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertEqual(srv.reqs, [])
        self.assertEqual(self.sb.decisions(), [])
        self.assertFalse(os.path.exists(os.path.join(self.sb.state, "pinned")))

    def test_self_names_from_environment(self):
        """JHG_SELF_NAMES reaches mask(): the names are <name> in the request body and in the logged head. The same
        prompt without the variable keeps them."""
        prompt = "jdoe 계정의 배포 로그를 Jane Doe 에게 보낼 요약으로 정리해줘"
        masked = "<name> 계정의 배포 로그를 <name> 에게 보낼 요약으로 정리해줘"
        srv = s.MockServer()
        try:
            for sid, extra in (("s-n1", {"JHG_SELF_NAMES": "jdoe, Jane Doe"}), ("s-n2", {})):
                r = self.sb.run_example(s.payload(prompt, sid=sid), self.sb.env(endpoint=srv.url, **extra))
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        finally:
            srv.close()
        sent = [json.loads(b)["state"]["prompt"] for b in srv.bodies()]
        heads = [d["prompt_head"] for d in self.sb.decisions() if d["status"] == "pending"]
        self.assertEqual(sent, [masked, prompt])
        self.assertEqual(heads, [masked, prompt])

    def test_plain_http_endpoint_refused(self):
        r = self.sb.run_example(s.payload(), self.sb.env(endpoint="http://judge.example/v1"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.sb.finals()[-1]["status"], "endpoint-refused")


if __name__ == "__main__":
    unittest.main()

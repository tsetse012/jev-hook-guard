"""refuse() (send nothing when the input looks like a secret dump) and leftover() (the last check before the send)."""
import json
import unittest
from unittest import mock

import support as s
import jev_hook_guard as g


class Refuse(unittest.TestCase):
    def test_refuse_categories(self):
        cases = {"url-credential": "접속 문자열 mysql://root:hunter@db.local:3306/app 로 붙여줘",
                 "secret-label": "please rotate the api key on staging tonight",
                 "env-file": "이 설정 확인해줘\nAPP_HOST=example.org\nAPP_PORT=8080\n",
                 "address": "배송지 경기도 성남시 분당로 55 로 바꿔서 메일 써줘"}
        for why, text in cases.items():
            self.assertEqual(g.refuse(text), why, text)
        for text in ("explain the retry loop in the uploader", "APP_HOST=example.org only one line", "", None, 42):
            self.assertIsNone(g.refuse(text), text)

    def test_refuse_korean_and_spaced_labels(self):
        for text in ("서버 비번은 내가 알려줄게", "관리자 비 번은 나중에", "공유기 비밀 번호 바꿔줘", "공유기 관리 페이지 P/W 확인",
                     "공공데이터 인증키 발급 절차", "패스워드 정책 정리", "the wifi pass is on the fridge"):
            self.assertEqual(g.refuse(text), "secret-label", text)
        for text in ("창구에서 준비 번호표를 뽑았습니다.", "예비 번호표 두 장", "tcp/ws 연결과 비율 메모"):
            self.assertIsNone(g.refuse(text), text)

    def test_refuse_reads_first_4000_normalized_chars(self):
        self.assertEqual(g.refuse("ｐａｓｓｗｏｒｄ 확인"), "secret-label")            # fullwidth label
        self.assertEqual(g.refuse("pass​word reset"), "secret-label")                # zero-width inside the word
        self.assertEqual(g.refuse("x" * 3990 + " token"), "secret-label")
        self.assertIsNone(g.refuse("x" * 4000 + " token"))                                 # beyond the window

    def test_passphrase_refused_whole(self):
        """A passphrase is plain words: masking the first one sent the rest ("passphrase: <redacted> horse battery
        staple"). An input that names a passphrase is refused whole, and nothing reaches the server."""
        texts = ["passphrase: correct horse battery staple", "the wifi PASSPHRASE is correct horse battery staple",
                 "ssh key passphrase = correct horse battery staple 로 설정해줘"]
        for t in texts:
            self.assertEqual(g.refuse(t), "secret-label", t)
        sb = s.Sandbox()
        srv = s.MockServer()
        try:
            ex = sb.load_example(sb.env(endpoint=srv.url))
            for i, t in enumerate(texts):
                self.assertEqual(ex.run(s.payload(t, sid="s-pp-%d" % i)), "")
            self.assertEqual([(d["status"], d["why"]) for d in sb.finals()], [("skip-refused", "secret-label")] * 3)
            self.assertEqual(srv.reqs, [])
            self.assertNotIn("horse", json.dumps(sb.decisions()))
        finally:
            srv.close()
            sb.cleanup()

    def test_secretish_skips_and_sends_nothing(self):
        """Through the example hook: four kinds of secret dumps, zero requests, and the value is not in any log."""
        sb = s.Sandbox()
        srv = s.MockServer()
        try:
            cases = {"secret-label": "우리 서버 password 바꾸는 절차 정리해줘 부탁해",
                     "env-file": "이 설정 확인해줘\nAPP_HOST=example.org\nAPP_PORT=8080\n",
                     "url-credential": "접속 문자열 mysql://root:hunter@db.local:3306/app 로 붙여줘",
                     "address": "배송지 경기도 성남시 분당로 55 로 바꿔서 메일 써줘"}
            env = sb.env(endpoint=srv.url)
            for why, p in cases.items():
                r = sb.run_example(s.payload(p, sid="s-sec-%s" % why), env)
                self.assertEqual((r.returncode, r.stdout), (0, ""))
                last = sb.finals()[-1]
                self.assertEqual((last["status"], last["why"]), ("skip-refused", why))
                self.assertNotIn("prompt_head", last)
            self.assertEqual(srv.reqs, [])
            logs = json.dumps(sb.decisions(), ensure_ascii=False) + sb.errors()
            for frag in ("hunter", "APP_PORT", "분당로"):
                self.assertNotIn(frag, logs)
        finally:
            srv.close()
            sb.cleanup()


class Leftover(unittest.TestCase):
    def test_leftover_rule_names(self):
        values = ["Zq9xWm4Tp2Lk77abcd"]
        self.assertEqual(g.leftover("값 Zq9xWm4Tp2Lk77abcd", values), "credential-value")
        self.assertEqual(g.leftover("값 Zq9xWm4Tp2LkQQ", values), "credential-prefix")
        self.assertEqual(g.leftover("값 QQ4Tp2Lk77abcd", values), "credential-suffix")
        self.assertEqual(g.leftover("use sk-abcdefgh12345 now"), "shape-3")
        self.assertEqual(g.leftover("API_TOKEN=abcdef"), "shape-15")
        self.assertEqual(g.leftover("blob " + "a1" * 20), "long-token")
        self.assertIsNone(g.leftover("API_TOKEN=<redacted> and sk-<redacted>"))
        self.assertIsNone(g.leftover("nothing to see"))
        self.assertIsNone(g.leftover(None))

    def test_leftover_flags_numbers_left_in_the_text(self):
        """Phone, ID, card and account numbers still in the text to be sent stop the send, as keys do (a Korean letter
        against the number included). Numbers the account rule keeps (ports, prices, dates), a timestamp, placeholders and
        email shapes are not part of the check."""
        flagged = {"call 010-1234-5678": "shape-23", "번호 010-1234-5678이야": "shape-23", "+82 10 2345 6789": "shape-22",
                   "02-123-4567": "shape-24", "주민 900101-1234567로": "shape-25", "카드 4532 0151 1283 0366": "shape-26",
                   "계좌 110-123-456789로": "shape-27", "계좌 3333-01-1234567": "shape-27", "아멕스 378282246310005": "shape-32",
                   "(02) 1234-5678": "shape-33"}
        for text, rule in flagged.items():
            self.assertEqual(g.leftover(text), rule, text)
        for text in ("ports 3000 8080 5432 open", "가격은 15000 20000 25000원", "2026-10-01-12-30 시작",
                     "타임스탬프 1790662827840", "메일 a.b@example.co.kr", "call <phone> or <card>"):
            self.assertIsNone(g.leftover(text), text)

    def test_leftover_clean_after_mask(self):
        creds = [v for v in s.FAKE_CREDS.values() if len(v) >= 6]
        texts = [case[1] for case in s.AUDIT26 + s.BYPASS26] + s.NO_OVERMASK + [s.PROMPT_SECRET]
        flagged = [t for t in texts if g.leftover(g.mask(t, creds, 600), creds)]
        self.assertEqual(flagged, [])

    def test_leak_check_blocks_send(self):
        """With masking switched off (mask returns its input), the last check still stops the send."""
        raw = lambda text, env_values=(), limit=600, home=None, self_names=(): g.normalize(text)[:limit]
        prompt = "배포 키는 %s 이고 연락처 %s" % (s.SECRETS["anthropic"], s.SECRETS["phone1"])
        srv = s.MockServer()
        try:
            # env file shares the "sk-ant-api03" prefix: env values are checked first; without an env file the shape rule
            for creds, rule in ((None, "credential-prefix"), ({}, "shape-3")):
                sb = s.Sandbox(creds=creds)
                try:
                    ex = sb.load_example(sb.env(endpoint=srv.url))
                    with mock.patch.object(ex.g, "mask", raw):
                        self.assertEqual(ex.run(s.payload(prompt)), "")
                    last = sb.finals()[-1]
                    self.assertEqual((last["status"], last["rule"]), ("skip-leak", rule))
                    self.assertNotIn(s.SECRETS["anthropic"], json.dumps(sb.decisions()))
                finally:
                    sb.cleanup()
            self.assertEqual(srv.reqs, [])
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()

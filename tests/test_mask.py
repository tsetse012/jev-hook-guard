"""normalize(), load_env_values() and mask(): the 52 adversarial cases from two independent reviews, the over-masking
controls, env values, names, the home path and the cut."""
import json
import os
import re
import unicodedata
import unittest

import support as s
import jev_hook_guard as g


class Api(unittest.TestCase):
    def test_public_names(self):
        names = {"normalize", "load_env_values", "mask", "refuse", "leftover", "Exclude", "SessionPins", "endpoint_ok",
                 "post_json", "classify_error", "ensure_private_dir", "append_jsonl", "Deadline"}
        self.assertEqual(set(g.__all__), names)
        self.assertTrue(all(callable(getattr(g, n)) for n in names))
        for n in ("1. kill switch", "2. Exclude.hit()", "3. refuse()", "4. mask()", "6. leftover()", "7. append_jsonl()",
                  "8. post_json()", "9. classify_error()"):
            self.assertIn(n, g.__doc__)


class Normalize(unittest.TestCase):
    def test_fullwidth_zero_width_nfc_dashes_lookalikes(self):
        self.assertEqual(g.normalize("ｓｋ－ａｂｃ　１２"), "sk-abc 12")
        self.assertEqual(g.normalize("ab​c­ d﻿"), "abc d")
        nfd = unicodedata.normalize("NFD", "가나상사")
        self.assertNotEqual(nfd, "가나상사")
        self.assertEqual(g.normalize(nfd), "가나상사")
        self.assertEqual(g.normalize("900101–1234567 a—b c−d"), "900101-1234567 a-b c-d")
        self.assertEqual(g.normalize("ѕk-аpі ΑΒΕ"), "sk-api ABE")   # Cyrillic s a i, Greek A B E

    def test_meaning_preserved_and_non_string(self):
        self.assertEqual(g.normalize("①②③ ㎏ ㄱ"), "①②③ ㎏ ㄱ")       # no full NFKC: circled digits keep their meaning
        self.assertEqual(g.normalize(None), "")
        self.assertEqual(g.normalize(123), "")


class EnvValues(unittest.TestCase):
    def setUp(self):
        self.sb = s.Sandbox(creds={})

    def tearDown(self):
        self.sb.cleanup()

    def test_load_env_values_parsing(self):
        with open(self.sb.creds, "w", encoding="utf-8") as f:
            f.write('export A_KEY="quoted value # not a comment" # comment\n'
                    "B='single quoted'\n"
                    "C=plain-value-1 # trailing comment\n"
                    "D=short\n"
                    "# E=commented-out-value\n"
                    "not an assignment line\n"
                    "F=  spaced-around  \n"
                    "G=plain-value-1\n")
        self.assertEqual(g.load_env_values(self.sb.creds),
                         ["quoted value # not a comment", "plain-value-1", "single quoted", "spaced-around"])
        self.assertIn("short", g.load_env_values(self.sb.creds, min_len=3))
        self.assertEqual(g.load_env_values(os.path.join(self.sb.root, "missing.env")), [])
        self.assertEqual(g.load_env_values(""), [])

    def test_credentials_values_masked_on_wire(self):
        """Values from the env file never reach the server: whole value, split across a line break, only the first 12,
        only the last 12 characters, a key sharing a prefix. Also checked in the decision log."""
        sb = s.Sandbox()
        srv = s.MockServer()
        try:
            prompts = ["DB 연결 값으로 이걸 넣어줘 Kx82mQ9vLp44Rt 그리고 재시작해줘",
                       "설정에 붙일 값 Kx82mQ9v\nLp44Rt 줄이 나뉘어 들어갔어 확인해줘",
                       "앞부분만 기억나는데 Zq9xWm4Tp2Lk 로 시작하는 값으로 설정해줘",
                       "뒷부분만 보이는데 4Tp2Lk77abcd 로 끝나는 값으로 다시 넣어줘",
                       "키는 %s 으로 바꿔서 배포해줘" % s.FAKE_CREDS["ANTHROPIC_API_KEY"]]
            env = sb.env(endpoint=srv.url)
            for i, p in enumerate(prompts):
                r = sb.run_example(s.payload(p, sid="s-cr%d" % i), env)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
            self.assertEqual([d["status"] for d in sb.finals()], ["judged"] * 5)
            self.assertEqual(len(srv.reqs), 5)
            on_disk = json.dumps(sb.decisions(), ensure_ascii=False)
            for hay in ("\n".join(srv.bodies()), on_disk):
                for v in s.FAKE_CREDS.values():
                    if len(v) >= 6:
                        self.assertNotIn(v, hay)
                        self.assertNotIn(v[:12], hay)
                        self.assertNotIn(v[-12:], hay)
                for frag in ("Kx82mQ9v", "Lp44Rt", "FAKEfake", "77abcd"):
                    self.assertNotIn(frag, hay)
        finally:
            srv.close()
            sb.cleanup()


class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sb = s.Sandbox()
        cls.creds = g.load_env_values(cls.sb.creds)

    @classmethod
    def tearDownClass(cls):
        cls.sb.cleanup()

    def assert_env_values_absent(self, out):
        for v in self.creds:
            self.assertNotIn(v, out)
            if len(v) >= 12:
                self.assertNotIn(v[:12], out)
            if len(v) >= 16:
                self.assertNotIn(v[-12:], out)

    def assert_no_fragment(self, name, out, value, kind, needle=None):
        """No 7-digit (digits) / 6-character (alnum) run of `value` in `out` (reviewer's rule, see survived()), and the
        value is long enough for that rule to find one. With `needle`, none of its forms as typed, normalized or NFKC:
        mask() returns normalized text, so a fullwidth needle as typed could never be found in it."""
        core = unicodedata.normalize("NFKC", value)
        core = re.sub(r"\D", "", core) if kind == "digits" else re.sub(r"\s+", "", core)
        self.assertGreaterEqual(len(core), 7 if kind == "digits" else 6, name)
        self.assertFalse(s.survived(value, out, kind), (name, out))
        if needle is not None:
            for nd in {needle, g.normalize(needle), unicodedata.normalize("NFKC", needle)}:
                self.assertNotIn(nd, out, name)

    def test_audit_26_cases_masked_or_refused(self):
        """First review, 26 cases: each input is refused whole by refuse(), or mask() leaves no 7-digit / 6-character run
        of the value and no form of the fragment the review named."""
        refused, masked = [], []
        for label, prompt, needle, value, kind in s.AUDIT26:
            if g.refuse(prompt):
                refused.append(label)
                continue
            out = g.mask(prompt, self.creds, 600)
            self.assert_no_fragment(label, out, value, kind, needle)
            self.assert_env_values_absent(out)
            self.assertIsNone(g.leftover(out, self.creds), label)
            masked.append(label)
        self.assertEqual((len(s.AUDIT26), len(refused) + len(masked)), (26, 26))
        self.assertEqual((len(refused), len(masked)), (14, 12))

    def test_bypass_26_cases_masked_or_refused(self):
        """Second review, 26 cases: refused, or no 7-digit / 6-character run of the value in mask() (reviewer's rule)."""
        refused, masked = [], []
        for name, prompt, secret, kind in s.BYPASS26:
            if g.refuse(prompt):
                refused.append(name)
                continue
            out = g.mask(prompt, self.creds, 600)
            self.assert_no_fragment(name, out, secret, kind)
            self.assert_env_values_absent(out)
            self.assertIsNone(g.leftover(out, self.creds), name)
            masked.append(name)
        self.assertEqual((len(s.BYPASS26), len(refused) + len(masked)), (26, 26))
        self.assertEqual((len(refused), len(masked)), (7, 19))

    def test_shape_rules_alone_without_env_values(self):
        """With no env file the 52 cases still hold: none of them depends on env values (same checks as above)."""
        for label, prompt, needle, value, kind in s.AUDIT26:
            if not g.refuse(prompt):
                self.assert_no_fragment(label, g.mask(prompt, (), 600), value, kind, needle)
        for name, prompt, secret, kind in s.BYPASS26:
            if not g.refuse(prompt):
                self.assert_no_fragment(name, g.mask(prompt, (), 600), secret, kind)

    def test_no_overmasking_controls(self):
        """Ordinary text comes back as normalize() + space collapse, nothing else (19 controls)."""
        same = lambda t: re.sub(r"[ \t]{2,}", " ", g.normalize(t)).strip()
        self.assertEqual(len(s.NO_OVERMASK), 19)
        self.assertEqual([t for t in s.NO_OVERMASK if g.mask(t, self.creds, 4000) != same(t)], [])
        self.assertEqual([t for t in s.NO_OVERMASK if g.leftover(g.mask(t, self.creds, 4000), self.creds)], [])

    def test_prompt_secret_all_values_masked_with_english_placeholders(self):
        out = g.mask(s.PROMPT_SECRET, self.creds, 600)
        for name, v in s.SECRETS.items():
            self.assertNotIn(v, out, name)
        for frag in ("ABCDEFGHIJ123456", "1234-5678", "9876", "5555", "example.com", "1234567", "hunter2"):
            self.assertNotIn(frag, out)
        for ph in ("<redacted>", "<phone>", "<email>", "<id-number>", "<card>"):
            self.assertIn(ph, out)
        self.assertFalse(re.search(r"<[가-힣]+>", out), out)
        self.assertLessEqual(len(out), 600)

    def test_mask_all_52_on_wire(self):
        """The 52 cases through the example hook, in process, against a loopback server: nothing on the wire or in the
        decision log. Statuses are refused (skip-refused) or sent (judged); nothing needs the last check."""
        srv = s.MockServer()
        try:
            ex = self.sb.load_example(self.sb.env(endpoint=srv.url))
            cases = ([(lab, p, val, kind, nd) for lab, p, nd, val, kind in s.AUDIT26]
                     + [(name, p, val, kind, None) for name, p, val, kind in s.BYPASS26])
            statuses = {}
            for i, (name, prompt, value, kind, needle) in enumerate(cases):
                n0 = len(srv.reqs)
                self.assertEqual(ex.run(s.payload(prompt, sid="s-wire-%d" % i)), "")
                statuses.setdefault(self.sb.finals()[-1]["status"], []).append(name)
                for body in srv.bodies()[n0:]:
                    self.assert_no_fragment(name, json.loads(body)["state"]["prompt"], value, kind, needle)
            heads = [d["prompt_head"] for d in self.sb.decisions() if d.get("prompt_head")]
            self.assertTrue(heads)
            for name, _p, value, kind, needle in cases:
                for h in heads:
                    self.assertFalse(s.survived(value, h, kind), (name, h))
                    if needle is not None:
                        self.assertNotIn(g.normalize(needle), h, name)
            self.assertEqual(sorted(statuses), ["judged", "skip-refused"])
            self.assertEqual((len(statuses["skip-refused"]), len(statuses["judged"]), len(srv.reqs)), (21, 31, 31))
        finally:
            srv.close()


class Rules(unittest.TestCase):
    def test_env_value_whole_token_and_split(self):
        """Only the first 12 characters of a value matched: the whole token goes, so the middle does not remain (masking
        just the first and last 12 characters left 7 to 8 characters of real values behind)."""
        values = ["Zq9xWm4Tp2Lk77abcd"]
        t = "값 Zq9xWm4Tp2LkQQ77abcd 확인"
        step = g._ENV_TOKEN.sub(g.MASK, g._mask_env_values(t, values))
        self.assertEqual(step, "값 <redacted> 확인")
        self.assertEqual(g.mask("값 Zq9x Wm4T\np2Lk77abcd 확인", values, 600, home=""), "값 <redacted> 확인")
        self.assertEqual(g.mask("prefix-Zq9xWm4Tp2Lk77abcd.suffix 끝", values, 600, home=""), "<redacted> 끝")
        self.assertIsNone(g.leftover("값 <redacted> 확인", values))

    def test_cut_happens_after_masking(self):
        """A key that crosses the cut is masked before the cut. Cutting first would leave its first 8 letters, which no
        rule recognises on their own."""
        t = "x " * 296 + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY 끝"
        out = g.mask(t, (), 600)
        self.assertLessEqual(len(out), 600)
        self.assertNotIn("wJalrXUt", out)
        self.assertIn("wJalrXUt", g.mask(t[:600], (), 600))
        self.assertEqual(g.mask("abc", (), 0), "")

    def test_name_and_home_masked(self):
        home = "/home/jdoe"
        p = "김철수님께 보낼 견적 메일 초안을 %s/projects/x 에 저장하고 지수 이름은 빼줘 고객님 확인 jdoe" % home
        out = g.mask(p, (), 600, home=home, self_names=["지수", "jdoe"])
        self.assertNotIn("김철수", out)
        self.assertNotIn("지수", out)
        self.assertNotIn(home, out)
        self.assertNotIn("jdoe", out)
        self.assertIn("~/projects/x", out)
        self.assertIn("고객님", out)
        self.assertEqual(out.count("<name>"), 3)

    def test_home_default_and_disabled(self):
        home = os.path.expanduser("~")
        self.assertNotIn(home, g.mask("path %s/notes here" % home, (), 600))
        self.assertIn("~/notes", g.mask("path %s/notes here" % home, (), 600))
        self.assertIn("/srv/data", g.mask("path /srv/data/x", (), 600, home="/srv/data2"))
        self.assertEqual(g.mask("a/b", (), 600, home="/"), "a/b")
        self.assertEqual(g.mask("path /opt/app/x", (), 600, home=""), "path /opt/app/x")

    def test_korean_honorific_names_and_titles(self):
        out = g.mask("홍길동씨와 박민지님, 고객님과 이사님 그리고 박사님께", (), 600, home="")
        self.assertEqual(out, "<name>씨와 <name>님, 고객님과 이사님 그리고 박사님께")

    def test_self_names_word_boundaries(self):
        out = g.mask("dan said danger; Dan and DAN. tag ab12cd", (), 600, home="", self_names=["dan", "ab12"])
        self.assertEqual(out, "<name> said danger; <name> and <name>. tag <name>cd")
        self.assertEqual(g.mask("Jane  Doe wrote", (), 600, home="", self_names=["Jane Doe"]), "<name> wrote")
        self.assertEqual(g.mask("x", (), 600, home="", self_names="x"), "<name>")

    def test_key_shapes(self):
        shapes = ["sk-proj-abcdefgh12345678", "sk_live_abcdefghij1234", "rk_test_ABCDEFGHIJ1234",
                  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "gh" + "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123",
                  "github_pat_11ABCDEFG0123456789_abcdefghij", "xo" + "xb-1234567890-abcdefghij", "AKIAIOSFODNN7EXAMPLE",
                  "AI" + "zaSyA1234567890abcdefghijklmnopqrstuv", "sbp_0123456789abcdefghij0123",
                  "np" + "m_abcdefghijklmnopqrstuvwxyz0123456789", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"]
        for k in shapes:
            out = g.mask("use %s now" % k, (), 600, home="")
            self.assertEqual(out, "use <redacted> now", k)
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0abc\nxyz\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(g.mask("key:\n%s\ndone" % pem, (), 600, home=""), "key:\n<redacted>\ndone")
        self.assertEqual(g.mask("Authorization: Bearer abc.def.ghi", (), 600, home=""), "Authorization: <redacted>")
        self.assertEqual(g.mask("curl -H basic dXNlcjpwYXNzd29yZA==", (), 600, home=""), "curl -H basic <redacted>")
        self.assertEqual(g.mask("ssh deploy:Hx9pwq@build.example.org now", (), 600, home=""), "ssh <redacted> now")
        self.assertEqual(g.mask("commit 3f2a9c1 merged", (), 600, home=""), "commit <hash> merged")

    def test_korean_personal_data_shapes(self):
        cases = [("전화 010-1234-5678 끝", "전화 <phone> 끝"), ("전화 +82 10 2345 6789 끝", "전화 <phone> 끝"),
                 ("전화 (02) 1234-5678 끝", "전화 <phone> 끝"), ("전화 031.123.4567 끝", "전화 <phone> 끝"),
                 ("주민 900101-1234567 끝", "주민 <id-number> 끝"), ("외국인 900101-5234567 끝", "외국인 <id-number> 끝"),
                 ("카드 4532 0151 1283 0366 끝", "카드 <card> 끝"), ("아멕스 378282246310005 끝", "아멕스 <card> 끝"),
                 # a separated Amex number already matches the earlier account rule: masked, labelled <account>
                 ("아멕스 3782 822463 10005 끝", "아멕스 <account> 끝"),
                 ("계좌 110-123-456789 끝", "계좌 <account> 끝"), ("농협 계좌 301 1234 5678 91 끝", "농협 계좌 <account> 끝"),
                 ("메일 a.b@example.co.kr 끝", "메일 <email> 끝"), ("메일 kim at example dot com 끝", "메일 <email> 끝")]
        for t, want in cases:
            self.assertEqual(g.mask(t, (), 600, home=""), want, t)
        self.assertEqual(g.mask("ports 3000 8080 5432 open", (), 600, home=""), "ports 3000 8080 5432 open")

    def test_long_letter_digit_tokens(self):
        """Tokens of 32+ letter-digit characters that the 8-64 rule leaves are masked, so leftover() does not have to stop
        the send (base64 of a key, 88 characters)."""
        b64 = "c2stYW50LWFwaTAzLUFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0"
        out = g.mask("decode %s please" % b64, (), 600, home="")
        self.assertEqual(out, "decode <redacted> please")
        self.assertEqual(g.leftover("decode %s please" % b64), "long-token")
        self.assertIsNone(g.leftover(out))
        name_like = "claude-sonnet-5-5-and-gpt-image-2-and-more-parts"
        self.assertEqual(g.mask(name_like, (), 600, home=""), "<redacted>")
        self.assertEqual(g.mask("claude-sonnet-5-5", (), 600, home=""), "claude-sonnet-5-5")

    def test_non_string_and_limits(self):
        self.assertEqual(g.mask(None), "")
        self.assertEqual(g.mask({"prompt": "x"}), "")
        long_text = "word " * 2000
        self.assertEqual(len(g.mask(long_text, (), 600)), 600)
        self.assertLessEqual(len(g.mask(long_text, (), 5000)), 5000)
        self.assertGreater(len(g.mask(long_text, (), 5000)), 4000)

    def test_account_4_2_7_not_taken_for_a_date(self):
        """A 4-2-7 account (3333-01-1234567) starts like a date and was kept whole. A date now needs month 01-12, day 01-31
        and no digit right after the day: the account is masked, real dates are still kept."""
        for t in ("카카오뱅크 계좌 3333-01-1234567 로 입금해줘", "계좌 3333-12-1234567 확인", "3333-01-123456 번 계좌"):
            out = g.mask(t, (), 600, home="")
            self.assertIn("<account>", out, t)
            self.assertNotIn("123456", out, t)
            self.assertIsNone(g.leftover(out), t)
        for keep in ("2026-10-01-12-30 에 시작", "2026-10-01 12:30 회의", "2026/10/01/1234 로그", "작업일 2026-10-01 끝"):
            self.assertEqual(g.mask(keep, (), 600, home=""), keep)


class NextToKoreanLetters(unittest.TestCase):
    """A number or key written against a Korean word ("010-1234-5678이야", "번호는010-...", "이거sk-...로") went out
    unmasked: Python's \\b counts a Korean letter as a word character, so the rule did not match at that edge."""

    NUMBERS = [("010-1234-5678", "<phone>"), ("+82 10 2345 6789", "<phone>"), ("02-123-4567", "<phone>"),
               ("(02) 1234-5678", "<phone>"), ("900101-1234567", "<id-number>"), ("900101-5234567", "<id-number>"),
               ("4532-0151-1283-0366", "<card>"), ("4532 0151 1283 0366", "<card>"), ("378282246310005", "<card>"),
               ("110-123-456789", "<account>"), ("123456-01-234567", "<account>"), ("3333-01-1234567", "<account>")]

    def test_numbers_against_korean_letters_masked(self):
        for number, placeholder in self.NUMBERS:
            for text in ("메모 %s이야 확인" % number, "메모 번호는%s 확인" % number, "메모 번호는%s로 확인" % number):
                out = g.mask(text, (), 600, home="")
                self.assertEqual(out, text.replace(number, placeholder), text)
                self.assertIsNone(g.leftover(out), text)

    def test_keys_against_korean_letters_masked(self):
        """Key bodies of letters only: no other rule (mixed letter-digit tokens) catches them."""
        keys = ["sk-abcdefghijklmnop", "xo" + "xb-abcdefghijklmnop", "gh" + "p_abcdefghijklmnopqrstuvwx",
                "AKIA" + "ABCDEFGHIJKLMNOP", "sbp_" + "abcdefghijklmnopqrstuvwx", "123456789:" + "Ab" * 17 + "c"]
        for k in keys:
            for text in ("값은%s이야" % k, "이거%s로 해줘" % k):
                self.assertEqual(g.mask(text, (), 600, home=""), text.replace(k, "<redacted>"), text)

    def test_reported_prompts_on_wire(self):
        """The prompts from the review through the example hook: the number is in neither the request body nor the
        logged head."""
        prompts = {"내 번호는 010-1234-5678이야 저장해줘": "내 번호는 <phone>이야 저장해줘",
                   "주민번호 900101-1234567로 서류 채워줘": "주민번호 <id-number>로 서류 채워줘",
                   "계좌 110-123-456789로 보내달라고 써줘": "계좌 <account>로 보내달라고 써줘",
                   "법인카드 4532-0151-1283-0366로 결제 테스트 해줘": "법인카드 <card>로 결제 테스트 해줘"}
        sb = s.Sandbox()
        srv = s.MockServer()
        try:
            ex = sb.load_example(sb.env(endpoint=srv.url))
            for i, p in enumerate(prompts):
                self.assertEqual(ex.run(s.payload(p, sid="s-ko-%d" % i)), "")
            self.assertEqual([d["status"] for d in sb.finals()], ["judged"] * 4)
            sent = [json.loads(b)["state"]["prompt"] for b in srv.bodies()]
            heads = [d["prompt_head"] for d in sb.decisions() if d["status"] == "pending"]
            self.assertEqual(sent, list(prompts.values()))
            self.assertEqual(heads, list(prompts.values()))
        finally:
            srv.close()
            sb.cleanup()


class LabelValues(unittest.TestCase):
    """_mask_near_labels(): the value next to a secret label. refuse() stops only some label words (api key, 인증키,
    token, ...). After the others (시크릿 = secret, 토큰 = token, 인증번호 = verification code, OTP, PIN, pwd, 키체인 =
    keychain, other ...키 = ... key) mask() is the only step that hides the value, and values of letters only or digits
    only are left alone by the mixed letter-digit token rules."""

    def test_values_next_to_labels_masked(self):
        cases = [  # (text, mask() output, refuse())
            ("시크릿: QwErTyUiOp 로 바꿔줘", "시크릿: <redacted> 로 바꿔줘", None),
            ("시크릿 키: Zx!8qwe#Rt 로 설정", "시크릿 키: <redacted> 로 설정", None),
            ("토큰: QwErTyUiOpAs 넣고 호출해줘", "토큰: <redacted> 넣고 호출해줘", None),
            ("인증번호 482913 입력해줘", "인증번호 <redacted> 입력해줘", None),
            ("인증 번호는\n482913 이야", "인증 번호는\n<redacted> 이야", None),
            ("OTP 482913 넣어줘", "OTP <redacted> 넣어줘", None),
            ("otp는 482913 이야", "otp는 <redacted> 이야", None),
            ("PIN: 7391 이야", "PIN: <redacted> 이야", None),
            ("pin 7391 입력", "pin <redacted> 입력", None),
            ("pwd Tiger#Lily!Moon 로 접속", "pwd <redacted> 로 접속", None),
            ("키체인 QwErTyUiOpAs 지워줘", "키체인 <redacted> 지워줘", None),
            ("앱키 QwErTyUiOpAs 로 바꿔", "앱키 <redacted> 로 바꿔", None),
            ("auth: Zq9xWm4Tp2Lk", "auth: <redacted>", None),
            # refuse() drops these in a hook; mask() called on its own still hides the value
            ("api key = Ab12Cd34Ef56", "api key = <redacted>", "secret-label"),
            ("인증키 Ab12Cd34Ef56Gh78", "인증키 <redacted>", "secret-label"),
        ]
        for text, want, why in cases:
            self.assertEqual(g.refuse(text), why, text)
            self.assertEqual(g.mask(text, (), 600, home=""), want, text)
            self.assertIsNone(g.leftover(want), text)

    def test_label_words_without_a_value_kept(self):
        """A label word followed by ordinary words, a count, a date or a version is not a secret."""
        texts = ["token 12000개", "토큰 12000개를 썼고 연락은 메일로 주세요.", "Auth: fixed the login redirect after the upgrade",
                 "pin the dependency to 1.2.3", "run pwd then ls -la", "OTP 앱 설치 방법", "단축키 Cmd+Shift+4 눌러",
                 "인증번호 받기 버튼", "PIN: 2026-10-01"]
        for text in texts:
            self.assertEqual(g.mask(text, (), 600, home=""), text)


if __name__ == "__main__":
    unittest.main()

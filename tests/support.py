"""Shared fixtures and helpers for the tests. Every value below is fake. No test touches the network: requests go to a
loopback mock server, or the module's `_open` is replaced."""
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.dont_write_bytecode = True                       # keep __pycache__ out of the working tree
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
EXAMPLE = os.path.join(ROOT, "hooks", "example_prompt_hook.py")
WRAPPER = os.path.join(ROOT, "hooks", "wrapper.sh")
DEAD = "http://127.0.0.1:9/v1/systemone"           # closed port: connection refused

# Fixtures shaped like real vendor tokens are assembled at import time, so these files hold no whole literal that a
# scanner for real token formats (GitHub push protection) would flag. The values themselves are fake.
SKA = "sk-ant-" + "api03-"

# Fake env-file values. None contains a label word (secret, token, password, ...): such a word makes refuse() drop the
# whole input, and these fixtures exist to test masking. The second value shares the "sk-ant-api03" prefix with the
# keys in SECRETS on purpose.
FAKE_CREDS = {"TYPESAFE_API_KEY": "ts-test-key-not-real-0001", "ANTHROPIC_API_KEY": SKA + "FAKEfake0123456789abcdefXYZ",
              "DB_VALUE_ONE": "Kx82mQ9vLp44Rt", "APP_VALUE_TWO": "Zq9xWm4Tp2Lk77abcd", "SHORT_ONE": "abc"}
KEY = FAKE_CREDS["TYPESAFE_API_KEY"]
SECRETS = {"anthropic": SKA + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
           "aws": "AKIAIOSFODNN7EXAMPLE", "github": "gh" + "p_1234567890abcdefghijABCDEFGHIJ123456",
           "slack": "xo" + "xb-1234567890-abcdefghij", "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
           "phone1": "010-1234-5678", "phone2": "+82 10 9876 5432", "phone3": "01055556666", "email": "someone.test@example.com",
           "rrn": "900101-1234567", "card": "4111-1111-1111-1111", "envval": "hunter2qwertyvalue",
           "google": "AI" + "zaSyA1234567890abcdefghijklmnopqrstuv"}
# Korean prompt: "fix the deploy script. the key is ..., AWS ..., GitHub ..., Slack ..., token ..., contact ..., mail ...,
# resident number ..., card ..., Google ...".
PROMPT_SECRET = ("배포 스크립트 고쳐줘. 키는 %(anthropic)s 이고 AWS는 %(aws)s, 깃허브 %(github)s, 슬랙 %(slack)s, 토큰 %(jwt)s. "
                 "연락처 %(phone1)s / %(phone2)s / %(phone3)s, 메일 %(email)s, 주민 %(rrn)s, 카드 %(card)s, "
                 "DB_URL_VALUE=%(envval)s, 구글 %(google)s" % SECRETS)
GOOD_PROMPT = "지식 저장소 색인 검색 도구를 바꾸려는데 뭘 조심해야 해?"   # "what should I watch for when changing the index search?"

# First review: 26 leak cases. (label, prompt, fragment the review named, whole value, comparison: digits = 7+ common
# digits, alnum = 6+ common characters; see survived())
AUDIT26 = [
    ("URL scheme credential (with !)", "DB 붙여줘 postgres://admin:S3cr3tPass!@db.example.com:5432/app 이거 연결 안돼", "S3cr3tPass",
     "S3cr3tPass!", "alnum"),
    ("URL scheme credential (alnum before @)", "redis://default:Zq9xWm4Tp2@10.0.0.5:6379 로 붙는데 타임아웃 나", "default:Zq9xWm4Tp2",
     "Zq9xWm4Tp2", "alnum"),
    ("KEY: value, prefixed name", "OPENAI_API_KEY: Zq9xWm4Tp2Lk 로 설정했는데 401 떠", "Zq9xWm4Tp2Lk", "Zq9xWm4Tp2Lk", "alnum"),
    ("lowercase db_password=value", ".env에 db_password=hunter2x 넣었는데 연결이 안 돼", "hunter2x", "hunter2x", "alnum"),
    ("value after a particle (password는)", "password는 Tr0ub4dor&3 인데 로그인이 안 돼 왜 그럴까", "Tr0ub4dor", "Tr0ub4dor&3",
     "alnum"),
    ("Korean label 비번", "관리자 비번: qwerty123! 로 들어가서 설정 바꿔줘 부탁해", "qwerty123", "qwerty123!", "alnum"),
    ("Korean label 인증키", "공공데이터 인증키 = Ab12Cd34Ef56Gh78 넣고 호출해줘 부탁", "Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78", "alnum"),
    ("pass is ...", "the wifi pass is BlueSky2024 so connect the pi to it please", "BlueSky2024", "BlueSky2024", "alnum"),
    ("short password (5 chars)", "서버 password: ab12c 로 ssh 접속해서 로그 봐줘 제발", "ab12c", "ab12c", "alnum"),
    ("key split across lines", "키 붙여넣을게\n" + SKA + "AbCdEfGh\nIjKlMnOpQrStUvWx0123\n이걸로 호출해줘", "IjKlMnOpQrStUvWx0123",
     SKA + "AbCdEfGhIjKlMnOpQrStUvWx0123", "alnum"),
    ("fullwidth key", "키는 ｓｋ－ａｎｔ－ａｐｉ０３－ＡｂＣｄＥｆＧｈＩｊ 이야 설정해줘", "ＡｂＣｄＥｆＧｈＩｊ",
     "ｓｋ－ａｎｔ－ａｐｉ０３－ＡｂＣｄＥｆＧｈＩｊ", "alnum"),
    ("key with a Cyrillic s", "키는 ѕk-ant-api03-AbCdEfGhIjKl 이야 설정해 줘 부탁해", "AbCdEfGhIjKl", "ѕk-ant-api03-AbCdEfGhIjKl",
     "alnum"),
    ("resident number with en dash", "가족 주민번호 900101–1234567 로 서류 채워줘 부탁해요", "1234567", "900101–1234567", "digits"),
    ("resident number, spaced hyphen", "주민번호 900101 - 2234567 로 신청서 작성해줘 제발", "2234567", "900101 - 2234567", "digits"),
    ("Amex card 4-6-5", "법인카드 3782 822463 10005 로 결제 테스트 해줘 부탁", "822463", "3782 822463 10005", "digits"),
    ("bank account (3-3-6)", "입금 계좌 신한 110-123-456789 예금주 홍길동으로 안내문 써줘", "110-123-456789", "110-123-456789",
     "digits"),
    ("bank account (6-2-6)", "국민은행 123456-01-234567 로 환불해 달라는 메일 써줘", "123456-01-234567", "123456-01-234567", "digits"),
    ("email written with at", "연락은 kim.jisoo at example dot com 으로 달라고 써줘", "kim.jisoo", "kim.jisoo", "alnum"),
    ("phone with area code in parentheses", "사무실 (02) 1234-5678 로 연락 달라고 공지 써줘 부탁", "1234-5678", "(02) 1234-5678",
     "digits"),
    ("phone in fullwidth digits", "연락처 ０１０-１２３４-５６７８ 로 바꿔서 저장해 줘", "５６７８", "０１０-１２３４-５６７８", "digits"),
    ("pasted .env (mixed case)", "```\nDb_Password=hunter2secret\nstripeKey=rk9Tq2Lm4Xz\n```\n이 설정으로 배포해줘", "hunter2secret",
     "hunter2secret", "alnum"),
    ("pasted .env, second value", "```\nDb_Password=hunter2secret\nstripeKey=rk9Tq2Lm4Xz\n```\n이 설정으로 배포해줘", "rk9Tq2Lm4Xz",
     "rk9Tq2Lm4Xz", "alnum"),
    ("JSON pwd field", "설정 파일 {\"user\": \"admin\", \"pwd\": \"Pa55w0rdX\"} 이거 맞아?", "Pa55w0rdX", "Pa55w0rdX", "alnum"),
    ("query pw, short name", "https://nas.local/login?id=admin&pw=Kx82mQ9 로 접속 스크립트", "Kx82mQ9", "Kx82mQ9", "alnum"),
    ("key inside pasted_content", "<pasted_content id=\"ab12\">\nANTHROPIC_API_KEY=" + SKA + "AbCdEfGhIjKlMnOp\n"
                                  "</pasted_content id=\"ab12\">\n이거 봐줘", "AbCdEfGhIjKlMnOp", SKA + "AbCdEfGhIjKlMnOp", "alnum"),
    ("real name and street address", "고객 김철수님 서울시 강남구 테헤란로 123 101동 202호 계약서 초안 써줘", "김철수", "김철수", "alnum"),
]
# Second review: 26 bypass cases. (name, prompt, value, comparison: digits = 7+ common digits, alnum = 6+ common chars)
BYPASS26 = [
    ("key split by spaces", "이 키로 호출해 줘 sk-ant-api03-Q7wE 9rTy U2iO pA5s DfG8 hJkL 4zXc 그리고 결과 알려줘",
     SKA + "Q7wE9rTyU2iOpA5sDfG8hJkL4zXc", "alnum"),
    ("비번은 + line break + value", "서버 비번은\nXk29mQpL 이걸로 접속해서 로그 봐줘", "Xk29mQpL", "alnum"),
    ("spaced label 비 번 + value without digits", "서버 비 번은\nTiger#Lily!Moon 이걸로 접속해서 로그 봐줘", "Tiger#Lily!Moon", "alnum"),
    ("key in base64 (44 chars)", "이 값 디코드해서 설정에 써줘 c2stYW50LWFwaTAzLUFiQ2RFZkdoSWpLbE1uT3BRclN0 그리고 재시작",
     "c2stYW50LWFwaTAzLUFiQ2RFZkdoSWpLbE1uT3BRclN0", "alnum"),
    ("key in base64 (88 chars, one line)",
     "이 값 디코드해 줘 c2stYW50LWFwaTAzLUFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0 끝",
     "c2stYW50LWFwaTAzLUFiQ2RFZkdoSWpLbE1uT3BRclN0VXZXeFl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0", "alnum"),
    ("URL query ?token=", "https://api.example.com/v1/items?token=Ab12Cd34Ef56Gh78 로 부르면 403 나와 봐줘", "Ab12Cd34Ef56Gh78", "alnum"),
    ("URL query ?access_key=", "https://cdn.example.com/v1/items?access_key=Ab12Cd34Ef56Gh78 로 부르면 403 나와 봐줘",
     "Ab12Cd34Ef56Gh78", "alnum"),
    ("URL query ?k= letters only", "https://maps.example.com/tiles?k=QwErTyUiOpAsDfGhJk&z=3 로 타일이 안 떠 봐줘", "QwErTyUiOpAsDfGhJk", "alnum"),
    ("Korean label 패스워드:", "공유기 패스워드: Zx!8qweRt 로 들어가서 포트 열어줘", "Zx!8qweRt", "alnum"),
    ("label P/W:", "공유기 관리 페이지 P/W: Zx!8qwe 로 들어가서 포트 열어줘", "Zx!8qwe", "alnum"),
    ("label 비밀 번호 (spaced)", "공유기 비밀 번호 Zx!8qwe 로 들어가서 포트 열어줘", "Zx!8qwe", "alnum"),
    ("phone +82 10", "연락처 +82 10 2345 6789 로 바꿔서 저장해 줘", "+821023456789", "digits"),
    ("phone +82 (0)10", "연락처 +82 (0)10 2345 6789 로 바꿔서 저장해 줘", "+821023456789", "digits"),
    ("phone with slashes", "연락처 010/2345/6789 로 바꿔서 저장해 줘", "01023456789", "digits"),
    ("pasted .env, 3 lines (no spaces around =)", "DB_HOST=db.internal.example\nDB_USER=admin\nDB_PASS=Zx81qweRtY\n이 설정으로 붙여줘",
     "Zx81qweRtY", "alnum"),
    ("pasted .env, 3 lines (spaces, lowercase)", "db_host = db.internal.example\ndb_user = admin\ndb_pass = Zx81qweRtY\n이 설정으로 붙여줘",
     "Zx81qweRtY", "alnum"),
    ("resident number with a space", "가족 주민번호 900101 1234567 로 서류 채워줘", "9001011234567", "digits"),
    ("foreigner registration number (starts with 5)", "직원 외국인등록번호 900101-5234567 로 서류 채워줘", "9001015234567", "digits"),
    ("card, one space", "법인카드 4532 0151 1283 0366 로 결제 테스트 해줘", "4532015112830366", "digits"),
    ("card, two spaces", "법인카드 4532  0151  1283  0366 로 결제 테스트 해줘", "4532015112830366", "digits"),
    ("card, spaced hyphens", "법인카드 4532 - 0151 - 1283 - 0366 로 결제 테스트 해줘", "4532015112830366", "digits"),
    ("bank account with spaces", "국민은행 123456 01 234567 로 환불해 달라는 메일 써줘", "12345601234567", "digits"),
    ("email: at + a real dot", "연락은 kim.minsu at example.com 으로 달라고 써줘", "kim.minsu", "alnum"),
    ("email: space after @", "연락은 kim.minsu@ example.com 으로 달라고 써줘", "kim.minsu", "alnum"),
    ("AWS secret key, 40 chars (control)", "aws 설정에 wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY 넣고 배포해줘",
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "alnum"),
    ("Telegram bot URL (control)", "https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage 로 보내줘",
     "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "alnum"),
]
# Over-masking controls: ordinary text the shape rules must leave alone (dates, versions, test results, ports, prices,
# word runs, a queue ticket, a domain, times, a timestamp, model names, a matrix product, handles, file names).
NO_OVERMASK = ["작업일 2026-10-01 에 react@19.0.0 으로 올렸고 Pass: 128/128 입니다.", "포트 3000 8080 5432 를 열어 주세요.",
               "가격은 15000 20000 25000원 세 가지예요.", "this will help make sure that works", "창구에서 준비 번호표를 뽑았습니다.",
               "API는 api.example.com 에 있습니다.", "버전 2.1.284 와 10:30 회의", "타임스탬프 1790662827840 기준",
               "2026 10 01 12 30 에 시작", "All tests pass 85/85 and the build is green.", "모델은 claude-sonnet-5-5 와 gpt-image-2",
               "행렬 곱 a @ b.T 로 계산", "Fixed the password reset flow; all 12 tests pass.", "meet at noon tomorrow",
               "비밀번호 변경 절차\n설정 화면에서 바꾼다 README 참고", "토큰 12000개를 썼고 연락은 메일로 주세요.",
               "인스타 계정 @shop.example 와 @studio.zip 에 올렸어요.",
               "Look at README.md and main.py first.", "tcp/ws 연결과 p/w 비율 메모"]


def _longest_common(a, b):
    best, prev = 0, [0] * (len(b) + 1)
    for i in range(1, len(a) + 1):
        cur = [0] * (len(b) + 1)
        for j in range(1, len(b) + 1):
            if a[i - 1] == b[j - 1]:
                cur[j] = prev[j - 1] + 1
                best = max(best, cur[j])
        prev = cur
    return best


def survived(secret, sent, kind):
    """Reviewer's rule: digits -> keep digits only, 7+ common digits leak; otherwise NFKC and no whitespace, 6+ common
    characters leak."""
    if kind == "digits":
        a, b = (re.sub(r"\D", "", unicodedata.normalize("NFKC", s)) for s in (secret, sent))
        return _longest_common(a, b) >= 7
    a, b = (re.sub(r"\s+", "", unicodedata.normalize("NFKC", s)) for s in (secret, sent))
    return _longest_common(a, b) >= 6


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def answers_for(body, p=0.1):
    try:
        q = json.loads(body).get("questions") or {}
    except (ValueError, AttributeError):
        q = {}
    return json.dumps({"answers": {k: {"type": "noul", "noul": p} for k in q}, "model": "jev-1.13.0",
                       "usage": {"input_tokens": 1200}}).encode()


class MockServer(object):
    """Loopback mock judge. mode: ok (answers every question with p) | redirect (3xx to `location`) |
    status (error `code`) | drip (sends the body one byte every `delay` seconds)."""

    def __init__(self, mode="ok", code=200, location=None, p=0.1, delay=0.0):
        self.reqs, self.mode, self.code, self.location, self.p, self.delay = [], mode, code, location, p, delay
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_POST(self):
                outer.handle(self)

            def do_GET(self):
                outer.handle(self)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.srv.block_on_close = False      # do not wait for a dripping handler on close
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.url = "http://127.0.0.1:%d/v1/systemone" % self.srv.server_address[1]

    def handle(self, h):
        n = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(n) if n else b""
        self.reqs.append({"method": h.command, "auth": h.headers.get("Authorization"), "body": body,
                          "headers": dict(h.headers.items())})
        if self.mode == "redirect":
            h.send_response(self.code)
            h.send_header("Location", self.location)
            h.send_header("Content-Length", "0")
            h.end_headers()
            return
        if self.mode == "status":
            payload = json.dumps({"error": {"type": "error %d" % self.code}}).encode()
            h.send_response(self.code)
        else:
            payload = answers_for(body, self.p)
            h.send_response(200)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(payload)))
        h.end_headers()
        if self.mode == "drip":
            for i in range(len(payload)):
                try:
                    h.wfile.write(payload[i:i + 1])
                    h.wfile.flush()
                except OSError:
                    return
                time.sleep(self.delay)
            return
        h.wfile.write(payload)

    def bodies(self):
        return [r["body"].decode("utf-8") for r in self.reqs]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Sandbox(object):
    """Temporary state directory, fake env file and fake HOME for the example hook."""

    def __init__(self, creds=None, exclude=None):
        self.root = tempfile.mkdtemp(prefix="jhg_")
        self.state = os.path.join(self.root, "state")
        self.home = os.path.join(self.root, "home")
        os.mkdir(self.home)
        self.creds = os.path.join(self.root, "creds.env")
        with open(self.creds, "w", encoding="utf-8") as f:
            f.write("".join("%s=%s\n" % kv for kv in (FAKE_CREDS if creds is None else creds).items()))
        self.exclude = os.path.join(self.root, "exclude.txt")
        if exclude is not None:
            with open(self.exclude, "w", encoding="utf-8") as f:
                f.write(exclude)

    def env(self, endpoint=DEAD, key=KEY, **extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith("JHG_") and k != "TYPESAFE_API_KEY"}
        e.update(JHG_STATE_DIR=self.state, JHG_ENDPOINT=endpoint, JHG_ENV_FILE=self.creds, JHG_EXCLUDE=self.exclude,
                 HOME=self.home)
        if key is not None:
            e["TYPESAFE_API_KEY"] = key
        e.update(extra)
        return e

    def decisions(self):
        p = os.path.join(self.state, "decisions.jsonl")
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    def finals(self):
        return [d for d in self.decisions() if d.get("status") != "pending"]

    def errors(self):
        p = os.path.join(self.state, "error.log")
        if not os.path.exists(p):
            return ""
        with open(p, encoding="utf-8") as f:
            return f.read()

    def run_example(self, stdin, env, python=None):
        """The example hook as Claude Code runs it: a separate process in isolated mode."""
        return subprocess.run([python or sys.executable, "-I", "-B", EXAMPLE], input=stdin, capture_output=True,
                              text=True, env=env, timeout=30)

    def install_copy(self):
        """Copy the module and hooks/ the way the README installs them; returns the copied wrapper path."""
        dest = os.path.join(self.root, "installed")
        shutil.copytree(os.path.join(ROOT, "hooks"), os.path.join(dest, "hooks"))
        shutil.copy(os.path.join(ROOT, "jev_hook_guard.py"), dest)
        return os.path.join(dest, "hooks", "wrapper.sh")

    def load_example(self, env):
        """The example hook imported in this process (module constants read from `env`)."""
        with mock.patch.dict(os.environ, env, clear=True):
            spec = importlib.util.spec_from_file_location("example_prompt_hook_%d" % id(self), EXAMPLE)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        return m

    def cleanup(self):
        for d, _subs, _files in os.walk(self.root):
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)


def payload(prompt=GOOD_PROMPT, sid="s-1", cwd="/home/dev/projects/app", tp="/home/dev/.claude/projects/app/s-1.jsonl"):
    return json.dumps({"session_id": sid, "transcript_path": tp, "cwd": cwd, "permission_mode": "default",
                       "hook_event_name": "UserPromptSubmit", "prompt": prompt}, ensure_ascii=False)

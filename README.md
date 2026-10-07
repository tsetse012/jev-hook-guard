**English** | [한국어](README.ko.md)

# jev-hook-guard

![A prompt passes the kill switch, the exclusion words, the refusal check, masking and a last check before one masked line is sent to the judgment API](docs/img/hero.png)

**The checks a Claude Code hook runs before it sends text to an external judgment API.**

A Claude Code hook that asks a remote model for a judgment (TypeSafe Jev's `/v1/systemone`, or any HTTP judge) sends text from your session off your machine: the prompt you typed, a tool call, the last assistant message. That text carries API keys, phone numbers, client names and file paths. `jev_hook_guard.py` is one standard-library Python module that runs in front of that send. It stops sessions that touched topics you listed, refuses inputs that look like a secret dump, masks what is left, checks the result once more, and posts with no redirects and a hard time limit; a wrapper script keeps a broken hook from blocking your session. It is for anyone writing a Claude Code hook or an agent sidecar that calls a judgment API. It is not a guarantee: it is a set of regular-expression rules applied as the last step before the send, tested against 52 adversarial cases from two independent reviews, and every new kind of secret needs its own rule.

## What leaves the machine, what never does

| Item | Where it goes |
|---|---|
| Masked text, at most `limit` characters (600 by default) | to the endpoint you set |
| Your question wording and the model name | to the endpoint you set |
| The API key | only in the `Authorization` header, only to an https endpoint (or http on 127.0.0.1, localhost, [::1]), never to a second host after a redirect |
| Unmasked text of any kind: the prompt, tool input, tool output | never |
| Anything from a session after an exclusion hit in user text, assistant text, the working directory or the transcript path | never, for the rest of that session |
| An input that looks like a secret dump: URL credentials, a secret label, two or more `NAME=value` lines, a street address | never: refused whole |
| Values of 6 or more characters from your env file (see Limits), their first or last 12 characters, and any token that contains one of these | never: `<redacted>` |
| Key and token shapes, phone numbers, ID numbers, card and account numbers, email addresses, Korean honorific names, your own names, your home path | never: `<redacted>` `<phone>` `<id-number>` `<card>` `<account>` `<email>` `<hash>` `<name>` `~` |
| Anything at all, when the pending log line cannot be written or the pin directory is not writable | never |
| Log lines | stay on disk: files 0600 in a 0700 directory; the example hook logs a status and the first 120 masked characters, never raw text |

## What it does, in order

![The nine steps from the kill switch to error classification, and the exits at each step that send nothing](docs/img/pipeline.png)

1. **Kill switch.** The hook checks a file (`OFF`) first and stops: no log line, no network.
2. **Exclusion words.** `Exclude` reads one pattern per line from a file and matches it on normalized text, then again with all whitespace removed. A hit pins the session with `SessionPins`.
3. **Refuse.** `refuse()` drops the whole input when it looks like a secret dump: URL credentials, a secret label, a pasted `.env` file, a street address.
4. **Mask.** `mask()` replaces env-file values, key and token shapes, personal data, values next to labels, names and your home path.
5. **Cut.** `mask()` cuts to `limit` characters after masking, so no half key is left at the edge.
6. **Leftover check.** `leftover()` runs the rules for env values, keys, labelled values, phone, ID, card and account numbers and long tokens once more on the exact text to be sent; any hit means no send.
7. **Pending line.** `append_jsonl()` writes a pending line before the send. If that fails, nothing is sent.
8. **Post.** `post_json()` sends over https only (http only to loopback), refuses every 3xx, and stops at a wall-clock deadline.
9. **Classify errors.** `classify_error()` sorts failures into `timeout`, `billing` (402), `redirect-refused`, `auth-error`, `rate-limited`, `http-error` and `network`. The example hook also writes 402 to an error log, because a judge that stops answering for lack of credits looks like a judge that answers no.

## Why each rule exists

The rules come from two private hooks that send text to TypeSafe Jev (a prompt hook and a Stop hook), and from independent reviews of them.

- **Whole tokens, not the first and last 12 characters.** An earlier version masked a known credential by its first and last 12 characters. On real values that left 7 to 8 characters from the middle in 19 items, and the last check let them through. Now any token that touches a known value is replaced whole.
- **52 adversarial cases.** Two independent reviews wrote 26 + 26 inputs meant to get a secret past the masking: keys split across lines or into 4-character groups, fullwidth and Cyrillic lookalike keys, phone numbers with `+82 (0)` or slashes, spaced card and account numbers, foreigner registration numbers, `P/W` and spaced Korean labels, `at`/`dot` email addresses, a space after `@`, query values without digits. Before the fixes, 12 shapes from the second set leaked from all 5 places the prompt hook sends from: 60 of 130 sends. Every case is now refused or masked, and the tests check all 52.
- **Pins depend on where the hit came from.** A tool output that listed one file name matching an exclusion word once pinned a whole session, which was then never judged again. Now only user text, assistant text, the working directory and the transcript path pin a session. A hit in tool input, tool output, an attachment or the raw transcript tail skips that one send.
- **Pins are permanent.** A session that touched an excluded topic and is resumed the next day must not start sending again, so pin files are never cleaned.
- **Exit-0 wrapper.** Claude Code reads exit code 2 from a hook as "block". On `UserPromptSubmit` that blocks and erases the prompt; on `Stop` it forces the session to continue. A missing `.py` file makes `python3` exit with 2, so one moved file would block every prompt in every session. The wrapper always exits 0 and logs the code.
- **No redirects.** Following a 3xx would send the `Authorization` header to whatever host the redirect names.
- **Pending line first.** If the process is killed during the send, the log still shows that something was about to leave; if the log cannot be written, nothing leaves.
- **Separators in patterns.** A pattern written with a hyphen matched only the hyphen, and the spaced, underscored and joined spellings went out. Write `client[-_ ]?x`; matching also runs once with all whitespace removed.

## Install and use

No package to install: clone the repository (`git clone https://github.com/tsetse012/jev-hook-guard`) or copy `jev_hook_guard.py` next to your hook script. Python 3.9 or newer, standard library only.

```python
import os, jev_hook_guard as g

pins = g.SessionPins(os.path.expanduser("~/.my-hook/pinned"))
ex = g.Exclude(os.path.expanduser("~/.my-hook/exclude.txt"))
if pins.pinned(sid) or not pins.writable():
    return
if ex.hit(cwd) or ex.hit(prompt):
    pins.pin(sid, "cwd" if ex.hit(cwd) else "user")
    return
if g.refuse(prompt):
    return
env = g.load_env_values(os.path.expanduser("~/.my-hook/mask.env"))   # for example your credentials file
text = g.mask(prompt, env, limit=600, self_names=["Jane Doe", "jdoe"])
if not text or g.leftover(text, env):
    return
g.append_jsonl(log_path, {"status": "pending", "head": text[:120]})
try:
    resp, ms = g.post_json(url, {"model": "jev-1.13.0", "state": {"prompt": text}, "questions": questions}, key, 2.5)
except Exception as e:
    status, extra = g.classify_error(e)
```

`hooks/example_prompt_hook.py` is a complete `UserPromptSubmit` hook built this way. It asks Jev one question (does the prompt ask for something hard to undo?) and, in shadow mode, the default, only writes log lines. Register the wrapper, not the Python file (`hooks/settings.snippet.json`):

```json
{"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command",
  "command": "/ABSOLUTE/PATH/TO/jev-hook-guard/hooks/wrapper.sh", "timeout": 5}]}]}}
```

Settings for the example, all environment variables. The hook reads `TYPESAFE_API_KEY` (without it the hook logs `no-key` and sends nothing); `JHG_ENDPOINT`, the judge URL, default `https://api.typesafe.ai/v1/systemone` (https, or http on loopback only); `JHG_ENV_FILE`, the file whose values are masked; `JHG_EXCLUDE`, default `exclude.txt` in the state directory (see `examples/exclude.txt`); `JHG_SELF_NAMES`, comma-separated; `JHG_SHADOW=0` to print the reminder line into the session; `JHG_STATE_DIR`, the state directory, default `~/.jev-hook-guard/`, which holds `decisions.jsonl`, `error.log` and `pinned/`. The wrapper reads `JHG_PYTHON`, the interpreter, default `/usr/bin/python3` (where that path does not exist the hook does nothing and the wrapper writes `wrapper python rc=127` to `error.log`), and `JHG_HOOK_PY`, the hook file, default `example_prompt_hook.py` next to the wrapper.

Kill switch: `mkdir -p ~/.jev-hook-guard && touch ~/.jev-hook-guard/OFF` (the directory exists only after the hook's first run, so create it first). The hook stops before it reads the prompt. Remove the file to resume.

## Coverage

English and Korean shapes, matched after normalization (fullwidth letters folded, zero-width characters removed, NFC, dash variants unified, Cyrillic and Greek lookalikes mapped to Latin):

- Keys and tokens: `sk-` (OpenAI, Anthropic), `sk_live_` / `rk_test_` (Stripe), `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`, Slack tokens (`xoxa` `xoxb` `xoxo` `xoxp` `xoxr` `xoxs`), `AKIA` (AWS), `AIza` (Google), `sb_secret_` and `sbp_` (Supabase), `npm_`, Telegram bot tokens, JWTs, PEM private keys, `Authorization:` and `Bearer`, HTTP Basic and Digest, keys split into 4-character groups, letter-digit tokens of 8 characters or more.
- Assignments: names ending in `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASS`, `PWD` with `=` or `:`, JSON fields, `.env` lines, settings whose name contains `session`, `sid`, `auth`, `sign` or `cred`.
- URL credentials: `scheme://user:pw@host`, `user:pw@host` without a scheme, query values named `key`, `token`, `auth`, `sig`, `pass`, `pw`, `secret`, and other query values of 12 or more characters with both cases.
- Values next to labels: password, passwd, passphrase, pwd, P/W, pass, api key, token, secret, auth, otp, pin, and the Korean labels 비번, 비 번, 비밀번호, 암호, 패스워드, 인증번호, 시크릿, 키체인, ○○키, 토큰, including a value on the next line after `비번은`.
- Phone numbers: Korean mobile and landline numbers with hyphens, dots, slashes or spaces, `+82 10`, `+82 (0)10`, `(02) 1234-5678`.
- Korean resident registration numbers and foreigner registration numbers (the first six digits must be a date).
- Card numbers (4-4-4-4 with any separator, Amex 4-6-5) and bank account numbers (Korean layouts; ambiguous ones need a bank word nearby).
- Email addresses, including `name at example dot com`, `name at example.com` and a space after `@`.
- Commit hashes and hex ids; values of 6 or more characters from your env file (whole, split by spaces or lines, first or last 12 characters); Korean names before 님 and 씨; your own names; your home path.
- Refused whole: URL credentials; the words password, passwd, passphrase, secret, token, credential and api key in any case, also inside a longer word (tokens, apikey, api_key); pw and P/W standing alone; `pass is`; the Korean 비번 (also spaced, 비 번), 비밀번호, 암호, 인증키 and 패스워드; two or more `NAME=value` lines; Korean street addresses and apartment units. The other label words above (pwd, pass, auth, otp, pin, 인증번호, 시크릿, 키체인, other ○○키, 토큰) do not refuse the input: the value next to them is masked.

## Limits

- New kinds of data need their own rules. A secret with no recognizable shape and no label (a plain-word passphrase, a street address outside Korea, a name without an honorific) passes the shape rules. Put such words in the exclusion file, or put the value in the env file.
- The mask is lossy on purpose. Hashes, long tokens, paths with digits and numbers shaped like accounts become placeholders, and an input that mentions a password or a token is not sent at all. The judge sees less than you typed.
- Env-file values shorter than 6 characters (`min_len` of `load_env_values()`) are not loaded, so they are never masked: loading short values such as `true`, `false` or `8080` would mask that word or number everywhere in the text. A short secret is masked only when a label or a shape rule catches it; pass a smaller `min_len` if that extra masking is acceptable to you.
- A session pin is permanent. If a pin was wrong, delete its file under `pinned/` by hand.
- No thresholds are involved: this module makes no judgments. The question, the model and the probability that means "act" belong to your hook; the example's 0.7 is only an illustration.
- It is regex-based and runs as the last step before a send. It does not replace a data-loss-prevention product; read what your hook logs as sent.
- Known gaps in 0.1.1, measured on the final module: after `pwd =`, `pass:` or `pw는` only the first word of a multi-word value is masked (`passphrase` is refused whole, these labels are not); `핀번호 7391` is not masked because `핀번호` is not a label word; a letters-only token glued directly to a Korean word before `bearer` or `basic` (`값은bearer abcdefghijklmnop`) is not masked, because those two rules still use `\b`. Put such words in the exclusion file or the env file until a later version covers them.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

89 tests, no network: requests go to a loopback mock server or a replaced opener. They include the 52 adversarial cases (26 from each review: each input must be refused, or leave no fragment of the value, where a fragment is 7 digits for numbers and 6 characters otherwise), 19 controls that must come back unchanged (dates, versions, test results, ports, prices, model names, handles, file names), numbers and keys written against Korean letters, values next to labels, the example hook end to end (empty payload, missing key, 402, redirects, deadline, shadow and live output, your own names), session pins, file modes, log rotation and the wrapper's exit code. They run on Python 3.9 and on current Python 3.

## License

MIT

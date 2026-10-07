# Changelog

## 0.1.1 — 2026-10-07

Fixes from a pre-publication review.

- A number or key prefix written against a Korean letter is masked. The phone, ID, card, account and key-prefix rules check ASCII letters and digits at their edges instead of `\b`, which counts a Korean letter as a word character: a phone, resident registration or account number with a Korean particle attached went out unmasked.
- `leftover()` also checks phone, ID, card and account numbers (not email addresses). A rule whose replacement is a function counts only where it would mask, so ports, prices and dates still pass.
- 4-2-7 account numbers (3333-01-1234567) are masked. A leading date now needs month 01-12, day 01-31 and no digit right after the day.
- `refuse()` refuses an input that names a passphrase. Masking the first word left the rest of a multi-word passphrase in the text.
- README: lists exactly the words `refuse()` refuses; every setting the example reads (`JHG_ENDPOINT`, `JHG_STATE_DIR`, and the wrapper's `JHG_PYTHON` and `JHG_HOOK_PY` were missing); the kill switch creates its directory first; env-file values under 6 characters are not loaded and so never masked (Limits); `leftover()` covers numbers.
- Tests, 88: values next to labels that only `mask()` hides, `JHG_SELF_NAMES` through the example hook, a real socket timeout in a worker thread, the 7-digit / 6-character fragment rule on all 52 adversarial cases, numbers and keys against Korean letters, 4-2-7 accounts, passphrases.
- Test fixtures shaped like vendor tokens (GitHub, Google, npm, Anthropic, Slack) are assembled at import time, so no tracked file holds such a token as one literal.

## 0.1.0 — 2026-10-07

- First release. One module, `jev_hook_guard.py`: `normalize`, `load_env_values`, `mask`, `refuse`, `leftover`, `Exclude`, `SessionPins`, `endpoint_ok`, `post_json`, `classify_error`, `ensure_private_dir`, `append_jsonl`.
- `hooks/example_prompt_hook.py` (a `UserPromptSubmit` hook that asks Jev one question, shadow mode by default), `hooks/wrapper.sh` (always exits 0, logs a non-zero Python exit), `hooks/settings.snippet.json`, `examples/exclude.txt`.
- 80 tests, including the 52 adversarial cases from two independent reviews and 19 over-masking controls.

#!/usr/bin/env bash
# Exit-0 wrapper for a Python hook. Register this file in settings.json, not the .py file.
#
# Why: Claude Code reads exit code 2 from a hook as "block". On UserPromptSubmit that blocks the prompt and erases it;
# on Stop it forces the session to keep going. When the .py file is missing or unreadable, python3 itself exits with 2,
# so a moved file would block every prompt in every session (and a kill-switch file is never read, because Python
# never starts). This wrapper always exits 0 and writes one line to error.log whenever Python did not exit 0.
# Standard output (the hook's text for the session) passes through unchanged. If this wrapper itself is missing, the
# shell exits with 127, which Claude Code treats as a non-blocking error.
#
# umask 077: every log, pin and directory the hook creates is readable by you only.
# /usr/bin/python3 -I: isolated mode, so a json.py or re.py in the session's working directory cannot replace the
# standard library, and PYTHON* variables are ignored. JHG_PYTHON overrides the interpreter path.
umask 077
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${JHG_HOOK_PY:-$HERE/example_prompt_hook.py}"
"${JHG_PYTHON:-/usr/bin/python3}" -I "$PY" "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
    d="${JHG_STATE_DIR:-$HOME/.jev-hook-guard}"
    if ! { mkdir -p "$d" && printf '%s\twrapper python rc=%d\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$rc" >> "$d/error.log"; }; then
        echo "jev-hook-guard wrapper: python rc=$rc, and error.log is not writable" >&2
    fi
fi
exit 0

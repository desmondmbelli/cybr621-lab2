# CYB 621 Lab 2 — AI Code Review and Memory-Safety Validation

## Prediction (written before generating Assistant 2)
<Replace with your one-sentence prediction>

## Generation details
| File | AI agent | Prompt |
|---|---|---|
| assistant1.c | OpenAI Codex | Basic prompt |
| assistant2.c | Claude Code | Secure prompt |

## Notes
- The Codex output for assistant1.c was copied without its final closing brace `}`. Only that brace was added so the file would compile; no other changes were made before testing. `originals/` preserves the raw pasted files.
- Environment: GitHub Codespaces, GCC 13.3.0, Semgrep 1.179.0, CodeQL CLI 2.27.1.
- The course Codespace was not accessible, so this lab was completed in a personal Codespace (repo: cybr621-lab2).

## Remediation (assistant1.c)
1. Replaced fopen() with open(..., S_IRUSR|S_IWUSR) + fdopen() so the log is created 0600.
2. Rejected CR/LF in username and message to block log injection.
- localtime_r() remediation (Part 8B) not applicable: neither program calls localtime().

## Results summary
- CodeQL: 1 finding before (cpp/world-writable-file-creation, assistant1.c:8), 0 after.
- Semgrep (auto + custom): 0 findings before and after.
- userlog.txt permissions: 666 before (default ACL overrides umask 0022), 600 after.

## Reflection answers
<To be added>

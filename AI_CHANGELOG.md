# AI Change Log

This file records work performed by AI assistants in this repository, including
documentation-only work. Update it in the same task as each AI-made change.

## What to record

For every task, add the date and a short summary. List every file the AI changed
and describe what changed and why. Record errors found while investigating or
validating the work, how each error was resolved, and the checks run afterward.
If no errors were found, say so. If a check was not run or a result is unknown,
state that instead of implying it passed.

Do not attribute pre-existing worktree changes to an AI assistant unless their
authorship is known. Keep uncertain history clearly marked as unverified.

## Entries

### 2026-10-14 - Add AI change documentation

- **Summary:** Created this log and established a practice for recording AI
  changes, errors, resolutions, and validation results.
- **Files changed by AI:** `AI_CHANGELOG.md` (created).
- **Errors found:** None during this documentation task.
- **Resolution:** No errors needed resolution.
- **Validation:** Documentation-only change; no tests or build were run.
- **Pre-existing worktree changes (not attributed to this task):**
  - `frontend/src/App.tsx` already had uncommitted changes removing the default
    React import and using relative `/api/scan` and `/api/sever` request URLs.
  - `frontend/vite.config.ts` already had an uncommitted `/api` proxy to
    `http://localhost:8000`.
  - The author, reason, related errors, and whether these changes were tested
    are unknown; they are not recorded as AI-made fixes.

## Entry template

Copy this section for each future AI task and fill in every field:

### YYYY-MM-DD - Short task title

- **Summary:**
- **Files changed by AI:**
  - `path/to/file` - change made and reason.
- **Errors found:** Describe the error, where it appeared, and how it was
  reproduced; write "None" if none were found.
- **Resolution:** Explain the fix for each error, or write "No errors needed
  resolution."
- **Validation:** List commands/checks and their outcomes; clearly mark checks
  that were not run.
- **Unresolved items or limitations:** Write "None" if there are none.

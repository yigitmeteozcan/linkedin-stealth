[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# stealth-watch

Track when LinkedIn people go stealth or change positions. VC deal scourcing. Runs free on GitHub Actions. No API keys. No servers.

---

## How it works

- Reads a list of LinkedIn profiles from `profiles.csv`
- Queries Google for each profile's current title and snippet (never touches LinkedIn directly)
- Flags changes that match stealth startup patterns: founder keywords, blank titles after senior roles, etc.
- Writes findings to `results.md` and commits them automatically every 48 hours

---

## Quick start

1. **Fork** this repo
2. **Edit** `profiles.csv` — add the people you want to watch
3. **Done** — GitHub Actions runs every 48 hours and updates `results.md`

To trigger a run immediately: Actions → Stealth Watch → Run workflow.

---

## Run locally

```bash
pip install -r requirements.txt
python tracker.py
```

Results are written to `results.md` and `state.json`.

---

## How stealth detection works

A profile is flagged as **STEALTH** if any of the following is true:

1. The current title or snippet contains a stealth keyword (`founder`, `building`, `new venture`, `kurucu`, etc.)
2. The title went blank or passive (`open to work`, `between roles`, etc.) AND the previous title was senior-level (`Director`, `VP`, `Head of`, `CTO`, etc.)

**Confidence levels:**
- `high` — stealth keyword found directly in the title
- `medium` — title went blank and person was previously senior
- `low` — keyword found in snippet only

---

## results.md example

```
# Stealth Watch
*Last run: 2026-05-25 09:00 UTC — 50 profiles monitored*

## Stealth Signals
| Name | Was | Now | Confidence | LinkedIn | Detected | Notes |
|------|-----|-----|------------|----------|----------|-------|
| John Smith | Engineering Director @ Stripe | [blank] | medium | [profile](…) | 2026-05-25 | ex-Stripe EM |

## Recent Job Changes
| Name | Was | Now | LinkedIn | Since |
|------|-----|-----|----------|-------|

## Active & Unchanged
*47 profiles verified unchanged as of last run.*

## Failed Scrapes
*No failed scrapes.*
```

---

## Privacy note

stealth-watch reads **public** Google search cache of **public** LinkedIn data.
Keep your `profiles.csv` private — it reveals who you are watching.
Do not commit it to a public fork.

> **Warning — `state.json` contains your watchlist data.**
> It stores every person's name, job title history, and change timestamps.
> It is excluded from git via `.gitignore` and persisted only in GitHub Actions
> cache between runs. **Never commit `state.json` to a public repository.**
> If you run locally, keep `state.json` out of version control.

---

## Run tests

```bash
python -m unittest discover tests
```

---

MIT License — see [LICENSE](LICENSE)

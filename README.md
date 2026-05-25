[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# stealth-watch

LinkedIn job change tracker for VC deal sourcing. Runs automatically every 2 weeks via GitHub Actions.

---

## Requirements

Requires an Enrichlayer API key (~$4/month for 200 profiles checked twice a month).
Get yours at [enrichlayer.com](https://enrichlayer.com).

Enrichlayer gives free credits on signup to cover your first month.

---

## Setup

1. **Fork** this repo
2. **Get an API key** at [enrichlayer.com](https://enrichlayer.com)
3. **Add it to GitHub repo secrets** as `ENRICHLAYER_API_KEY`
   (Settings → Secrets and variables → Actions → New secret)
4. **Edit** `profiles.csv` with the people you want to track
5. **GitHub Actions runs automatically** on the 1st and 15th of every month
6. **Check `results.md`** for findings

---

## How it works

- Reads a list of LinkedIn profiles from `profiles.csv`
- Calls the Enrichlayer API for each profile's current occupation and headline
- Flags changes that match stealth startup patterns: founder keywords, blank titles after senior roles, etc.
- Writes findings to `results.md` and commits automatically

---

## Cost

200 profiles × 2 runs/month × $0.01 = **~$4/month**

Enrichlayer gives free credits on signup to cover your first month.

---

## Run locally

```bash
cp .env.example .env
# Add your ENRICHLAYER_API_KEY to .env
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

Keep your `profiles.csv` private — it reveals who you are watching.
Do not commit it to a public fork.

> **Warning — `state.json` contains your watchlist data.**
> It stores every person's name, job title history, and change timestamps.
> It is excluded from git via `.gitignore`.
> **Never commit `state.json` to a public repository.**

---

## Run tests

```bash
python -m unittest discover tests
```

---

MIT License — see [LICENSE](LICENSE)

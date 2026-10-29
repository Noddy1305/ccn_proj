# Instructions for AI coding agents (Codex, Cursor, Copilot, etc.)

Start with `README.md` (project status, architecture, module contract, gotchas), then follow the rules in
`CLAUDE.md` and the requirements in `PRD.md`. In short:

- The code decides the verdict (M6, `modules/scoring.py`); an LLM only adds a capped signal and writes text.
- Every check returns the dict shape in README section 4 and never raises. Points live in `config.yaml`.
- Use the virtual environment in `phishguard/venv`; run `python -m pytest -q` from `phishguard/`. Tests must not use the network.
- Build only the session you are asked for, then stop. After each session write `notes/sessionN.md` per `CLAUDE.md`.
- Never commit `.env`, API keys, `venv/` or `chk/`.

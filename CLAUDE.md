# PhishGuard-AI — Project Rules

## Notes rules
After every session, write notes/sessionN.md (N = session number) for
two students who are complete beginners in networking and security.
They must understand it well enough to explain it in a viva without
looking. Write it like a patient teacher, in simple English:

1. The big picture: what this session added, in 2-3 sentences, and
   where it sits in the whole PhishGuard-AI flow.
2. New terms: every technical word used (e.g. SPF, DNS, header), with
   its full form and a one-line meaning in plain words.
3. How it works: explain each new feature step by step, starting with
   a real-life analogy (post office, envelope, ID card, etc.), then
   what actually happens, then why it matters for catching phishing.
4. Walk-through example: follow one sample email through the new code
   and show what comes out at each step.
5. Files: each new file, what it does in one or two lines, and which
   function to point at if an examiner asks "show me where".
6. Viva questions: 8-10 questions an examiner is likely to ask about
   this session, each with a short answer (2-3 sentences) we can
   memorise.
7. Remember this: 3-5 one-line key points to revise before the review.

No code dumps in the notes. Short paragraphs. If something is
complicated, explain it twice in different ways.

## Build rules
- Build in the 8 sessions listed in PRD.md section 11; do only the session asked for.
- Follow the folder structure in PRD.md section 8 and requirements in section 5.
- Use a Python virtual environment (venv).
- When a session is done, tell the user how to run it and what they should see, then stop.

## LLM (M5, M7) — from session 4 onward
- Main provider: NVIDIA Nemotron API, key read from env var `LLM_API_KEY`.
- Offline fallback: Ollama with a small local model.
- Switchable in config.yaml.

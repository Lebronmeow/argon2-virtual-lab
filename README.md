# Argon2 Virtual Lab

An interactive, IIT-Virtual-Labs-style experiment on **Argon2** — the memory-hard
password hashing function (winner of the Password Hashing Competition, standardised
in RFC 9106).

Fully static — no backend, no build step.

## Run

```bash
python -m http.server 8000
```

Open http://localhost:8000.

## Pages

Introduction → Theory → Objective → Procedure → Simulation → Demonstrations →
Assignment → References → Feedback (classic Virtual Labs structure).

The Simulation and Demonstrations run **real Argon2id/i/d in your browser** via the
[hash-wasm](https://github.com/Daninet/hash-wasm) WebAssembly library (loaded from a
CDN — internet needed for hashing; everything else works offline).

- **Hasher** — password + salt + cost parameters (m, t, p) → PHC string
- **Verify** — paste a PHC string, test the login flow
- **Memory Grid** — animated memory-fill with data-dependent vs data-independent addressing
- **Benchmark** — Argon2id vs PBKDF2, live timings
- **Demos** — salt vs rainbow tables, cost-parameter trade-offs, hardware-cost economics

Educational use only.

# tuneup

A weekly self-improvement loop for a personal AI agent's own tools.

An agent's toolbox rots silently: thresholds drift, prompts go stale, nobody
notices until something fails. tuneup makes the toolbox compound instead of
decay. Once a week it picks one tool from a declared roster, replays the
tool's own real past runs as evaluation cases, and proposes rewrites —
threshold changes, prompt changes, memory-note changes — keeping only the
ones that measurably improve on **held-out** cases, behind honesty gates
borrowed from Google's RRSI work (leakage critic, noise floor, cost rule,
pruning). Or it honestly reports "no improvement found," with what was
tried. Every step lands in an append-only changelog.

The one hard rule: **an agent can never approve its own proposals.**
`tuneup review --approve` only runs on an interactive terminal (a human at a
keyboard). There is no `--yes` flag and no environment override, by design.
Rejection is always allowed; approval is a human act.

## Install

Requires Python 3.12+ (stdlib only — no dependencies).

```bash
git clone https://github.com/wally-dk24/tuneup
cd tuneup
./tuneup.py init        # creates ~/.tuneup (override with TUNEUP_HOME)
```

Or via Docker (multi-arch: amd64, arm64, 386):

```bash
docker run --rm -v ~/.tuneup:/home/tuneup/.tuneup wallydk24/tuneup:latest changelog
```

## The loop

```bash
tuneup roster                  # tools under improvement; `tuneup next` picks this week's
tuneup cases --tool my-watch   # build train/held-out from real past runs; held-out is SEALED
# ... the agent studies the train set (printed) and proposes rewrites ...
tuneup propose --tool my-watch --name p1 --set alert_on_failed_streak=2 --note "why"
tuneup eval --tool my-watch    # replay on sealed held-out; honesty gates decide
tuneup review --tool my-watch  # diffs + per-case before/after scores
tuneup review --tool my-watch --approve p1   # human, on a TTY, only
tuneup apply --tool my-watch   # write the approved rewrite to the real config
tuneup changelog               # everything that ever happened, append-only
```

`tuneup run --tool my-watch` is shorthand: it opens a cycle and scores the
baseline, then tells the agent what to do next.

## Honesty gates

1. **Leakage critic.** The held-out set is sealed (mode 600, sha256 recorded)
   before any proposal exists. The proposer only ever sees the train set —
   enforced by construction, not by promise. Eval re-checks that no held-out
   content leaked into a proposal, and refuses to score a cycle whose seal
   was tampered with.
2. **Noise floor.** An improvement must beat the baseline by a declared
   margin (`noise_margin_cases`), not by one lucky case.
3. **Cost rule.** A run aborts before replaying anything if the evaluation
   would exceed the declared op budget (`max_eval_ops`).
4. **Pruning.** Any rewrite that regresses a previously-passing case is
   dropped, however good its totals look.

**Protected files.** tuneup refuses to rewrite anything matching the
deny-list (`*api_key*`, `*credential*`, `*secret*`, `*token*`,
`*password*`, `*.pem`, …) — both as proposal keys and as config paths.

## Tool kinds

0.1.0 ships one adapter:

- **quietwatch-policy** — the silence-contract alert rule for a quietwatch
  watch. Cases are per-run decision points from the watch's own run log
  (the true online semantics); labels come from an incidents file written
  before any proposal exists. Rewrites are threshold changes, applied to the
  real policy file on approval.

New kinds (prompt templates, decision flows) plug in as adapter classes.

## Design notes

- "No improvement found" is a successful outcome, logged with what was
  tried — not an error.
- Held-out labels are written before proposals exist, with their basis
  recorded, so the ground truth can't be fitted to the rewrite.
- The changelog is JSONL append-only; tuneup never rewrites history.
- Single file, stdlib only, auditable in one sitting.

## License

MIT.

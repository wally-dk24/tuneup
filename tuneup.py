#!/usr/bin/env python3
"""tuneup 0.1.0 -- a weekly self-improvement loop for a personal agent's tools.

One tool per week gets measurably better, or the run honestly reports
"no improvement found". Rewrites are proposed by the agent, then evaluated
against HELD-OUT cases built from the tool's own real past runs, behind
honesty gates borrowed from Google's RRSI work:

  1. leakage critic -- held-out cases are sealed before any proposal exists;
     the proposer only ever sees the train set (enforced by construction),
     and eval re-checks that no held-out content leaked into a proposal.
  2. noise floor -- an improvement must beat the baseline by a declared
     margin, not by one lucky case.
  3. cost rule -- a run aborts past a declared evaluation budget.
  4. pruning -- any rewrite that regresses a previously-passing case is
     dropped, no matter how good its totals look.

A human approves surviving rewrites on an interactive terminal
(`tuneup review --approve`); piped approval is refused, so an agent can
never approve its own proposals. Every step appends to an append-only
changelog. Files matching the protected deny-list (credentials, keys,
secrets) can never be rewritten.

Stdlib only. State lives in TUNEUP_HOME (default ~/.tuneup).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

VERSION = "0.1.0"

DEFAULT_DENY = [
    "*api_key*", "*apikey*", "*credential*", "*secret*", "*token*",
    "*password*", "*.pem", "*.key", "*private*",
]

MAX_PROPOSALS_PER_CYCLE = 3


def home() -> str:
    return os.environ.get("TUNEUP_HOME", os.path.expanduser("~/.tuneup"))


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def read_json(path: str, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, obj, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def changelog_path() -> str:
    return os.path.join(home(), "changelog.jsonl")


def log_event(event: str, **fields) -> dict:
    """Append-only changelog. Never rewrites history."""
    entry = {"ts": utcnow(), "event": event}
    entry.update(fields)
    os.makedirs(home(), exist_ok=True)
    with open(changelog_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def roster_path() -> str:
    return os.path.join(home(), "roster.json")


def load_roster() -> dict:
    r = read_json(roster_path())
    if r is None:
        die("no roster: run `tuneup init` first")
    return r


def save_roster(r: dict) -> None:
    write_json(roster_path(), r)


def get_tool(name: str) -> dict:
    r = load_roster()
    tools = r.get("tools", {})
    if name not in tools:
        die(f"unknown tool {name!r}; `tuneup roster` lists registered tools")
    return tools[name]


def denied(path_or_key: str, patterns) -> str | None:
    base = os.path.basename(path_or_key)
    for pat in patterns:
        if fnmatch.fnmatch(path_or_key, pat) or fnmatch.fnmatch(base, pat):
            return pat
    return None


def die(msg: str, code: int = 1):
    print(f"tuneup: error: {msg}", file=sys.stderr)
    sys.exit(code)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------
# Tool adapters. Each kind knows how to build cases from real past runs,
# evaluate a policy against a case, and apply an approved rewrite.
# --------------------------------------------------------------------------

class QuietwatchPolicy:
    """Adapter for a quietwatch silence-contract policy.

    The tool under test is the alert rule for one watch: at each run
    (a decision point), given the trailing K run records, decide "alert"
    or "silent". Cases are decision points built from the watch's own
    real run log -- the true online semantics of the policy. Labels come
    from an incidents file written BEFORE any proposal exists: a decision
    point is "alert" only if a genuine incident was active then; transient
    blips the system itself rode out silently are labeled "silent", with
    the basis recorded.
    """

    THRESHOLD_KEYS = ("alert_on_failed_streak", "missed_after_mult")

    @staticmethod
    def baseline(cfg: dict) -> dict:
        policy = read_json(cfg["config_path"], {})
        entry = policy.get(cfg["config_key"], {})
        return {
            "alert_on_failed_streak": int(entry.get("alert_on_failed_streak", 1)),
            "missed_after_mult": int(entry.get("missed_after_mult", 2)),
        }

    @staticmethod
    def decide(policy: dict, interval_min: float, window: list) -> str:
        streak = 0
        for rec in reversed(window):
            if rec.get("status") == "failed":
                streak += 1
            else:
                break
        if streak >= policy["alert_on_failed_streak"]:
            return "alert"
        tss = [parse_ts(r["ts"]) for r in window]
        gaps = [(tss[i + 1] - tss[i]).total_seconds() / 60.0
                for i in range(len(tss) - 1)]
        if gaps and max(gaps) > interval_min * policy["missed_after_mult"]:
            return "alert"
        return "silent"

    @staticmethod
    def build_cases(cfg: dict):
        runs = []
        with open(cfg["runs_log"], encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    runs.append(json.loads(line))
        runs.sort(key=lambda r: r["ts"])
        if cfg.get("history_from"):
            cutoff = parse_ts(cfg["history_from"])
            runs = [r for r in runs if parse_ts(r["ts"]) >= cutoff]
        k = int(cfg.get("window_size", 5))
        incidents = read_json(cfg["incidents_file"], []) or []

        def label(ts):
            for inc in incidents:
                if inc.get("severity") != "genuine":
                    continue
                if parse_ts(inc["start"]) <= ts <= parse_ts(inc["end"]):
                    return "alert", inc.get("note", "")
            return "silent", "no genuine incident at this decision point"

        cases = []
        for i in range(k - 1, len(runs)):
            window = runs[i - k + 1:i + 1]
            point_ts = parse_ts(window[-1]["ts"])
            lab, basis = label(point_ts)
            streak = 0
            for r in reversed(window):
                if r.get("status") == "failed":
                    streak += 1
                else:
                    break
            cases.append({
                "case_id": f"{cfg['name']}-d{i:04d}",
                "decision_ts": window[-1]["ts"],
                "trailing_failed": streak,
                "max_gap_min": round(max(
                    (parse_ts(window[j + 1]["ts"]) - parse_ts(window[j]["ts"])
                     ).total_seconds() / 60.0 for j in range(k - 1)), 2),
                "label": lab,
                "label_basis": basis,
                "window": window,
            })
        return cases

    @staticmethod
    def apply_changes(cfg: dict, changes: dict) -> dict:
        hit = denied(cfg["config_path"], cfg.get("protected", DEFAULT_DENY))
        if hit:
            die(f"refusing: config path matches protected pattern {hit!r}")
        policy = read_json(cfg["config_path"], {})
        entry = policy.setdefault(cfg["config_key"], {})
        before = {k: entry.get(k) for k in changes}
        entry.update(changes)
        write_json(cfg["config_path"], policy)
        return before


KINDS = {"quietwatch-policy": QuietwatchPolicy}


def adapter_for(cfg: dict):
    kind = cfg.get("kind")
    if kind not in KINDS:
        die(f"unsupported tool kind {kind!r}")
    return KINDS[kind]


# --------------------------------------------------------------------------
# Cycle state
# --------------------------------------------------------------------------

def cycle_dir(tool: str, cycle: str) -> str:
    return os.path.join(home(), "cycles", tool, cycle)


def sealed_path(tool: str, cycle: str) -> str:
    return os.path.join(home(), "sealed", tool, cycle + ".json")


def latest_cycle(tool: str) -> str | None:
    d = os.path.join(home(), "cycles", tool)
    if not os.path.isdir(d):
        return None
    cycles = sorted(os.listdir(d))
    return cycles[-1] if cycles else None


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def default_tool_cfg() -> dict:
    h = os.path.expanduser("~")
    return {
        "qw-inbound-policy": {
            "kind": "quietwatch-policy",
            "desc": "Silence-contract alert thresholds for the inbound-text-check watch",
            "config_path": os.path.join(h, ".quietwatch", "policy.json"),
            "config_key": "inbound-text-check",
            "runs_log": os.path.join(h, ".quietwatch", "runs", "inbound-text-check.jsonl"),
            "incidents_file": os.path.join(home(), "tools", "qw-inbound-policy", "incidents.json"),
            "window_size": 5,
            "held_out_windows": 70,
            "noise_margin_cases": 2,
            "max_eval_ops": 5000,
            "check_interval_minutes": 2,
            "history_from": "2026-10-05T15:00:00+00:00",
            "protected": DEFAULT_DENY,
            "last_cycle": None,
        }
    }


def cmd_init(args) -> None:
    os.makedirs(os.path.join(home(), "sealed"), exist_ok=True)
    os.makedirs(os.path.join(home(), "cycles"), exist_ok=True)
    os.makedirs(os.path.join(home(), "tools", "qw-inbound-policy"), exist_ok=True)
    if not os.path.exists(roster_path()):
        save_roster({"tools": default_tool_cfg()})
    if not os.path.exists(changelog_path()):
        open(changelog_path(), "a").close()
    inc_path = os.path.join(home(), "tools", "qw-inbound-policy", "incidents.json")
    if not os.path.exists(inc_path):
        write_json(inc_path, [
            {
                "start": "2026-10-06T02:11:08+00:00",
                "end": "2026-10-06T02:13:00+00:00",
                "severity": "transient",
                "note": "Twilio API connectivity failure on one run; next run ok; "
                        "no alert sent (correct per silence contract)",
                "source": "memory/2026-10-05.md, 22:11 EDT inbound-text-check run",
            }
        ])
    log_event("init", version=VERSION)
    print(f"tuneup {VERSION} initialized at {home()}")


def cmd_roster(args) -> None:
    r = load_roster()
    for name, cfg in r.get("tools", {}).items():
        print(f"{name}  [{cfg.get('kind')}]  last_cycle={cfg.get('last_cycle')}")
        print(f"    {cfg.get('desc', '')}")


def cmd_next(args) -> None:
    r = load_roster()
    tools = r.get("tools", {})
    if not tools:
        die("roster is empty")
    pick = min(tools.items(), key=lambda kv: (kv[1].get("last_cycle") or "", kv[0]))
    print(pick[0])


def open_cycle(tool_name: str, cfg: dict) -> tuple[str, list, list]:
    adapter = adapter_for(cfg)
    cases = adapter.build_cases({**cfg, "name": tool_name})
    if not cases:
        die("no cases built: runs log empty or unreadable")
    n_held = min(int(cfg.get("held_out_windows", 10)), len(cases) - 1)
    train, heldout = cases[:len(cases) - n_held], cases[len(cases) - n_held:]
    cycle = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    cdir = cycle_dir(tool_name, cycle)
    os.makedirs(cdir, exist_ok=True)
    # Seal the held-out set BEFORE any proposal can exist. Mode 600.
    spath = sealed_path(tool_name, cycle)
    write_json(spath, {"tool": tool_name, "cycle": cycle, "cases": heldout}, mode=0o600)
    seal_sha = sha256_file(spath)
    write_json(os.path.join(cdir, "train.json"), train)
    write_json(os.path.join(cdir, "meta.json"), {
        "tool": tool_name, "cycle": cycle, "kind": cfg.get("kind"),
        "n_train": len(train), "n_heldout": len(heldout),
        "sealed_sha256": seal_sha, "sealed_path": spath,
    })
    write_json(os.path.join(cdir, "proposals.json"), {})
    r = load_roster()
    r["tools"][tool_name]["last_cycle"] = cycle
    save_roster(r)
    log_event("cycle_opened", tool=tool_name, cycle=cycle,
              n_train=len(train), n_heldout=len(heldout), sealed_sha256=seal_sha)
    return cycle, train, heldout

def cmd_cases(args) -> None:
    cfg = get_tool(args.tool)
    cycle, train, heldout = open_cycle(args.tool, cfg)
    print(f"cycle {cycle} opened for tool {args.tool!r}")
    print(f"train cases: {len(train)} (shown below -- the proposer may use these)")
    print(f"held-out cases: {len(heldout)} (SEALED -- never shown to the proposer)")
    print()
    for c in train:
        print(json.dumps({k: c[k] for k in
                           ("case_id", "decision_ts", "trailing_failed",
                            "max_gap_min", "label", "label_basis")}, sort_keys=True))


def coerce_value(s: str):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def cmd_propose(args) -> None:
    cfg = get_tool(args.tool)
    cycle = latest_cycle(args.tool)
    if not cycle:
        die("no open cycle: run `tuneup cases --tool` first")
    cdir = cycle_dir(args.tool, cycle)
    proposals = read_json(os.path.join(cdir, "proposals.json"), {})
    if args.name in proposals:
        die(f"proposal {args.name!r} already registered this cycle")
    if len(proposals) >= MAX_PROPOSALS_PER_CYCLE:
        die(f"at most {MAX_PROPOSALS_PER_CYCLE} proposals per cycle")
    adapter = adapter_for(cfg)
    baseline = adapter.baseline(cfg)
    changes = {}
    for item in args.set:
        if "=" not in item:
            die(f"bad --set {item!r}: expected key=value")
        k, v = item.split("=", 1)
        k, v = k.strip(), v.strip()
        hit = denied(k, cfg.get("protected", DEFAULT_DENY))
        if hit:
            log_event("proposal_rejected", tool=args.tool, cycle=cycle,
                      name=args.name, reason=f"protected key pattern {hit}")
            die(f"refusing: proposed key {k!r} matches protected pattern {hit!r}")
        if k not in baseline:
            die(f"unknown threshold {k!r}; baseline keys: {sorted(baseline)}")
        val = coerce_value(v)
        if not isinstance(val, (int, float)) or isinstance(val, bool):
            die(f"threshold {k!r} must be numeric, got {v!r}")
        changes[k] = val
    if not changes:
        die("no changes proposed")
    proposals[args.name] = {"changes": changes, "note": args.note or "",
                            "ts": utcnow()}
    write_json(os.path.join(cdir, "proposals.json"), proposals)
    log_event("proposed", tool=args.tool, cycle=cycle, name=args.name,
              changes=changes, note=args.note or "")
    print(f"proposal {args.name!r} registered: {changes}")


def evaluate_all(cfg, tool_name, cycle, proposals: dict):
    """Run baseline + proposals against the sealed held-out set.

    Returns (report, ops_used). Applies gates in order: cost rule,
    leakage critic, scoring, pruning, noise floor.
    """
    adapter = adapter_for(cfg)
    spath = sealed_path(tool_name, cycle)
    if not os.path.exists(spath):
        die("sealed held-out set missing; cycle is corrupt")
    meta = read_json(os.path.join(cycle_dir(tool_name, cycle), "meta.json"), {})
    if sha256_file(spath) != meta.get("sealed_sha256"):
        log_event("seal_tampered", tool=tool_name, cycle=cycle)
        die("refusing: sealed held-out set was modified after sealing")
    sealed = read_json(spath)
    heldout = sealed["cases"]
    interval = float(cfg.get("check_interval_minutes", 2))

    ops_budget = int(cfg.get("max_eval_ops", 5000))
    ops_needed = len(heldout) * (1 + len(proposals))
    report = {"tool": tool_name, "cycle": cycle, "ts": utcnow(),
              "n_heldout": len(heldout), "ops_needed": ops_needed,
              "ops_budget": ops_budget, "gates": {}, "results": {}}
    # Gate 3 (cost rule) is checked before any replay happens.
    if ops_needed > ops_budget:
        report["gates"]["cost_rule"] = {
            "passed": False,
            "reason": f"needed {ops_needed} eval ops > budget {ops_budget}; aborted",
        }
        log_event("evaluated", tool=tool_name, cycle=cycle,
                  cost_rule="aborted", ops_needed=ops_needed, ops_budget=ops_budget)
        return report, ops_needed

    # Gate 1: leakage critic -- no held-out content may appear in a proposal.
    heldout_text = json.dumps(heldout, sort_keys=True)
    leaked_markers = set()
    for c in heldout:
        leaked_markers.add(c["case_id"])
        leaked_markers.add(c["decision_ts"])
    critic = {}
    for name, p in proposals.items():
        ptext = json.dumps(p, sort_keys=True)
        hits = sorted(m for m in leaked_markers if m in ptext)
        critic[name] = {"passed": not hits, "hits": hits}
    report["gates"]["leakage_critic"] = critic

    baseline = adapter.baseline(cfg)

    def score(policy):
        per_case, errors, false_alerts, misses = [], 0, 0, 0
        for c in heldout:
            pred = adapter.decide(policy, interval, c["window"])
            ok = (pred == c["label"])
            if not ok:
                errors += 1
                if pred == "alert":
                    false_alerts += 1
                else:
                    misses += 1
            per_case.append({"case_id": c["case_id"], "label": c["label"],
                             "pred": pred, "ok": ok})
        return {"errors": errors, "false_alerts": false_alerts,
                "misses": misses, "per_case": per_case}

    base = score(baseline)
    report["results"]["__baseline__"] = {"policy": baseline, **base}

    margin = int(cfg.get("noise_margin_cases", 2))
    survivors = {}
    for name, p in proposals.items():
        if not critic[name]["passed"]:
            log_event("proposal_leaked", tool=tool_name, cycle=cycle, name=name,
                      hits=critic[name]["hits"])
            continue
        policy = dict(baseline)
        policy.update(p["changes"])
        res = score(policy)
        # Gate 4: pruning -- regressing any previously-passing case kills it.
        regressed = [a["case_id"] for a, b in
                     zip(res["per_case"], base["per_case"])
                     if b["ok"] and not a["ok"]]
        if regressed:
            log_event("pruned", tool=tool_name, cycle=cycle, name=name,
                      regressed=regressed)
            report["results"][name] = {
                "policy": policy, **res, "pruned": True, "regressed": regressed}
            continue
        improvement = base["errors"] - res["errors"]
        # Gate 2: noise floor.
        if improvement < margin:
            log_event("below_noise", tool=tool_name, cycle=cycle, name=name,
                      improvement=improvement, margin=margin)
            report["results"][name] = {
                "policy": policy, **res, "below_noise": True,
                "improvement": improvement, "margin": margin}
            continue
        survivors[name] = {"policy": policy, **res, "improvement": improvement}
        report["results"][name] = survivors[name]

    report["gates"]["cost_rule"] = {"passed": True}
    report["gates"]["noise_floor"] = {"margin_cases": margin}
    report["survivors"] = sorted(survivors)
    if not proposals:
        log_event("evaluated", tool=tool_name, cycle=cycle,
                  baseline_errors=base["errors"], note="no proposals")
    elif not survivors:
        log_event("no_improvement", tool=tool_name, cycle=cycle,
                  baseline_errors=base["errors"],
                  note="no proposal survived the honesty gates")
    else:
        log_event("evaluated", tool=tool_name, cycle=cycle,
                  baseline_errors=base["errors"], survivors=sorted(survivors))
    write_json(os.path.join(cycle_dir(tool_name, cycle), "eval.json"), report)
    return report, ops_needed


def cmd_eval(args) -> None:
    cfg = get_tool(args.tool)
    cycle = latest_cycle(args.tool)
    if not cycle:
        die("no open cycle: run `tuneup cases --tool` first")
    proposals = read_json(os.path.join(cycle_dir(args.tool, cycle), "proposals.json"), {})
    report, _ = evaluate_all(cfg, args.tool, cycle, proposals)
    base = report["results"]["__baseline__"]
    print(f"held-out cases: {report['n_heldout']}  "
          f"eval ops: {report['ops_needed']}/{report['ops_budget']}")
    print(f"baseline errors={base['errors']} "
          f"(false_alerts={base['false_alerts']}, misses={base['misses']})")
    if not proposals:
        print("no proposals registered; baseline scored only")
        return
    for name in proposals:
        r = report["results"].get(name)
        if r is None:
            print(f"  {name}: REJECTED by leakage critic")
        elif r.get("pruned"):
            print(f"  {name}: PRUNED (regressed {r['regressed']})")
        elif r.get("below_noise"):
            print(f"  {name}: below noise floor "
                  f"(improvement {r['improvement']} < margin {r['margin']})")
        else:
            print(f"  {name}: SURVIVES  errors={r['errors']} "
                  f"(false_alerts={r['false_alerts']}, misses={r['misses']}) "
                  f"improvement={r['improvement']}")


def cmd_run(args) -> None:
    """Open a cycle and score the baseline; the agent then proposes rewrites."""
    cfg = get_tool(args.tool)
    cycle, train, heldout = open_cycle(args.tool, cfg)
    report, _ = evaluate_all(cfg, args.tool, cycle, {})
    base = report["results"]["__baseline__"]
    print(f"cycle {cycle} opened for tool {args.tool!r}")
    print(f"train: {len(train)} cases (printed above by `tuneup cases`); "
          f"held-out: {len(heldout)} sealed")
    print(f"baseline on held-out: errors={base['errors']} "
          f"(false_alerts={base['false_alerts']}, misses={base['misses']})")
    print("next: study the train set, then `tuneup propose --tool "
          f"{args.tool} --name <id> --set key=value` (max "
          f"{MAX_PROPOSALS_PER_CYCLE} per cycle)")


def cmd_review(args) -> None:
    cfg = get_tool(args.tool)
    cycle = latest_cycle(args.tool)
    if not cycle:
        die("no open cycle")
    cdir = cycle_dir(args.tool, cycle)
    proposals = read_json(os.path.join(cdir, "proposals.json"), {})
    eval_path = os.path.join(cdir, "eval.json")
    report = read_json(eval_path)
    if not report:
        die("no eval yet: run `tuneup eval --tool` first")
    adapter = adapter_for(cfg)
    baseline = adapter.baseline(cfg)
    survivors = report.get("survivors", [])

    if args.approve or args.reject:
        name = args.approve or args.reject
        if name not in proposals:
            die(f"unknown proposal {name!r}")
        if name not in survivors and args.approve:
            die(f"cannot approve {name!r}: it did not survive the honesty gates")
        if args.approve:
            if not sys.stdin.isatty():
                die("refusing: approval requires an interactive terminal "
                    "(a human at a keyboard); piped approval is not allowed")
        decision = {"decision": "approved" if args.approve else "rejected",
                    "proposal": name, "ts": utcnow(),
                    "reason": args.reason or ""}
        if args.reject and not args.reason:
            die("--reject needs --reason")
        write_json(os.path.join(cdir, "decision.json"), decision)
        log_event("approved" if args.approve else "rejected",
                  tool=args.tool, cycle=cycle, name=name,
                  reason=args.reason or "")
        print(f"proposal {name!r} {decision['decision']}")
        return

    if not survivors:
        print("no surviving proposals: nothing to review "
              "(see `tuneup eval` for pruned / below-noise details)")
        return
    for name in survivors:
        p = proposals[name]
        r = report["results"][name]
        print(f"=== proposal {name} ===")
        if p.get("note"):
            print(f"note: {p['note']}")
        print("diff:")
        for k, new in p["changes"].items():
            print(f"  {k}: {baseline.get(k)} -> {new}")
        print(f"scores on {report['n_heldout']} held-out cases: "
              f"errors {report['results']['__baseline__']['errors']} -> {r['errors']} "
              f"(false_alerts {r['false_alerts']}, misses {r['misses']})")
        print("per-case (baseline -> proposal):")
        bmap = {b["case_id"]: b for b in report["results"]["__baseline__"]["per_case"]}
        for c in r["per_case"]:
            b = bmap[c["case_id"]]
            mark = " " if b["pred"] == c["pred"] else "*"
            print(f" {mark} {c['case_id']}: label={c['label']} "
                  f"{b['pred']} -> {c['pred']}")
        print()


def cmd_apply(args) -> None:
    cfg = get_tool(args.tool)
    cycle = latest_cycle(args.tool)
    if not cycle:
        die("no open cycle")
    cdir = cycle_dir(args.tool, cycle)
    decision = read_json(os.path.join(cdir, "decision.json"))
    if not decision or decision.get("decision") != "approved":
        die("nothing approved: run `tuneup review --tool ... --approve` first")
    proposals = read_json(os.path.join(cdir, "proposals.json"), {})
    name = decision["proposal"]
    changes = proposals[name]["changes"]
    adapter = adapter_for(cfg)
    before = adapter.apply_changes(cfg, changes)
    log_event("applied", tool=args.tool, cycle=cycle, name=name,
              before=before, after=changes,
              config_path=cfg["config_path"])
    print(f"applied {name!r} to {cfg['config_path']}:")
    for k in changes:
        print(f"  {k}: {before.get(k)} -> {changes[k]}")


def cmd_changelog(args) -> None:
    if not os.path.exists(changelog_path()):
        die("no changelog yet: run `tuneup init` first")
    with open(changelog_path(), encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if args.tool and e.get("tool") != args.tool:
                continue
            print(f"{e['ts']}  {e['event']}" +
                  (f"  tool={e['tool']}" if e.get("tool") else "") +
                  (f"  cycle={e['cycle']}" if e.get("cycle") else "") +
                  (f"  name={e['name']}" if e.get("name") else ""))

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tuneup",
        description="Weekly self-improvement loop for a personal agent's tools.")
    p.add_argument("--version", action="version", version=f"tuneup {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="create ~/.tuneup (or $TUNEUP_HOME)")
    i.set_defaults(func=cmd_init)

    r = sub.add_parser("roster", help="list registered tools")
    r.set_defaults(func=cmd_roster)

    n = sub.add_parser("next", help="which tool is due this week (rotation)")
    n.set_defaults(func=cmd_next)

    c = sub.add_parser("cases", help="build train/held-out cases; seal held-out")
    c.add_argument("--tool", required=True)
    c.set_defaults(func=cmd_cases)

    pr = sub.add_parser("propose", help="register a rewrite proposal (train only)")
    pr.add_argument("--tool", required=True)
    pr.add_argument("--name", required=True, help="proposal id, e.g. p1")
    pr.add_argument("--set", action="append", default=[],
                    help="key=value threshold change (repeatable)")
    pr.add_argument("--note", default="", help="why this rewrite might help")
    pr.set_defaults(func=cmd_propose)

    e = sub.add_parser("eval", help="replay baseline + proposals on sealed held-out")
    e.add_argument("--tool", required=True)
    e.set_defaults(func=cmd_eval)

    run = sub.add_parser("run", help="open a cycle and score the baseline")
    run.add_argument("--tool", required=True)
    run.set_defaults(func=cmd_run)

    rev = sub.add_parser("review", help="show diffs/scores; approve or reject")
    rev.add_argument("--tool", required=True)
    rev.add_argument("--approve", default=None, metavar="NAME")
    rev.add_argument("--reject", default=None, metavar="NAME")
    rev.add_argument("--reason", default="")
    rev.set_defaults(func=cmd_review)

    a = sub.add_parser("apply", help="write the approved rewrite to the real config")
    a.add_argument("--tool", required=True)
    a.set_defaults(func=cmd_apply)

    cl = sub.add_parser("changelog", help="show the append-only changelog")
    cl.add_argument("--tool", default=None)
    cl.set_defaults(func=cmd_changelog)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

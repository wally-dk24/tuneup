#!/usr/bin/env python3
"""tuneup test suite — stdlib unittest. Exercises the honesty machinery."""
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tuneup


def make_runs_log(path, n_runs=20, failed_at=(17,), gap_min=2.0):
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    with open(path, "w", encoding="utf-8") as f:
        for i in range(n_runs):
            ts = start + timedelta(minutes=i * gap_min)
            status = "failed" if i in failed_at else "ok"
            f.write(json.dumps({"ts": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                                "status": status}) + "\n")


def make_cfg(tmp, name="t1", failed_at=(17,), **over):
    cfg_path = os.path.join(tmp, "policy.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({"t1": {"alert_on_failed_streak": 1, "missed_after_mult": 2}}, f)
    runs_log = os.path.join(tmp, "runs.jsonl")
    make_runs_log(runs_log, failed_at=failed_at)
    inc = os.path.join(tmp, "incidents.json")
    with open(inc, "w", encoding="utf-8") as f:
        json.dump([], f)
    cfg = {
        "kind": "quietwatch-policy",
        "desc": "test tool",
        "config_path": cfg_path,
        "config_key": "t1",
        "runs_log": runs_log,
        "incidents_file": inc,
        "window_size": 5,
        "held_out_windows": 2,
        "noise_margin_cases": 2,
        "max_eval_ops": 5000,
        "check_interval_minutes": 2,
        "protected": tuneup.DEFAULT_DENY,
        "last_cycle": None,
        "name": name,
    }
    cfg.update(over)
    return cfg


class TuneupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["TUNEUP_HOME"] = os.path.join(self.tmp, "tuneup-home")
        # reload home-dependent state: tuneup.home() reads env each call
        tuneup.cmd_init(argparse_ns())

    def open_cycle(self, **over):
        cfg = make_cfg(self.tmp, **over)
        r = tuneup.load_roster()
        r["tools"]["t1"] = cfg
        tuneup.save_roster(r)
        cycle, train, heldout = tuneup.open_cycle("t1", cfg)
        return cfg, cycle, train, heldout

    def test_init_layout(self):
        h = tuneup.home()
        self.assertTrue(os.path.isdir(os.path.join(h, "sealed")))
        self.assertTrue(os.path.isdir(os.path.join(h, "cycles")))
        self.assertTrue(os.path.exists(os.path.join(h, "roster.json")))
        self.assertTrue(os.path.exists(os.path.join(h, "changelog.jsonl")))

    def test_cases_split_and_seal(self):
        cfg, cycle, train, heldout = self.open_cycle()
        # 20 runs, k=5 -> decision points i=4..19 (16 cases);
        # held_out 2 -> train 14, held 2
        self.assertEqual(len(train), 14)
        self.assertEqual(len(heldout), 2)
        # decision points are the true online semantics: case d0017's
        # trailing window ends at the failed run
        by_id = {c["case_id"]: c for c in train + heldout}
        self.assertEqual(by_id["t1-d0017"]["trailing_failed"], 1)
        self.assertEqual(by_id["t1-d0018"]["trailing_failed"], 0)
        spath = tuneup.sealed_path("t1", cycle)
        self.assertTrue(os.path.exists(spath))
        mode = stat.S_IMODE(os.stat(spath).st_mode)
        self.assertEqual(mode, 0o600, "sealed held-out must be owner-only")
        # stdout of cmd_cases must not contain held-out case ids
        buf = io.StringIO()
        with redirect_stdout(buf):
            tuneup.cmd_cases(argparse_ns(tool="t1"))
        out = buf.getvalue()
        for c in heldout:
            self.assertNotIn(c["case_id"], out, "held-out leaked to proposer")
        for c in train:
            self.assertIn(c["case_id"], out, "train should be visible")
        # seal sha recorded and verifiable
        meta = tuneup.read_json(
            os.path.join(tuneup.cycle_dir("t1", tuneup.latest_cycle("t1")), "meta.json"))
        self.assertEqual(meta["sealed_sha256"], tuneup.sha256_file(spath))

    def test_propose_validation(self):
        self.open_cycle()
        # unknown key
        with self.assertRaises(SystemExit):
            tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                           set=["bogus_key=2"], note=""))
        # protected key refused
        with self.assertRaises(SystemExit):
            tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                           set=["api_key=xyz"], note=""))
        # non-numeric refused
        with self.assertRaises(SystemExit):
            tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                           set=["missed_after_mult=many"], note=""))
        # ok proposals up to the cap
        for i in range(3):
            tuneup.cmd_propose(argparse_ns(tool="t1", name=f"p{i}",
                                           set=["missed_after_mult=3"], note=""))
        with self.assertRaises(SystemExit):
            tuneup.cmd_propose(argparse_ns(tool="t1", name="p3",
                                           set=["missed_after_mult=3"], note=""))

    def test_leakage_critic(self):
        cfg, cycle, train, heldout = self.open_cycle()
        held_id = heldout[0]["case_id"]
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["missed_after_mult=3"],
                                       note=f"motivated by {held_id}"))
        report, _ = tuneup.evaluate_all(cfg, "t1", cycle,
                                        {"p1": {"changes": {"missed_after_mult": 3},
                                                "note": f"motivated by {held_id}",
                                                "ts": tuneup.utcnow()}})
        self.assertFalse(report["gates"]["leakage_critic"]["p1"]["passed"])
        self.assertIn(held_id, report["gates"]["leakage_critic"]["p1"]["hits"])
        self.assertEqual(report.get("survivors"), [])

    def test_cost_rule_aborts(self):
        cfg, cycle, train, heldout = self.open_cycle(max_eval_ops=1)
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["missed_after_mult=3"], note=""))
        report, _ = tuneup.evaluate_all(cfg, "t1", cycle,
                                        {"p1": {"changes": {"missed_after_mult": 3},
                                                "note": "", "ts": tuneup.utcnow()}})
        self.assertFalse(report["gates"]["cost_rule"]["passed"])
        self.assertEqual(report["results"], {})
        self.assertEqual(report.get("survivors", None), None)

    def test_pruning(self):
        # streak=0 alerts on everything -> regresses passing cases -> pruned
        cfg, cycle, train, heldout = self.open_cycle(noise_margin_cases=1)
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p0",
                                       set=["alert_on_failed_streak=0"], note=""))
        report, _ = tuneup.evaluate_all(cfg, "t1", cycle,
                                        {"p0": {"changes": {"alert_on_failed_streak": 0},
                                                "note": "", "ts": tuneup.utcnow()}})
        r = report["results"]["p0"]
        self.assertTrue(r.get("pruned"))
        self.assertTrue(len(r["regressed"]) > 0)
        self.assertEqual(report.get("survivors"), [])

    def test_noise_floor(self):
        # failure at run 18 -> decision point d0018 is held-out (last 2).
        # streak=2 fixes the single false alert: improvement=1.
        cfg, cycle, train, heldout = self.open_cycle(noise_margin_cases=2,
                                                    failed_at=(18,))
        self.assertIn("t1-d0018", {c["case_id"] for c in heldout})
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note=""))
        report, _ = tuneup.evaluate_all(cfg, "t1", cycle,
                                        {"p1": {"changes": {"alert_on_failed_streak": 2},
                                                "note": "", "ts": tuneup.utcnow()}})
        r = report["results"]["p1"]
        self.assertTrue(r.get("below_noise"))
        self.assertEqual(r["improvement"], 1)
        self.assertEqual(report.get("survivors"), [])
        # with margin 1 it survives
        cfg2, cycle2, _, _ = self.open_cycle(noise_margin_cases=1,
                                             failed_at=(18,))
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note=""))
        report2, _ = tuneup.evaluate_all(cfg2, "t1", cycle2,
                                         {"p1": {"changes": {"alert_on_failed_streak": 2},
                                                 "note": "", "ts": tuneup.utcnow()}})
        self.assertEqual(report2.get("survivors"), ["p1"])
        self.assertEqual(report2["results"]["p1"]["errors"], 0)

    def test_approve_requires_tty(self):
        cfg, cycle, _, _ = self.open_cycle(noise_margin_cases=1)
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note=""))
        tuneup.evaluate_all(cfg, "t1", cycle,
                            {"p1": {"changes": {"alert_on_failed_streak": 2},
                                    "note": "", "ts": tuneup.utcnow()}})
        # test runner stdin is not a tty -> approval must refuse
        self.assertFalse(sys.stdin.isatty())
        with self.assertRaises(SystemExit):
            tuneup.cmd_review(argparse_ns(tool="t1", approve="p1",
                                          reject=None, reason=""))
        # ...but rejection without a reason is also refused
        with self.assertRaises(SystemExit):
            tuneup.cmd_review(argparse_ns(tool="t1", approve=None,
                                          reject="p1", reason=""))
        # rejection with reason works non-interactively
        tuneup.cmd_review(argparse_ns(tool="t1", approve=None,
                                      reject="p1", reason="not worth it"))

    def test_apply_writes_config(self):
        cfg, cycle, _, _ = self.open_cycle(noise_margin_cases=1)
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note=""))
        tuneup.evaluate_all(cfg, "t1", cycle,
                            {"p1": {"changes": {"alert_on_failed_streak": 2},
                                    "note": "", "ts": tuneup.utcnow()}})
        # simulate a human approval (the TTY gate itself is tested above)
        cdir = tuneup.cycle_dir("t1", cycle)
        tuneup.write_json(os.path.join(cdir, "decision.json"),
                          {"decision": "approved", "proposal": "p1",
                           "ts": tuneup.utcnow(), "reason": "test"})
        tuneup.cmd_apply(argparse_ns(tool="t1"))
        policy = tuneup.read_json(cfg["config_path"])
        self.assertEqual(policy["t1"]["alert_on_failed_streak"], 2)
        # other keys untouched
        self.assertEqual(policy["t1"]["missed_after_mult"], 2)

    def test_apply_refuses_protected_path(self):
        cfg, cycle, _, _ = self.open_cycle(noise_margin_cases=1)
        cfg["config_path"] = os.path.join(self.tmp, "my_api_key.json")
        with open(cfg["config_path"], "w") as f:
            json.dump({"t1": {"alert_on_failed_streak": 1}}, f)
        r = tuneup.load_roster()
        r["tools"]["t1"] = cfg
        tuneup.save_roster(r)
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note=""))
        tuneup.evaluate_all(cfg, "t1", cycle,
                            {"p1": {"changes": {"alert_on_failed_streak": 2},
                                    "note": "", "ts": tuneup.utcnow()}})
        cdir = tuneup.cycle_dir("t1", cycle)
        tuneup.write_json(os.path.join(cdir, "decision.json"),
                          {"decision": "approved", "proposal": "p1",
                           "ts": tuneup.utcnow(), "reason": "test"})
        with self.assertRaises(SystemExit):
            tuneup.cmd_apply(argparse_ns(tool="t1"))

    def test_changelog_append_only(self):
        with open(tuneup.changelog_path(), encoding="utf-8") as f:
            n0 = sum(1 for _ in f)
        tuneup.log_event("test_event", foo="bar")
        with open(tuneup.changelog_path(), encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), n0 + 1)
        last = json.loads(lines[-1])
        self.assertEqual(last["event"], "test_event")
        # earlier entries untouched
        first = json.loads(lines[0])
        self.assertEqual(first["event"], "init")

    def test_next_rotation(self):
        r = tuneup.load_roster()
        # never-run tool (last_cycle None -> "") must beat an old run
        r["tools"]["t-old"] = {"kind": "quietwatch-policy", "desc": "x",
                              "last_cycle": "20200101-000000"}
        r["tools"]["t-new"] = {"kind": "quietwatch-policy", "desc": "x",
                               "last_cycle": None}
        del r["tools"]["qw-inbound-policy"]
        tuneup.save_roster(r)
        buf = io.StringIO()
        with redirect_stdout(buf):
            tuneup.cmd_next(argparse_ns())
        self.assertEqual(buf.getvalue().strip(), "t-new")

    def test_review_lists_survivors(self):
        cfg, cycle, _, _ = self.open_cycle(noise_margin_cases=1,
                                           failed_at=(18,))
        tuneup.cmd_propose(argparse_ns(tool="t1", name="p1",
                                       set=["alert_on_failed_streak=2"], note="calmer"))
        tuneup.evaluate_all(cfg, "t1", cycle,
                            {"p1": {"changes": {"alert_on_failed_streak": 2},
                                    "note": "calmer", "ts": tuneup.utcnow()}})
        buf = io.StringIO()
        with redirect_stdout(buf):
            tuneup.cmd_review(argparse_ns(tool="t1", approve=None,
                                          reject=None, reason=""))
        out = buf.getvalue()
        self.assertIn("proposal p1", out)
        self.assertIn("alert_on_failed_streak: 1 -> 2", out)


class argparse_ns:
    def __init__(self, **kw):
        self.__dict__.update(kw)


if __name__ == "__main__":
    unittest.main(verbosity=2)

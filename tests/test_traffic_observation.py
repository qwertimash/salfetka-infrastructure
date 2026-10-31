import concurrent.futures
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from services.traffic_observation import DAY, GB, ObservationError, Observer, initialize


def inventory():
    return {"schema_version": 1, "accounts": [
        {"account_id": "a", "plan": "trial"}, {"account_id": "b", "plan": "paid"}],
        "meters": [dict(id=name, account_id=account, node_id=node, meter_id=key,
                       source="xray", measurement_point="client_ingress")
                   for name, account, node, key in [("a1", "a", "de", "key-a1"),
                                                   ("a2", "a", "pl", "key-a2"),
                                                   ("b1", "b", "de", "key-b")]]}


def sample(meter, seq, at, down, epoch="boot1"):
    return dict(meter=meter, epoch=epoch, sequence=seq, observed_at_ms=at, download_bytes=down)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "observer.db"
        initialize(self.path, inventory(), 0)
        self.o = Observer(self.path)
        self.addCleanup(self.o.close)
        self.o.ingest([sample(m, 0, 0, 0) for m in ["a1", "a2", "b1"]], 0)

    def ingest(self, at, a1, a2=0, b=0):
        return self.o.ingest([sample(m, at, at, v) for m, v in [("a1", a1), ("a2", a2), ("b1", b)]], at)

    def report(self, at, index=0):
        return self.o.report(at)["accounts"][index]

    def test_thresholds_sum_all_meters_not_per_device(self):
        self.ingest(1000, 12*GB, 8*GB, 49*GB)
        r = self.o.evaluate(1000)
        self.assertFalse(r["enforcement"]); self.assertFalse(r["user_notifications"])
        self.assertEqual(r["accounts"][0]["download_lower_bytes"], 20*GB)
        self.assertEqual(r["accounts"][0]["shadow_until_ms"], 1000+DAY)
        self.assertEqual(r["accounts"][1]["measurement_status"], "below_candidate")
        self.ingest(2000, 12*GB, 8*GB, 50*GB)
        self.assertEqual(len(self.o.evaluate(2000)["events"]), 2)

    def test_duplicate_after_restart_and_conflict_are_atomic(self):
        rows = [sample("a1", 1, 1000, 10*GB)]
        self.o.ingest(rows, 1000)
        with Observer(self.path) as reopened:
            self.assertEqual(reopened.ingest(rows, 1000), {"inserted": 0, "replayed": 1})
            with self.assertRaisesRegex(ObservationError, "replay_conflict"):
                reopened.ingest([sample("b1", 1, 1000, GB), sample("a1", 1, 1000, 11*GB)], 1000)
        self.assertEqual(self.report(1000, 1)["download_lower_bytes"], 0)
        self.assertEqual(self.report(1000)["download_lower_bytes"], 10*GB)

    def test_first_lifetime_counter_is_not_billed(self):
        other = Path(self.tmp.name)/"baseline.db"
        initialize(other, inventory(), 0)
        with Observer(other) as o:
            o.ingest([sample("a1", 1, 1000, 1000*GB)], 1000)
            a = o.evaluate(1000)["accounts"][0]
            self.assertEqual(a["download_lower_bytes"], 0)
            self.assertIsNone(a["download_upper_bytes"])
            self.assertEqual(a["measurement_status"], "insufficient_data")

    def test_window_boundary_returns_bounds_not_prorated_exact_usage(self):
        self.ingest(2000, 30*GB)
        self.ingest(DAY+1000, 30*GB)
        a = self.report(DAY+1000)
        self.assertEqual((a["download_lower_bytes"], a["download_upper_bytes"]), (0, 30*GB))
        self.assertEqual(a["measurement_status"], "possible_exceedance")
        self.assertIsNone(self.o.evaluate(DAY+1000)["accounts"][0]["shadow_until_ms"])
        self.ingest(DAY+2000, 30*GB)
        self.assertEqual(self.report(DAY+2000)["download_upper_bytes"], 0)

    def test_missing_node_never_becomes_zero_or_complete(self):
        self.o.ingest([sample("a1", 1, 1000, GB)], 1000)
        a = self.report(1000)
        self.assertFalse(a["coverage_complete"])
        self.assertIn("unobserved_tail", a["quality_reasons"])
        self.assertEqual(a["measurement_status"], "insufficient_data")
        self.assertIn("stale_or_missing_meter", self.report(200000)["quality_reasons"])

    def test_null_counter_and_recovery_preserve_gap(self):
        self.o.ingest([sample("a1", 1, 1000, None), sample("a2", 1, 1000, 0)], 1000)
        self.assertIn("missing_counter", self.report(1000)["quality_reasons"])
        self.ingest(2000, 15*GB)
        self.ingest(3000, 16*GB)
        a = self.report(3000)
        self.assertEqual(a["download_lower_bytes"], GB)
        self.assertIsNone(a["download_upper_bytes"])

    def test_reset_counter_never_subtracts_or_counts_new_lifetime_total(self):
        self.ingest(1000, 10*GB)
        self.ingest(2000, 0)
        self.ingest(3000, 2*GB)
        a = self.report(3000)
        self.assertEqual(a["download_lower_bytes"], 12*GB)
        self.assertIn("counter_decreased", a["quality_reasons"])

    def test_new_epoch_and_retired_epoch_rejection(self):
        self.ingest(1000, GB)
        self.o.ingest([sample("a1", 0, 2000, 100*GB, "boot2")], 2000)
        self.o.ingest([sample("a1", 1, 3000, 101*GB, "boot2")], 3000)
        a = self.report(3000)
        self.assertEqual(a["download_lower_bytes"], 2*GB)
        self.assertIn("epoch_changed", a["quality_reasons"])
        with self.assertRaisesRegex(ObservationError, "retired_epoch"):
            self.o.ingest([sample("a1", 9, 4000, 200*GB, "boot1")], 4000)

    def test_out_of_order_future_negative_bool_and_total_only_rejected(self):
        self.ingest(1000, GB)
        for row, at in [(sample("a1", 0, 900, 0), 1000),
                        (sample("a1", 2, 2000, GB), 1000),
                        (sample("a1", 2, 2000, -1), 2000),
                        (sample("a1", 2, 2000, True), 2000),
                        (sample("a1", 2, 2000, GB) | {"total_bytes": 5*GB}, 2000)]:
            with self.assertRaises(ObservationError):
                self.o.ingest([row], at)
        self.assertEqual(self.report(1000)["download_lower_bytes"], GB)

    def test_shadow_lasts_fixed_24h_and_expiry_restarts_counting(self):
        self.ingest(1000, 20*GB)
        self.o.evaluate(1000)
        self.ingest(2000, 80*GB)
        self.o.evaluate(2000)
        self.assertEqual(len(self.o.report(2000)["events"]), 1)
        end = 1000+DAY
        self.ingest(end, 100*GB)
        r = self.o.evaluate(end)
        self.assertEqual([e["kind"] for e in r["events"]], ["would_limit", "shadow_expired"])
        self.assertIsNone(r["accounts"][0]["shadow_until_ms"])
        self.assertEqual(r["accounts"][0]["download_lower_bytes"], 0)
        self.ingest(end+1000, 120*GB)
        self.assertEqual(len(self.o.evaluate(end+1000)["events"]), 3)

    def test_manual_release_is_idempotent_and_keeps_history(self):
        self.ingest(1000, 20*GB); self.o.evaluate(1000)
        self.ingest(2000, 30*GB)
        self.assertTrue(self.o.release("a", 1, 2000))
        self.assertFalse(self.o.release("a", 1, 2500))
        self.ingest(3000, 50*GB)
        r = self.o.evaluate(3000)
        self.assertEqual(len(r["events"]), 3)
        self.assertFalse(self.o.release("a", 1, 3000))
        self.assertEqual(self.report(3000)["shadow_until_ms"], 3000+DAY)
        self.assertEqual(r["accounts"][0]["download_lower_bytes"], 20*GB)

    def test_plan_change_does_not_reset_traffic_or_active_shadow(self):
        self.ingest(1000, 21*GB); self.o.evaluate(1000)
        self.o.set_plan("a", "paid", 1000)
        a = self.o.evaluate(1000)["accounts"][0]
        self.assertEqual(a["candidate_bytes"], 50*GB)
        self.assertEqual(a["download_lower_bytes"], 21*GB)
        self.assertEqual(a["shadow_until_ms"], DAY+1000)

    def test_concurrent_replays_and_evaluation_make_one_incident(self):
        def run(_):
            with Observer(self.path) as o:
                o.ingest([sample("a1", 1, 1000, 20*GB)], 1000)
                return o.evaluate(1000)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(run, range(3)))
        self.assertEqual(len(self.o.report(1000)["events"]), 1)

    def test_clock_rollback_and_late_unseen_sample_rejected(self):
        self.ingest(1000, GB); self.o.evaluate(2000)
        with self.assertRaisesRegex(ObservationError, "clock_before"):
            self.o.evaluate(1999)
        with self.assertRaisesRegex(ObservationError, "stale_sample"):
            self.o.ingest([sample("a1", 3, 1500, 2*GB)], 2000)
        with self.assertRaisesRegex(ObservationError, "clock_before"):
            self.o.report(999)

    def test_foreign_database_is_untouched(self):
        p = Path(self.tmp.name)/"foreign.db"
        with sqlite3.connect(p) as db:
            db.execute('CREATE TABLE important_data(value)')
        db.close(); before = p.read_bytes()
        with self.assertRaises(ObservationError): Observer(p)
        with self.assertRaises(FileExistsError): initialize(p, inventory(), 0)
        self.assertEqual(before, p.read_bytes())
        with self.assertRaises(ObservationError): initialize(Path(self.tmp.name)/"vpn_bot.db", inventory(), 0)

    def test_inventory_rejects_double_counting_and_unbound_accounts(self):
        for change in ["duplicate", "relay", "plan"]:
            inv = inventory()
            if change == "duplicate": inv["meters"].append(inv["meters"][0] | {"id": "alias"})
            if change == "relay": inv["meters"][0]["measurement_point"] = "transit"
            if change == "plan": inv["accounts"][0]["plan"] = "unknown"
            p = Path(self.tmp.name)/(change+".db")
            with self.assertRaises(ObservationError): initialize(p, inv, 0)
            self.assertFalse(p.exists())

    def test_warmup_does_not_claim_a_full_window_and_gap_ages_out(self):
        path = Path(self.tmp.name)/"warmup.db"; start = 100*DAY
        initialize(path, inventory(), start)
        with Observer(path) as o:
            for seq, at in enumerate([start, start+1000, start+DAY]):
                o.ingest([sample(m, seq, at, 0) for m in ["a1", "a2", "b1"]], at)
                a = o.report(at)["accounts"][0]
                self.assertEqual(a["coverage_complete"], at == start+DAY)
                self.assertEqual(a["measurement_status"], "below_candidate" if at == start+DAY else "insufficient_data")

    def test_null_initial_baseline_at_window_start_stays_unknown(self):
        path = Path(self.tmp.name)/"null.db"; initialize(path, inventory(), 0)
        with Observer(path) as o:
            o.ingest([sample(m, 0, 0, None) for m in ["a1", "a2", "b1"]], 0)
            a = o.report(0)["accounts"][0]
            self.assertFalse(a["coverage_complete"])
            self.assertEqual(a["measurement_status"], "insufficient_data")

    def test_synthetic_hundred_accounts_remain_isolated(self):
        path = Path(self.tmp.name)/"hundred.db"
        inv = {"schema_version":1,"accounts":[],"meters":[]}
        for i in range(100):
            inv["accounts"].append({"account_id":f"account-{i}","plan":"trial" if i%2==0 else "paid"})
            inv["meters"].append(dict(id=f"meter-{i}",account_id=f"account-{i}",node_id="node",meter_id=f"identity-{i}",source="xray",measurement_point="client_ingress"))
        initialize(path, inv, 0)
        with Observer(path) as o:
            o.ingest([sample(f"meter-{i}",0,0,0) for i in range(100)],0)
            o.ingest([sample(f"meter-{i}",1,1000,21*GB) for i in range(100)],1000)
            r=o.evaluate(1000)
            self.assertEqual(len(r["events"]),50)
            self.assertEqual(sum(a["shadow_state"]=="active" for a in r["accounts"]),50)
            self.assertTrue(all(a["download_lower_bytes"]==21*GB for a in r["accounts"]))

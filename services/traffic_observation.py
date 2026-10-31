"""Offline shadow accounting. Deliberately has no network or enforcement API."""
from __future__ import annotations

import json
import re
import sqlite3
import stat
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import quote

GB = 1_000_000_000
DAY = 86_400_000
LIMITS = {"trial": 20 * GB, "paid": 50 * GB}
MARKER = "salfetka-traffic-observation-v1"
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
_METER = re.compile(r"[A-Za-z0-9_.:@+-]{1,128}\Z")
MAX_INT = 2**63 - 1


class ObservationError(ValueError):
    """Only stable codes, never raw input or credentials, are surfaced."""


def fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ObservationError("invalid_fields")


def integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_INT:
        raise ObservationError("invalid_integer")
    return value


def identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ObservationError("invalid_identifier")
    return value


def plan_name(value):
    if not isinstance(value, str) or value not in LIMITS:
        raise ObservationError("invalid_plan")
    return value


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ObservationError("duplicate_json_field")
            result[key] = value
        return result
    p = Path(path)
    info = p.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ObservationError("input_not_regular_file")
    limit = 16 * 1024 * 1024
    if info.st_size > limit:
        raise ObservationError("input_too_large")
    with p.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ObservationError("input_too_large")
    return json.loads(data, object_pairs_hook=unique)


SCHEMA = """
CREATE TABLE observer_meta(marker TEXT NOT NULL);
CREATE TABLE accounts(id TEXT PRIMARY KEY, plan TEXT NOT NULL,
 cycle_start INTEGER NOT NULL, evaluated_at INTEGER NOT NULL, shadow_until INTEGER);
CREATE TABLE meters(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
 node_id TEXT NOT NULL, meter_id TEXT NOT NULL, source TEXT NOT NULL,
 UNIQUE(node_id,meter_id));
CREATE TABLE samples(meter TEXT NOT NULL REFERENCES meters(id), epoch TEXT NOT NULL,
 sequence INTEGER NOT NULL, at INTEGER NOT NULL, down INTEGER,
 start INTEGER NOT NULL, delta INTEGER, reason TEXT,
 PRIMARY KEY(meter,epoch,sequence), UNIQUE(meter,at));
CREATE INDEX samples_window ON samples(meter,at);
CREATE TABLE events(id INTEGER PRIMARY KEY, account_id TEXT NOT NULL,
 kind TEXT NOT NULL, at INTEGER NOT NULL, until_ms INTEGER, detail TEXT NOT NULL,
 UNIQUE(account_id,kind,at));
"""


def initialize(path, inventory, at):
    integer(at)
    fields(inventory, ["schema_version", "accounts", "meters"])
    if type(inventory["schema_version"]) is not int or inventory["schema_version"] != 1:
        raise ObservationError("invalid_schema")
    accounts, meters = inventory["accounts"], inventory["meters"]
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 10000 or not isinstance(meters, list) or not 1 <= len(meters) <= 100000:
        raise ObservationError("invalid_inventory")
    ids, names, physical = set(), set(), set()
    for a in accounts:
        fields(a, ["account_id", "plan"])
        identifier(a["account_id"]); plan_name(a["plan"])
        if a["account_id"] in ids:
            raise ObservationError("duplicate_account")
        ids.add(a["account_id"])
    for m in meters:
        fields(m, ["id", "account_id", "node_id", "meter_id", "source", "measurement_point"])
        for key in ["id", "account_id", "node_id"]:
            identifier(m[key])
        if not isinstance(m["meter_id"], str) or not _METER.fullmatch(m["meter_id"]):
            raise ObservationError("invalid_meter_label")
        if m["source"] not in ("xray", "panel") or m["measurement_point"] != "client_ingress":
            raise ObservationError("invalid_measurement_point")
        if m["account_id"] not in ids or m["id"] in names or (m["node_id"], m["meter_id"]) in physical:
            raise ObservationError("duplicate_or_unbound_meter")
        names.add(m["id"]); physical.add((m["node_id"], m["meter_id"]))
    if ids != {m["account_id"] for m in meters}:
        raise ObservationError("account_without_meters")
    p = Path(path)
    if p.name == "vpn_bot.db" or p.is_symlink():
        raise ObservationError("unsafe_database")
    # Exclusive creation prevents ever initializing/migrating an existing DB.
    import os
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with closing(sqlite3.connect(p)) as db, db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO observer_meta VALUES(?)", (MARKER,))
            db.executemany("INSERT INTO accounts VALUES(?,?,?,?,NULL)",
                           [(a["account_id"], a["plan"], max(0, at - DAY), at) for a in accounts])
            db.executemany("INSERT INTO meters VALUES(?,?,?,?,?)",
                           [(m["id"], m["account_id"], m["node_id"], m["meter_id"], m["source"]) for m in meters])
    except BaseException:
        p.unlink(missing_ok=True)
        raise


class Observer:
    STORE_MARKER = MARKER
    ALLOW_LATE_SAMPLES = False

    def __init__(self, path):
        p = Path(path)
        if p.name == "vpn_bot.db" or p.is_symlink():
            raise ObservationError("unsafe_database")
        self.db = sqlite3.connect("file:" + quote(str(p.resolve()), safe="/") + "?mode=rw", uri=True, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            if self.db.execute("SELECT marker FROM observer_meta").fetchall()[0][0] != self.STORE_MARKER:
                raise ObservationError("foreign_database")
            self.db.execute("PRAGMA foreign_keys=ON")
        except Exception:
            self.db.close()
            raise ObservationError("foreign_database") from None

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def meters(self):
        return [dict(r) for r in self.db.execute("SELECT * FROM meters ORDER BY id")]

    def _clock(self, at):
        integer(at)
        latest = self.db.execute("SELECT max(at) FROM samples").fetchone()[0]
        checked = self.db.execute("SELECT max(evaluated_at) FROM accounts").fetchone()[0]
        if at < max(latest or 0, checked or 0):
            raise ObservationError("clock_before_observed_state")

    def ingest(self, samples, at):
        with self.transaction():
            return self._ingest(samples, at)

    def _ingest(self, samples, at):
        integer(at)
        if not isinstance(samples, list) or not 1 <= len(samples) <= 100000:
            raise ObservationError("invalid_batch")
        self._clock(at)
        inserted = 0
        for s in samples:
            fields(s, ["meter", "epoch", "sequence", "observed_at_ms", "download_bytes"])
            meter, epoch = identifier(s["meter"]), identifier(s["epoch"])
            seq, stamp = integer(s["sequence"]), integer(s["observed_at_ms"])
            down = s["download_bytes"]
            if down is not None:
                integer(down)
            a = self.db.execute("SELECT a.* FROM accounts a JOIN meters m ON m.account_id=a.id WHERE m.id=?", (meter,)).fetchone()
            if a is None or stamp > at:
                raise ObservationError("unbound_or_future_sample")
            old = self.db.execute("SELECT * FROM samples WHERE meter=? AND epoch=? AND sequence=?", (meter, epoch, seq)).fetchone()
            if old:
                if (old["at"], old["down"]) != (stamp, down):
                    raise ObservationError("replay_conflict")
                continue
            prev = self.db.execute("SELECT * FROM samples WHERE meter=? ORDER BY at DESC LIMIT 1", (meter,)).fetchone()
            if (not self.ALLOW_LATE_SAMPLES and stamp < a["evaluated_at"]) or prev and (stamp <= prev["at"] or epoch == prev["epoch"] and seq <= prev["sequence"]):
                raise ObservationError("stale_sample")
            delta, reason = None, "baseline"
            if prev:
                if epoch != prev["epoch"]:
                    if self.db.execute("SELECT 1 FROM samples WHERE meter=? AND epoch=? LIMIT 1", (meter, epoch)).fetchone():
                        raise ObservationError("retired_epoch")
                    reason = "epoch_changed"
                elif down is None or prev["down"] is None:
                    reason = "missing_counter"
                elif down < prev["down"]:
                    reason = "counter_decreased"
                else:
                    delta, reason = down - prev["down"], None
            self.db.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)",
                            (meter, epoch, seq, stamp, down, prev["at"] if prev else stamp, delta, reason))
            inserted += 1
        return {"inserted": inserted, "replayed": len(samples) - inserted}

    def observe(self, samples, at):
        """Commit counters and their shadow decisions together, or neither."""
        with self.transaction():
            imported = self._ingest(samples, at)
            report = self._evaluate(at)
            return {"import": imported, "report": report}

    def _measure(self, a, at):
        start = max(a["cycle_start"], at - DAY)
        lower = upper = 0
        unknown, reasons, boundary = False, set(), False
        streams = self.db.execute("SELECT id FROM meters WHERE account_id=?", (a["id"],)).fetchall()
        for m in streams:
            first = self.db.execute("SELECT min(at) FROM samples WHERE meter=?", (m[0],)).fetchone()[0]
            last_row = self.db.execute("SELECT at,down FROM samples WHERE meter=? ORDER BY at DESC LIMIT 1", (m[0],)).fetchone()
            last = last_row["at"] if last_row else None
            if last_row and last_row["down"] is None:
                unknown = True; reasons.add("missing_counter")
            if first is None or first > start:
                unknown = True; reasons.add("missing_baseline")
            if last is None or last < at:
                unknown = True; reasons.add("unobserved_tail")
            if last is None or at - last > 120000:
                reasons.add("stale_or_missing_meter")
            rows = self.db.execute("SELECT * FROM samples WHERE meter=? AND at>? AND start<? ORDER BY at", (m[0], start, at))
            for r in rows:
                if r["delta"] is None:
                    unknown = True; reasons.add(r["reason"])
                elif r["start"] >= start:
                    lower += r["delta"]; upper += r["delta"]
                else:
                    # Actual time of the bytes inside this interval is unknown.
                    upper += r["delta"]; boundary = True
        if boundary:
            reasons.add("window_boundary_interval")
        limit = LIMITS[a["plan"]]
        status = ("would_exceed" if lower >= limit else "insufficient_data" if unknown
                  else "possible_exceedance" if upper >= limit else "below_candidate")
        return {"account_id": a["id"], "plan": a["plan"], "candidate_bytes": limit,
                "window_start_ms": start, "as_of_ms": at,
                "download_lower_bytes": lower, "download_upper_bytes": None if unknown else upper,
                "measurement_status": status, "coverage_complete": not unknown,
                "quality_reasons": sorted(reasons), "meter_count": len(streams)}

    def _event(self, account, kind, at, until, detail):
        self.db.execute("INSERT INTO events(account_id,kind,at,until_ms,detail) VALUES(?,?,?,?,?)",
                        (account, kind, at, until, json.dumps(detail, sort_keys=True)))

    def evaluate(self, at):
        with self.transaction():
            return self._evaluate(at)

    def _evaluate(self, at):
        self._clock(at)
        accounts = self.db.execute("SELECT * FROM accounts ORDER BY id").fetchall()
        for row in accounts:
            a = dict(row)
            if a["shadow_until"] is not None and at >= a["shadow_until"]:
                end = a["shadow_until"]
                self._event(a["id"], "shadow_expired", end, None, {})
                self.db.execute("UPDATE accounts SET shadow_until=NULL,cycle_start=? WHERE id=?", (end, a["id"]))
                a.update(shadow_until=None, cycle_start=end)
            measured = self._measure(a, at)
            if a["shadow_until"] is None and measured["measurement_status"] == "would_exceed":
                until = at + DAY
                integer(until)
                self._event(a["id"], "would_limit", at, until, measured)
                self.db.execute("UPDATE accounts SET shadow_until=? WHERE id=?", (until, a["id"]))
            self.db.execute("UPDATE accounts SET evaluated_at=? WHERE id=?", (at, a["id"]))
        return self._report(at)

    def _report(self, at):
        accounts = []
        for row in self.db.execute("SELECT * FROM accounts ORDER BY id"):
            a = dict(row); measured = self._measure(a, at)
            measured["shadow_until_ms"] = a["shadow_until"]
            measured["shadow_state"] = ("none" if a["shadow_until"] is None else
                                        "active" if at < a["shadow_until"] else "expiry_pending_evaluation")
            measured["last_evaluated_at_ms"] = a["evaluated_at"]
            accounts.append(measured)
        return {"mode": "observation_only", "schema_version": 1, "enforcement": False,
                "user_notifications": False, "coverage_scope": "declared_client_ingress_meters_only", "accounts": accounts,
                "events": [dict(r) | {"detail": json.loads(r["detail"])} for r in self.db.execute("SELECT * FROM events ORDER BY id")]}

    def report(self, at):
        # A read transaction gives one consistent snapshot across concurrent writers.
        self.db.execute("BEGIN")
        try:
            self._clock(at)
            return self._report(at)
        finally:
            self.db.execute("ROLLBACK")

    def release(self, account, incident_id, at):
        identifier(account); integer(incident_id, 1)
        with self.transaction():
            self._clock(at)
            a = self.db.execute("SELECT * FROM accounts WHERE id=?", (account,)).fetchone()
            if a is None:
                raise ObservationError("unknown_account")
            for e in self.db.execute("SELECT detail FROM events WHERE account_id=? AND kind='shadow_released'", (account,)):
                if json.loads(e[0])["incident_id"] == incident_id:
                    return False  # A delayed retry must not release a newer incident.
            latest = self.db.execute("SELECT id FROM events WHERE account_id=? AND kind='would_limit' ORDER BY id DESC LIMIT 1", (account,)).fetchone()
            if not latest or latest[0] != incident_id or a["shadow_until"] is None:
                raise ObservationError("incident_conflict")
            if at >= a["shadow_until"]:
                raise ObservationError("evaluate_expiry_first")
            self._event(account, "shadow_released", at, None, {"incident_id": incident_id})
            self.db.execute("UPDATE accounts SET cycle_start=?,shadow_until=NULL,evaluated_at=? WHERE id=?", (at, at, account))
            return True

    def set_plan(self, account, plan, at):
        identifier(account); plan_name(plan)
        with self.transaction():
            self._clock(at)
            a = self.db.execute("SELECT plan FROM accounts WHERE id=?", (account,)).fetchone()
            if a is None:
                raise ObservationError("unknown_account")
            if a[0] != plan:
                self._event(account, "plan_changed", at, None, {"from": a[0], "to": plan})
                self.db.execute("UPDATE accounts SET plan=?,evaluated_at=? WHERE id=?", (plan, at, account))

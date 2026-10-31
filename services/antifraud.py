"""Durable account-wide anti-fraud decisions, not an implicit deployment switch.

This separate store never imports bot/config or calls a provider. Command receipts
must come from authenticated node adapters; a decision alone is not enforcement.
Existing observation databases cannot be opened as an enforcement controller.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from services.traffic_observation import (
    DAY, ObservationError, Observer, identifier, initialize as initialize_observer,
    integer,
)

MARKER = "salfetka-antifraud-v1"
RATE_BPS = 1_000_000
RECEIPT_TTL_MS = 30_000
NOTIFICATION_UNCERTAIN_MS = 120_000
SCHEMA = """
CREATE TABLE fraud_policy(
 account_id TEXT PRIMARY KEY REFERENCES accounts(id), revision INTEGER NOT NULL,
 incident_id INTEGER, limited INTEGER NOT NULL CHECK(limited IN (0,1)),
 until_ms INTEGER, updated_at INTEGER NOT NULL);
CREATE TABLE fraud_incidents(
 id INTEGER PRIMARY KEY REFERENCES events(id), account_id TEXT NOT NULL REFERENCES accounts(id),
 triggered_at INTEGER NOT NULL, until_ms INTEGER NOT NULL, threshold_bytes INTEGER NOT NULL,
 evidence_bytes INTEGER NOT NULL, ended_at INTEGER, ended_by TEXT, end_reason TEXT);
CREATE TABLE fraud_receipts(
 account_id TEXT NOT NULL REFERENCES accounts(id), node_id TEXT NOT NULL,
 revision INTEGER NOT NULL, limited INTEGER NOT NULL CHECK(limited IN (0,1)),
 applied INTEGER NOT NULL CHECK(applied IN (0,1)), received_at INTEGER NOT NULL,
 error_code TEXT, sequence INTEGER NOT NULL, PRIMARY KEY(account_id,node_id));
CREATE TABLE fraud_notifications(
 incident_id INTEGER PRIMARY KEY REFERENCES fraud_incidents(id),
 state TEXT NOT NULL CHECK(state IN ('queued','sending','delivered','forbidden','unknown','cancelled')),
 claim_token TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
 message_id INTEGER, updated_at INTEGER NOT NULL);
CREATE TABLE fraud_audit(
 id INTEGER PRIMARY KEY, account_id TEXT NOT NULL, incident_id INTEGER,
 actor TEXT NOT NULL, action TEXT NOT NULL, at INTEGER NOT NULL);
CREATE TABLE fraud_clock(id INTEGER PRIMARY KEY CHECK(id=1), last_at INTEGER NOT NULL);
CREATE TABLE fraud_node_sessions(node_id TEXT PRIMARY KEY, session TEXT NOT NULL UNIQUE);
CREATE TABLE fraud_budget(account_id TEXT PRIMARY KEY REFERENCES accounts(id),
 revision INTEGER NOT NULL, next_ns INTEGER NOT NULL, observed_ns INTEGER NOT NULL);
CREATE TABLE fraud_request_heads(account_id TEXT NOT NULL, node_id TEXT NOT NULL,
 session TEXT NOT NULL, sequence INTEGER NOT NULL, PRIMARY KEY(account_id,node_id));
CREATE TABLE fraud_permits(account_id TEXT NOT NULL, node_id TEXT NOT NULL,
 session TEXT NOT NULL, sequence INTEGER NOT NULL, revision INTEGER NOT NULL,
 bytes INTEGER NOT NULL, direction TEXT NOT NULL, send_at_ns INTEGER NOT NULL,
 expires_ns INTEGER NOT NULL, PRIMARY KEY(account_id,node_id,session,sequence));
CREATE INDEX fraud_permits_retention ON fraud_permits(expires_ns);
"""


def initialize(path, inventory, at):
    """Exclusive new store; never promote an existing shadow journal."""
    initialize_observer(path, inventory, at)
    try:
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(SCHEMA)
            db.execute("UPDATE observer_meta SET marker=?", (MARKER,))
            db.execute("INSERT INTO fraud_clock VALUES(1,?)", (at,))
            db.execute("INSERT INTO fraud_policy SELECT id,0,NULL,0,NULL,? FROM accounts", (at,))
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


class Controller(Observer):
    STORE_MARKER = MARKER
    # Delayed node samples add evidence only; past incident evidence is immutable.
    # Per-meter timestamps/epochs still must advance, and boundary intervals never
    # count in the lower bound after release. Legacy shadow semantics stay strict.
    ALLOW_LATE_SAMPLES = True

    def _control_clock(self, at):
        integer(at)
        last = self.db.execute("SELECT last_at FROM fraud_clock WHERE id=1").fetchone()[0]
        if at < last:
            raise ObservationError("control_clock_regressed")
        self.db.execute("UPDATE fraud_clock SET last_at=? WHERE id=1", (at,))

    def _event(self, account, kind, at, until, detail):
        super()._event(account, kind, at, until, detail)
        event_id = self.db.execute("SELECT last_insert_rowid()").fetchone()[0]
        if kind == "would_limit":
            self.db.execute("INSERT INTO fraud_incidents VALUES(?,?,?,?,?,?,NULL,NULL,NULL)",
                            (event_id, account, at, until, detail["candidate_bytes"], detail["download_lower_bytes"]))
            self.db.execute("UPDATE fraud_policy SET revision=revision+1,incident_id=?,limited=1,until_ms=?,updated_at=? WHERE account_id=?",
                            (event_id, until, at, account))
        elif kind in ("shadow_released", "shadow_expired"):
            policy = self.db.execute("SELECT incident_id FROM fraud_policy WHERE account_id=?", (account,)).fetchone()
            incident = policy[0]
            reason = "admin_release" if kind == "shadow_released" else "expired"
            self.db.execute("UPDATE fraud_incidents SET ended_at=?,end_reason=? WHERE id=? AND ended_at IS NULL", (at, reason, incident))
            self.db.execute("UPDATE fraud_policy SET revision=revision+1,limited=0,until_ms=NULL,updated_at=? WHERE account_id=?", (at, account))
            self.db.execute("UPDATE fraud_notifications SET state='cancelled',updated_at=? WHERE incident_id=? AND state='queued'", (at, incident))

    def _expire(self, at):
        self._control_clock(at)
        self.db.execute("UPDATE fraud_notifications SET state='unknown',claim_token=NULL,updated_at=? WHERE state='sending' AND updated_at<=?", (at, at-NOTIFICATION_UNCERTAIN_MS))
        expired = self.db.execute("SELECT id,shadow_until FROM accounts WHERE shadow_until IS NOT NULL AND shadow_until<=?", (at,)).fetchall()
        for row in expired:
            self._event(row["id"], "shadow_expired", row["shadow_until"], None, {})
            self.db.execute("UPDATE accounts SET shadow_until=NULL,cycle_start=?,evaluated_at=max(evaluated_at,?) WHERE id=?",
                            (row["shadow_until"], row["shadow_until"], row["id"]))

    def tick(self, at):
        """Expire fixed penalties even when accounting sources are unavailable."""
        with self.transaction():
            self._expire(at)
            return self._report(at)

    def account_page(self, at, *, after="", limit=100):
        """Bounded admin projection, without histories or internal claim tokens."""
        integer(limit, 1)
        if limit > 100:
            raise ObservationError("invalid_page")
        if after:
            identifier(after)
        with self.transaction():
            self._expire(at)
            rows = self.db.execute("SELECT * FROM accounts WHERE id>? ORDER BY id LIMIT ?", (after, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = self._measure(dict(row), at)
                p = self.db.execute("SELECT * FROM fraud_policy WHERE account_id=?", (row['id'],)).fetchone()
                item['policy'] = dict(revision=p['revision'], incident_id=p['incident_id'], limited=bool(p['limited']), until_ms=p['until_ms'], **self._status(p, at))
                incident = self.db.execute("SELECT * FROM fraud_incidents WHERE id=?", (p['incident_id'],)).fetchone()
                item['incident'] = dict(incident) if incident else None
                notice = self.db.execute("SELECT state FROM fraud_notifications WHERE incident_id=?", (p['incident_id'],)).fetchone()
                item['notification_state'] = notice[0] if notice else 'none'
                items.append(item)
            return dict(items=items, next_cursor=rows[limit-1]['id'] if len(rows)>limit else '', generated_at_ms=at,
                        coverage_scope='declared_client_ingress_meters_only', aggregate_bps=RATE_BPS)

    def _evaluate(self, at):
        integer(at)
        last = self.db.execute("SELECT last_at FROM fraud_clock WHERE id=1").fetchone()[0]
        self._control_clock(max(at, last))
        return super()._evaluate(at)

    def _nodes(self, account):
        return [r[0] for r in self.db.execute("SELECT DISTINCT node_id FROM meters WHERE account_id=? ORDER BY node_id", (account,))]

    def _status(self, policy, at):
        nodes = self._nodes(policy["account_id"])
        receipts = {r["node_id"]: dict(r) for r in self.db.execute("SELECT * FROM fraud_receipts WHERE account_id=?", (policy["account_id"],))}
        confirmed = [n for n in nodes if n in receipts and receipts[n]["revision"] == policy["revision"] and receipts[n]["applied"] and receipts[n]["limited"] == policy["limited"] and at-receipts[n]["received_at"]<=RECEIPT_TTL_MS]
        errors = [n for n in nodes if n in receipts and receipts[n]["revision"] == policy["revision"] and not receipts[n]["applied"]]
        state = "limited" if policy["limited"] else "clear"
        if policy["revision"] and len(confirmed) != len(nodes):
            state = "apply_failed" if errors else "pending_apply" if policy["limited"] else "pending_release"
        return {"state": state, "required_nodes": nodes, "confirmed_nodes": confirmed, "failed_nodes": errors}

    def commands(self, node_id, at):
        identifier(node_id)
        with self.transaction():
            self._expire(at)
            if not self.db.execute("SELECT 1 FROM meters WHERE node_id=?", (node_id,)).fetchone():
                raise ObservationError("unknown_node")
            policies = self.db.execute("SELECT DISTINCT p.* FROM fraud_policy p JOIN meters m ON m.account_id=p.account_id WHERE m.node_id=? ORDER BY p.account_id", (node_id,))
            return [{"account_id": p["account_id"], "revision": p["revision"], "incident_id": p["incident_id"],
                     "limited": bool(p["limited"]), "until_ms": p["until_ms"],
                     "aggregate_bps": RATE_BPS if p["limited"] else None,
                     "budget_scope": "account_all_nodes_upload_plus_download"} for p in policies]

    def acknowledge(self, node_id, account, revision, *, limited, applied, at, error_code=None, sequence=1, session=None):
        identifier(node_id); identifier(account); integer(revision, 1); integer(sequence, 1)
        if type(limited) is not bool or type(applied) is not bool:
            raise ObservationError("invalid_receipt")
        if error_code is not None:
            identifier(error_code)
        if (applied and error_code is not None) or (not applied and error_code is None):
            raise ObservationError("invalid_receipt")
        with self.transaction():
            self._expire(at)
            if session is not None:
                current = self.db.execute("SELECT session FROM fraud_node_sessions WHERE node_id=?", (node_id,)).fetchone()
                if not isinstance(session, str) or not current or not secrets.compare_digest(current[0], session):
                    raise ObservationError("stale_node_session")
            p = self.db.execute("SELECT * FROM fraud_policy WHERE account_id=?", (account,)).fetchone()
            if not p or node_id not in self._nodes(account):
                raise ObservationError("unbound_account_node")
            if p["revision"] != revision or bool(p["limited"]) != limited:
                raise ObservationError("stale_policy")
            old = self.db.execute("SELECT * FROM fraud_receipts WHERE account_id=? AND node_id=?", (account, node_id)).fetchone()
            if old and old["revision"] == revision:
                if sequence < old["sequence"]:
                    raise ObservationError("stale_receipt")
                if sequence == old["sequence"]:
                    if (bool(old["applied"]), old["error_code"]) != (applied, error_code):
                        raise ObservationError("receipt_conflict")
                    return self._status(p, at)
            self.db.execute("INSERT INTO fraud_receipts VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(account_id,node_id) DO UPDATE SET revision=excluded.revision,limited=excluded.limited,applied=excluded.applied,received_at=excluded.received_at,error_code=excluded.error_code,sequence=excluded.sequence",
                            (account, node_id, revision, int(limited), int(applied), at, error_code, sequence))
            status = self._status(p, at)
            if status["state"] == "limited":
                self.db.execute("INSERT OR IGNORE INTO fraud_notifications(incident_id,state,next_attempt_at,updated_at) VALUES(?,'queued',?,?)", (p["incident_id"], at, at))
            return status

    def release(self, account, incident_id, at, *, actor):
        identifier(account); identifier(actor); integer(incident_id, 1)
        with self.transaction():
            self._expire(at)
            incident = self.db.execute("SELECT * FROM fraud_incidents WHERE id=? AND account_id=?", (incident_id, account)).fetchone()
            if not incident:
                raise ObservationError("incident_conflict")
            if incident["end_reason"] == "admin_release":
                return False
            p = self.db.execute("SELECT * FROM fraud_policy WHERE account_id=?", (account,)).fetchone()
            if not p["limited"] or p["incident_id"] != incident_id:
                raise ObservationError("incident_conflict")
            self._clock(at)
            self._event(account, "shadow_released", at, None, {"incident_id": incident_id})
            self.db.execute("UPDATE accounts SET cycle_start=?,shadow_until=NULL,evaluated_at=? WHERE id=?", (at, at, account))
            self.db.execute("UPDATE fraud_incidents SET ended_by=? WHERE id=?", (actor, incident_id))
            self.db.execute("INSERT INTO fraud_audit(account_id,incident_id,actor,action,at) VALUES(?,?,?,'release',?)", (account, incident_id, actor, at))
            return True

    def claim_notification(self, at):
        with self.transaction():
            self._expire(at)
            candidates = self.db.execute("SELECT n.*,i.account_id,i.until_ms,i.threshold_bytes FROM fraud_notifications n JOIN fraud_incidents i ON i.id=n.incident_id WHERE n.state='queued' AND n.next_attempt_at<=? ORDER BY n.incident_id", (at,)).fetchall()
            for row in candidates:
                p = self.db.execute("SELECT * FROM fraud_policy WHERE account_id=?", (row["account_id"],)).fetchone()
                if p["incident_id"] != row["incident_id"] or self._status(p, at)["state"] != "limited":
                    continue
                token = secrets.token_hex(24)
                self.db.execute("UPDATE fraud_notifications SET state='sending',claim_token=?,attempts=attempts+1,updated_at=? WHERE incident_id=?", (token, at, row["incident_id"]))
                return {"incident_id": row["incident_id"], "account_id": row["account_id"], "until_ms": row["until_ms"], "threshold_bytes": row["threshold_bytes"], "claim_token": token}
            return None

    def finish_notification(self, incident_id, token, outcome, at, *, message_id=None, retry_after_ms=30_000):
        integer(incident_id, 1); integer(at)
        if outcome not in ("delivered", "forbidden", "unknown", "not_sent") or not isinstance(token, str):
            raise ObservationError("invalid_delivery_outcome")
        if outcome == "delivered":
            integer(message_id, 1)
        elif message_id is not None:
            raise ObservationError("invalid_delivery_outcome")
        integer(retry_after_ms, 1)
        with self.transaction():
            self._expire(at)
            r = self.db.execute("SELECT * FROM fraud_notifications WHERE incident_id=?", (incident_id,)).fetchone()
            if not r or r["state"] != "sending" or not secrets.compare_digest(r["claim_token"] or "", token):
                raise ObservationError("notification_claim_conflict")
            state = "queued" if outcome == "not_sent" else outcome
            ended = self.db.execute("SELECT ended_at FROM fraud_incidents WHERE id=?", (incident_id,)).fetchone()[0]
            if ended is not None and state == "queued":
                state = "cancelled"
            self.db.execute("UPDATE fraud_notifications SET state=?,claim_token=NULL,message_id=?,next_attempt_at=?,updated_at=? WHERE incident_id=?",
                            (state, message_id, integer(at + retry_after_ms), at, incident_id))

    def notification_current(self, incident_id, token, at):
        """Recheck immediately before sending, after recipient lookup awaits."""
        integer(incident_id, 1)
        if not isinstance(token, str):
            raise ObservationError('invalid_delivery_outcome')
        with self.transaction():
            self._expire(at)
            row=self.db.execute('SELECT * FROM fraud_notifications WHERE incident_id=?',(incident_id,)).fetchone()
            if not row or row['state']!='sending' or not secrets.compare_digest(row['claim_token'] or '',token):
                return False
            policy=self.db.execute('SELECT * FROM fraud_policy WHERE incident_id=?',(incident_id,)).fetchone()
            return bool(policy and policy['limited'] and self._status(policy,at)['state']=='limited')

    def _report(self, at):
        result = super()._report(at)
        result.update(mode="antifraud", enforcement=False, user_notifications=False)
        # These booleans describe this controller's lack of external side effects.
        # Per-account node receipts describe the separately integrated data plane.
        for account in result["accounts"]:
            p = self.db.execute("SELECT * FROM fraud_policy WHERE account_id=?", (account["account_id"],)).fetchone()
            account["policy"] = {k: p[k] for k in ("revision", "incident_id", "limited", "until_ms")}
            account["policy"]["limited"] = bool(p["limited"])
            account["policy"].update(self._status(p, at))
            if p["limited"] and at >= p["until_ms"]:
                account["policy"]["state"] = "expiry_pending_tick"
        result["incidents"] = [dict(r) for r in self.db.execute("SELECT * FROM fraud_incidents ORDER BY id")]
        result["notifications"] = [dict(r) for r in self.db.execute("SELECT incident_id,state,attempts,message_id FROM fraud_notifications ORDER BY incident_id")]
        return result

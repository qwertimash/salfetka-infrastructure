"""One durable byte schedule per account, shared by all nodes and both directions.

Only authenticated node adapters may open sessions/reserve. This module does not
listen on a socket. A permit is consumed once by the node BEFORE forwarding;
its short validity window bounds delayed-packet bursts. No per-node 1 Mbps caps.
"""
from __future__ import annotations

import secrets
import time

from services.antifraud import Controller, RATE_BPS
from services.traffic_observation import ObservationError, identifier, integer

MAX_CHUNK = 65_535
STREAM_CHUNK = 16_384
MAX_AHEAD_NS = 1_000_000_000
VALIDITY_NS = 200_000_000
RETENTION_NS = 60_000_000_000


class Budget:
    def __init__(self, controller: Controller):
        self.c = controller

    def open_session(self, node_id, *, previous=None, proposed=None):
        """Authenticated process handoff with compare-and-swap, never by user input."""
        identifier(node_id)
        # Persist proposed in the agent before making the request. A lost reply
        # can then be retried without invalidating fresh receipts or locking out
        # the process. Old sessions still cannot regain ownership.
        if proposed is not None and (not isinstance(proposed, str) or len(proposed)!=48 or any(c not in '0123456789abcdef' for c in proposed)):
            raise ObservationError('invalid_node_session')
        with self.c.transaction():
            if not self.c.db.execute('SELECT 1 FROM meters WHERE node_id=?', (node_id,)).fetchone():
                raise ObservationError('unknown_node')
            old = self.c.db.execute('SELECT session FROM fraud_node_sessions WHERE node_id=?', (node_id,)).fetchone()
            if old and proposed is not None and secrets.compare_digest(old[0], proposed):
                return proposed
            if old and (not isinstance(previous, str) or not secrets.compare_digest(old[0], previous)):
                raise ObservationError('node_session_conflict')
            if not old and previous is not None:
                raise ObservationError('node_session_conflict')
            self.c.db.execute('DELETE FROM fraud_receipts WHERE node_id=?', (node_id,))
            session = proposed or secrets.token_hex(24)
            self.c.db.execute('INSERT INTO fraud_node_sessions VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET session=excluded.session', (node_id, session))
            return session

    def reserve(self, node_id, session, account, sequence, size, direction, at_ns=None):
        identifier(node_id); identifier(account); integer(sequence, 1); integer(size, 1)
        if at_ns is not None:
            integer(at_ns)
        if size > MAX_CHUNK or direction not in ('upload','download') or not isinstance(session,str):
            raise ObservationError('invalid_budget_request')
        with self.c.transaction():
            at_ns = time.time_ns() if at_ns is None else at_ns
            row = self.c.db.execute('SELECT session FROM fraud_node_sessions WHERE node_id=?', (node_id,)).fetchone()
            if not row or not secrets.compare_digest(row[0],session):
                raise ObservationError('stale_node_session')
            if node_id not in self.c._nodes(account):
                raise ObservationError('unbound_account_node')
            self.c._expire(at_ns // 1_000_000)
            p = self.c.db.execute('SELECT * FROM fraud_policy WHERE account_id=?', (account,)).fetchone()
            if not p['limited']:
                return dict(limited=False, revision=p['revision'], server_ns=at_ns)
            budget = self.c.db.execute('SELECT * FROM fraud_budget WHERE account_id=?', (account,)).fetchone()
            if budget and at_ns < budget['observed_ns']:
                raise ObservationError('budget_clock_regressed')
            existing = self.c.db.execute('SELECT * FROM fraud_permits WHERE account_id=? AND node_id=? AND session=? AND sequence=?', (account,node_id,session,sequence)).fetchone()
            if existing:
                if (existing['bytes'],existing['direction']) != (size,direction):
                    raise ObservationError('permit_conflict')
                if existing['revision'] != p['revision'] or at_ns >= existing['expires_ns']:
                    raise ObservationError('permit_expired')
                return self._result(existing,at_ns)
            head = self.c.db.execute('SELECT * FROM fraud_request_heads WHERE account_id=? AND node_id=?', (account,node_id)).fetchone()
            if head and head['session']==session and sequence<=head['sequence']:
                raise ObservationError('stale_budget_request')
            duration = (size * 8 * 1_000_000_000 + RATE_BPS - 1) // RATE_BPS
            start = max(at_ns, budget['next_ns'] if budget and budget['revision']==p['revision'] else at_ns)
            finish = start+duration
            deadline = p['until_ms']*1_000_000
            if finish-at_ns > MAX_AHEAD_NS or finish>=deadline:
                retry = (deadline-at_ns if finish>=deadline else finish-MAX_AHEAD_NS-at_ns)
                return dict(limited=True, status='wait', revision=p['revision'], retry_ns=retry, server_ns=at_ns)
            expires = min(finish+VALIDITY_NS,deadline)
            self.c.db.execute('INSERT INTO fraud_budget VALUES(?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET revision=excluded.revision,next_ns=excluded.next_ns,observed_ns=excluded.observed_ns', (account,p['revision'],finish,at_ns))
            self.c.db.execute('INSERT INTO fraud_request_heads VALUES(?,?,?,?) ON CONFLICT(account_id,node_id) DO UPDATE SET session=excluded.session,sequence=excluded.sequence', (account,node_id,session,sequence))
            self.c.db.execute('INSERT INTO fraud_permits VALUES(?,?,?,?,?,?,?,?,?)', (account,node_id,session,sequence,p['revision'],size,direction,finish,expires))
            self.c.db.execute('DELETE FROM fraud_permits WHERE expires_ns<?', (max(0,at_ns-RETENTION_NS),))
            return dict(limited=True,status='permit',revision=p['revision'],sequence=sequence,bytes=size,
                        send_at_ns=finish,expires_ns=expires,server_ns=at_ns)

    @staticmethod
    def _result(row,now):
        return dict(limited=True,status='permit',revision=row['revision'],sequence=row['sequence'],bytes=row['bytes'],send_at_ns=row['send_at_ns'],expires_ns=row['expires_ns'],server_ns=now)


def local_deadlines(permit, request_started_ns, reply_received_ns):
    """Conservative monotonic deadlines; no synchronized wall clocks required.

    Earliest send measured from response receipt cannot precede server send_at.
    Expiry measured from request start cannot follow server expiry. A slow RTT
    can waste a permit but cannot extend it. Never spend it twice after a retry.
    """
    integer(request_started_ns); integer(reply_received_ns)
    if reply_received_ns < request_started_ns or permit.get('status') != 'permit':
        raise ObservationError('invalid_permit')
    for key in ('server_ns','send_at_ns','expires_ns','bytes','sequence','revision'):
        integer(permit.get(key), 1)
    if permit['bytes']>MAX_CHUNK or permit['expires_ns']<=permit['send_at_ns'] or permit['expires_ns']-permit['send_at_ns']>VALIDITY_NS:
        raise ObservationError('invalid_permit')
    start=reply_received_ns+max(0,permit['send_at_ns']-permit['server_ns'])
    end=request_started_ns+permit['expires_ns']-permit['server_ns']
    if start>=end:
        raise ObservationError('permit_expired')
    return start,end

"""Local-file adapters. Importers must supply authenticated, non-resetting exports.

Never use Remnawave totalBytes/day history as download-only observations.
No provider connection, counter reset or production identity lookup happens here.
"""
from datetime import datetime, timezone

from services.traffic_observation import ObservationError, fields, identifier, integer


def timestamp(value):
    if type(value) is int:
        return integer(value)
    if not isinstance(value, str):
        raise ObservationError("invalid_timestamp")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError
        delta = dt.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return integer(delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000)
    except (ValueError, OverflowError):
        raise ObservationError("invalid_timestamp") from None


def proto_counter(value):
    # protobuf JSON encodes int64 as strings, unlike the panel's Go JSON.
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 19:
        value = int(value)
    return integer(value)


def _sample(m, epoch, seq, at, down):
    return dict(meter=m["id"], epoch=identifier(epoch), sequence=integer(seq),
                observed_at_ms=at, download_bytes=down)


def convert_frames(document, meters):
    fields(document, ["schema_version", "frames"])
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ObservationError("invalid_schema")
    frames = document["frames"]
    if not isinstance(frames, list) or not 1 <= len(frames) <= 10000:
        raise ObservationError("invalid_frames")
    out = []
    for frame in frames:
        if not isinstance(frame, dict):
            raise ObservationError("invalid_frame")
        if frame.get("source") == "xray":
            fields(frame, ["source", "node_id", "epoch", "sequence", "observed_at_ms", "stats"])
            node = identifier(frame["node_id"])
            selected = [m for m in meters if m["node_id"] == node and m["source"] == "xray"]
            fields(frame["stats"], [], ["stat"])
            entries = frame["stats"].get("stat", [])
            if not isinstance(entries, list):
                raise ObservationError("invalid_stats")
            counters = {}
            for entry in entries:
                fields(entry, ["name"], ["value"])
                name = entry["name"]
                if not isinstance(name, str) or len(name) > 512 or name in counters:
                    raise ObservationError("duplicate_or_invalid_counter")
                # An omitted protobuf int64 is zero; an absent stat is NOT zero.
                counters[name] = proto_counter(entry.get("value", 0))
            at = integer(frame["observed_at_ms"])
            for m in selected:
                name = "user>>>" + m["meter_id"] + ">>>traffic>>>downlink"
                out.append(_sample(m, frame["epoch"], frame["sequence"], at, counters.get(name)))
        elif frame.get("source") == "panel":
            fields(frame, ["source", "report"])
            r = frame["report"]
            fields(r, ["receipt", "engine_epoch", "sequence", "observed_at", "usage"])
            receipt = r["receipt"]
            fields(receipt, ["schema_version", "node_id", "installation_id", "generation",
                             "policy_sha256", "status", "usage", "completed_at"], ["error_code"])
            if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["status"] != "applied" or receipt.get("error_code"):
                raise ObservationError("unapplied_report")
            node = identifier(receipt["node_id"])
            selected = [m for m in meters if m["node_id"] == node and m["source"] == "panel"]
            at = timestamp(r["observed_at"])
            if timestamp(receipt["completed_at"]) > at:
                raise ObservationError("invalid_receipt_time")
            integer(receipt["generation"], 1)
            entries = r["usage"]
            if not isinstance(entries, list):
                raise ObservationError("invalid_usage")
            counters = {}
            for u in entries:
                fields(u, ["grant_id", "instance_epoch", "generation", "active", "uplink", "downlink"], ["ready"])
                key = identifier(u["grant_id"])
                integer(u["generation"], 1)
                if key in counters or u["instance_epoch"] != r["engine_epoch"] or u["generation"] != receipt["generation"] or type(u["active"]) is not bool:
                    raise ObservationError("invalid_usage_identity")
                if u["uplink"] is not None:
                    integer(u["uplink"])
                counters[key] = None if u["downlink"] is None else integer(u["downlink"])
            for m in selected:
                out.append(_sample(m, r["engine_epoch"], r["sequence"], at, counters.get(m["meter_id"])))
        else:
            raise ObservationError("unsupported_source")
        if not selected:
            raise ObservationError("unmapped_source")
        if len(out) > 100000:
            raise ObservationError("batch_too_large")
    return out

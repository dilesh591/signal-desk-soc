"""Import alert records from Suricata's mixed EVE JSON stream."""
import hashlib
import json
from contextlib import closing
from datetime import datetime, timezone

from store import connect
from wazuh import parse_export


def ingest_suricata(db, payload):
    if isinstance(payload, str):
        payload = parse_export(payload)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or not 1 <= len(payload) <= 2000:
        raise ValueError("Supply 1 to 2000 EVE records per batch")
    counts = {"inserted": 0, "duplicates": 0, "skipped": 0}
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        for record in payload:
            if not isinstance(record, dict) or not isinstance(record.get("event_type"), str):
                raise ValueError("Expected a Suricata EVE record with event_type")
            if record["event_type"] != "alert":
                counts["skipped"] += 1
                continue
            alert = record.get("alert")
            if not isinstance(alert, dict) or type(alert.get("signature_id")) is not int or not isinstance(alert.get("signature"), str) or not alert["signature"].strip():
                raise ValueError("Alert requires signature_id and signature")
            if any(not isinstance(record.get(k), str) or not record[k].strip() for k in ("src_ip","dest_ip","timestamp")):
                raise ValueError("Alert requires source IP, destination IP and timestamp")
            stamp = datetime.fromisoformat(record["timestamp"])
            if stamp.tzinfo is None:
                raise ValueError("EVE timestamp requires UTC offset")
            raw = json.dumps(record, sort_keys=True, allow_nan=False)
            key = "EVE-" + hashlib.sha256(raw.encode()).hexdigest()[:24]
            if conn.execute("SELECT 1 FROM platform_alerts WHERE id=?", (key,)).fetchone():
                counts["duplicates"] += 1
                continue
            if conn.execute("SELECT 1 FROM events WHERE id=?", (key,)).fetchone():
                raise ValueError("Alert ID conflicts with an existing event")
            at = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
            conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                         (key,"suricata.alert",at,record["src_ip"],str(alert["signature_id"]),record["dest_ip"],key))
            conn.execute("INSERT INTO platform_alerts VALUES(?,?,?)",(key,"suricata",raw))
            conn.execute("INSERT INTO incidents(id,finding,mapping) VALUES(?,?,?)",(key,alert["signature"],"Not applicable"))
            counts["inserted"] += 1
    return counts

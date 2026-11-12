"""Import Wazuh manager alert documents with their original evidence."""
import hashlib
import json
from contextlib import closing
from datetime import datetime, timezone

from store import connect


def parse_export(text):
    text = text.lstrip("\ufeff")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        batch = []
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    batch.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid alert JSON on line {number}") from exc
        return batch
    return value if isinstance(value, list) else [value]


def field(obj, name):
    value = obj.get(name) if isinstance(obj, dict) else None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing Wazuh field: {name}")
    return value


def ingest_wazuh(db, payload):
    if isinstance(payload, str):
        payload = parse_export(payload)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list) or not 1 <= len(payload) <= 2000:
        raise ValueError("Import between 1 and 2000 Wazuh alerts per batch")
    inserted = 0
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        for alert in payload:
            source_id = field(alert, "id")
            manager = field(alert.get("manager"), "name")
            agent = field(alert.get("agent"), "id")
            host = alert["agent"].get("name") or agent
            rule = alert.get("rule")
            rule_id = field(rule, "id")
            description = field(rule, "description")
            if type(rule.get("level")) is not int or not isinstance(host, str):
                raise ValueError("Invalid Wazuh rule level or agent name")
            stamp = datetime.fromisoformat(field(alert, "timestamp"))
            if stamp.tzinfo is None:
                raise ValueError("Wazuh timestamp requires UTC offset")
            at = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
            key = json.dumps([manager,source_id], ensure_ascii=True).encode()
            case_id = "WZ-" + hashlib.sha256(key).hexdigest()[:24]
            raw = json.dumps(alert, sort_keys=True, allow_nan=False)
            existing = conn.execute("SELECT payload FROM wazuh_alerts WHERE id=?", (case_id,)).fetchone()
            if existing:
                if existing["payload"] != raw:
                    raise ValueError(f"Conflicting Wazuh alert {source_id} on {manager}")
                continue
            if conn.execute("SELECT 1 FROM events WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Alert ID conflicts with an existing audit event")
            conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)",
                         (case_id, "wazuh.alert", at, manager, "rule " + rule_id, host, case_id))
            conn.execute("INSERT INTO incidents(id,finding,mapping) VALUES(?,?,?)",
                         (case_id, description, "Not applicable"))
            conn.execute("INSERT INTO wazuh_alerts VALUES(?,?)", (case_id,raw))
            inserted += 1
    return {"inserted":inserted,"duplicates":len(payload)-inserted}

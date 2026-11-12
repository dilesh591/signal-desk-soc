"""Local incident correlation and analyst decisions."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

TECHNIQUE = "AML.T0053"
FIELDS = ("id", "kind", "at", "actor", "action", "target", "request_id")
KINDS = {"approval.granted", "tool.completed", "tool.denied"}
STATES = {"Open", "Investigating", "Escalated", "Closed"}
MAPPINGS = {"Pending review", "Accepted", "Rejected", "Insufficient evidence"}


def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, kind TEXT, at TEXT, actor TEXT,
          action TEXT, target TEXT, request_id TEXT
        );
        CREATE INDEX IF NOT EXISTS request_events ON events(request_id, at);
        CREATE TABLE IF NOT EXISTS wazuh_alerts (
          id TEXT PRIMARY KEY REFERENCES events(id), payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS platform_alerts (
          id TEXT PRIMARY KEY REFERENCES events(id), source TEXT NOT NULL, payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS incidents (
          id TEXT PRIMARY KEY REFERENCES events(id), finding TEXT NOT NULL,
          status TEXT DEFAULT 'Open', mapping TEXT DEFAULT 'Pending review',
          note TEXT DEFAULT '', revision INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reviews (
          id INTEGER PRIMARY KEY, incident TEXT, at TEXT, status TEXT, mapping TEXT, note TEXT
        );
    """)
    return conn


def normalize(event):
    if not isinstance(event, dict) or set(event) != set(FIELDS):
        raise ValueError("Each event must contain exactly " + ", ".join(FIELDS))
    for key in FIELDS:
        if not isinstance(event[key], str) or not 1 <= len(event[key].strip()) <= 180:
            raise ValueError("Invalid value for " + key)
        if event[key] != event[key].strip() or not event[key].isprintable():
            raise ValueError("Whitespace or control character in " + key)
    if event["kind"] not in KINDS:
        raise ValueError("Unsupported event kind")
    try:
        stamp = datetime.fromisoformat(event["at"])
        if stamp.tzinfo is None:
            raise ValueError
        at = stamp.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        raise ValueError("Event time must include a date, time and UTC offset") from None
    return dict(event, at=at)


def ingest(db, events):
    if not isinstance(events, list) or not 1 <= len(events) <= 2000:
        raise ValueError("Submit between 1 and 2000 events")
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        inserted = 0
        requests = set()
        for item in events:
            event = normalize(item)
            old = conn.execute("SELECT * FROM events WHERE id=?", (event["id"],)).fetchone()
            if old:
                if dict(old) != event:
                    raise ValueError("Event ID reused with different content: " + event["id"])
                continue
            conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?)", [event[k] for k in FIELDS])
            requests.add(event["request_id"])
            inserted += 1
        for request in requests:
            correlate(conn, request)
    return {"inserted": inserted, "duplicates": len(events) - inserted}


def correlate(conn, request):
    records = conn.execute("SELECT * FROM events WHERE request_id=? ORDER BY at,id", (request,)).fetchall()
    approvals = [r for r in records if r["kind"] == "approval.granted"]
    for event in records:
        if event["kind"] not in {"tool.completed", "tool.denied"}:
            continue
        valid = any(a["at"] <= event["at"] and all(a[k] == event[k] for k in ("actor","action","target")) for a in approvals)
        if event["kind"] == "tool.denied":
            finding = "Tool request denied"
        elif valid:
            # Keep a previously raised case visible when supporting evidence arrives late.
            conn.execute("UPDATE incidents SET finding='Approval reconciled', revision=revision+1 WHERE id=? AND finding!='Approval reconciled'", (event["id"],))
            continue
        else:
            finding = "Completed without matching approval"
        conn.execute("INSERT OR IGNORE INTO incidents(id,finding) VALUES (?,?)", (event["id"], finding))


def snapshot(db):
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN")
        events = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY at,id")]
        cases = [dict(r) for r in conn.execute("SELECT i.*, e.at,e.request_id,e.target FROM incidents i JOIN events e ON e.id=i.id ORDER BY e.at DESC,e.id")]
        alerts = {r["id"]: json.loads(r["payload"]) for r in conn.execute("SELECT * FROM wazuh_alerts")}
        platforms = {r["id"]: r for r in conn.execute("SELECT * FROM platform_alerts")}
        for case in cases:
            if case["id"] in alerts:
                case["wazuh"] = alerts[case["id"]]
            elif case["id"] in platforms:
                row = platforms[case["id"]]
                case["raw_json"] = row["payload"]
                case[row["source"]] = json.loads(row["payload"])
        reviews = [dict(r) for r in conn.execute("SELECT * FROM reviews ORDER BY id")]
    return {"events": events, "cases": cases, "reviews": reviews}


def review(db, data):
    if not isinstance(data, dict) or not isinstance(data.get("id"), str) or type(data.get("revision")) is not int:
        raise ValueError("Invalid case or revision")
    if data.get("status") not in tuple(STATES):
        raise ValueError("Choose a valid disposition and mapping")
    note = data.get("note")
    if not isinstance(note, str) or not 1 <= len(note.strip()) <= 4000:
        raise ValueError("Enter an analyst note (1–4000 characters)")
    with closing(connect(db)) as conn, conn:
        record = conn.execute("SELECT kind FROM events WHERE id=?", (data["id"],)).fetchone()
        external = record and record["kind"].endswith(".alert")
        if data.get("mapping") not in (("Not applicable",) if external else tuple(MAPPINGS)):
            raise ValueError("Invalid mapping for this case")
        result = conn.execute("UPDATE incidents SET status=?, mapping=?, note=?, revision=revision+1 WHERE id=? AND revision=?",
                              (data["status"], data["mapping"], note.strip(), data["id"], data["revision"]))
        if result.rowcount != 1:
            raise RuntimeError("Case changed. Refresh the queue and review the latest evidence.")
        conn.execute("INSERT INTO reviews(incident,at,status,mapping,note) VALUES(?,?,?,?,?)",
                     (data["id"], datetime.now(timezone.utc).isoformat(), data["status"], data["mapping"], note.strip()))


def suggest(db, case_id, summary):
    if not isinstance(case_id, str) or not isinstance(summary, str) or len(summary) > 4000:
        raise ValueError("Invalid case or summary")
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN")
        case = conn.execute("SELECT e.*, i.finding FROM incidents i JOIN events e ON e.id=i.id WHERE i.id=?", (case_id,)).fetchone()
        approvals = [] if not case else conn.execute("SELECT * FROM events WHERE request_id=? AND kind='approval.granted' ORDER BY at,id", (case["request_id"],)).fetchall()
        alert = None
        if case and case["kind"] == "suricata.alert":
            alert = json.loads(conn.execute("SELECT payload FROM platform_alerts WHERE id=?", (case_id,)).fetchone()[0])
    if not case:
        raise ValueError("Unknown case")
    result = {"technique": None, "evidence": case_id}
    if case["kind"].endswith(".alert"):
        source = case["kind"].split(".")[0].capitalize()
        result["sentence"] = f"{source} recorded {case['finding']} for {case['target']} [{case_id}]."
        if alert:
            result["sentence"] = (f"Suricata signature {alert['alert']['signature_id']} matched traffic from "
                                  f"{alert['src_ip']} to {alert['dest_ip']}. Sensor action: "
                                  f"{alert['alert'].get('action','unspecified')} [{case_id}].")
        result["reason"] = ("Check the source rule and endpoint activity at the alert time." if source == "Wazuh"
                            else "Review the flow endpoints, signature and sensor action against expected traffic.")
    elif case["kind"] == "tool.denied":
        result["sentence"] = f"The request to perform {case['action']} on {case['target']} was denied [{case_id}]."
        result["reason"] = "Check related completion records before recording any impact."
    else:
        text = [f"{case['actor']} completed {case['action']} on {case['target']} [{case_id}]."]
        for approval in approvals:
            differences = [f"{k} was {approval[k]}" for k in ("actor","action","target") if approval[k] != case[k]]
            if approval["at"] > case["at"]:
                differences.append("approval came after completion")
            detail = ", ".join(differences) or "scope and time match"
            text.append(f"Approval [{approval['id']}]: {detail}.")
        if not approvals:
            text.append("No approval was recorded for this request.")
        result["sentence"] = " ".join(text)
        if case["finding"] == "Approval reconciled":
            result["reason"] = "A matching approval is now on record. Review its delivery time before closing."
        else:
            result.update(technique=TECHNIQUE, name="AI Agent Tool Invocation",
                          reason="Possible ATLAS mapping. Verify approval-log completeness and user intent before accepting.")
    return result


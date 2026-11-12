import json
import tempfile
import unittest
from pathlib import Path

from store import snapshot, review, suggest
from suricata import ingest_suricata


class SuricataTests(unittest.TestCase):
    def test_mixed_stream_retry_and_invalid_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "soc.sqlite3"
            alert = json.loads(Path(__file__).with_name("suricata-example.json").read_text())
            alert["flow_id"] = 9223372036854775807
            rows = [alert, {"event_type":"flow"}]
            result = ingest_suricata(db,"\n".join(map(json.dumps,rows)))
            self.assertEqual(result,{"inserted":1,"duplicates":0,"skipped":1})
            case = snapshot(db)["cases"][0]
            review(db,dict(case,note="Verified sensor action",status="Investigating"))
            self.assertEqual(ingest_suricata(db,rows)["duplicates"],1)
            self.assertIn(str(alert["flow_id"]),case["raw_json"])
            self.assertIn(alert["dest_ip"],suggest(db,case["id"],"")["sentence"])
            with self.assertRaises(ValueError):
                ingest_suricata(db,[dict(alert,src_ip="192.0.2.99"),{"event_type":"alert"}])
            self.assertEqual(len(snapshot(db)["cases"]),1)

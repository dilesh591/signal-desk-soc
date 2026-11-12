import json
import tempfile
import unittest
from pathlib import Path

from store import review, snapshot, suggest
from wazuh import ingest_wazuh


class WazuhImportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "soc.db"
        self.alert = json.loads(Path(__file__).with_name("wazuh-example.json").read_text())

    def test_manager_identity_and_review_survive_replay(self):
        other = dict(self.alert, manager={"name":"second"})
        batch = "\n".join(map(json.dumps, [self.alert, other]))
        self.assertEqual(ingest_wazuh(self.db,batch)["inserted"],2)
        case = snapshot(self.db)["cases"][0]
        review(self.db, dict(case, status="Investigating",note="Review deployment ticket"))
        self.assertEqual(ingest_wazuh(self.db,batch)["duplicates"],2)
        self.assertEqual(snapshot(self.db)["reviews"][0]["status"],"Investigating")
        self.assertIsNone(suggest(self.db,case["id"],"Wrong target.")["technique"])

    def test_conflict_rolls_back_new_records(self):
        ingest_wazuh(self.db,self.alert)
        with self.assertRaises(ValueError):
            ingest_wazuh(self.db,[dict(self.alert,id="new"),dict(self.alert,location="other")])
        state = snapshot(self.db)
        self.assertEqual(len(state["events"]),1)
        self.assertEqual(state["cases"][0]["wazuh"],self.alert)

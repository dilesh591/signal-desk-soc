import json
import tempfile
import unittest
from pathlib import Path
from store import ingest, review, snapshot, suggest


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "store.sqlite3"
        self.sample = json.loads(Path(__file__).with_name("example.json").read_text())
        self.approval, self.done = self.sample[:2]

    def test_sample_and_retry(self):
        self.assertEqual(ingest(self.db,self.sample)["inserted"],5)
        self.assertEqual(ingest(self.db,self.sample)["duplicates"],5)
        self.assertEqual({c["id"] for c in snapshot(self.db)["cases"]},{"AUD-408","AUD-410"})

    def test_late_delivery_and_timestamp(self):
        ingest(self.db,[self.done])
        correct = dict(self.approval,target=self.done["target"])
        ingest(self.db,[dict(correct,id="future",at="2026-11-12T09:00:00Z")])
        self.assertEqual(snapshot(self.db)["cases"][0]["finding"],"Completed without matching approval")
        ingest(self.db,[correct])
        self.assertEqual(snapshot(self.db)["cases"][0]["finding"],"Approval reconciled")

    def test_approval_requires_matching_scope(self):
        correct = dict(self.approval,target=self.done["target"])
        for key in ("actor","action","request_id"):
            ingest(self.db,[dict(correct,id=key,**{key:"other"})])
        ingest(self.db,[self.done])
        self.assertEqual(len(snapshot(self.db)["cases"]),1)

    def test_conflict_rolls_back_batch(self):
        ingest(self.db,[self.done])
        with self.assertRaises(ValueError):
            ingest(self.db,[self.approval,dict(self.done,target="different")])
        self.assertEqual(len(snapshot(self.db)["events"]),1)

    def test_review_history_and_stale_revision(self):
        ingest(self.db,self.sample)
        edit = dict(id="AUD-408",revision=0,mapping="Accepted",status="Escalated",note="Wrong ticket [AUD-408].")
        review(self.db,edit)
        with self.assertRaises(RuntimeError):
            review(self.db,edit)
        self.assertEqual(len(snapshot(self.db)["reviews"]),1)

    def test_suggestion_uses_real_evidence_even_with_empty_notes(self):
        ingest(self.db,self.sample)
        finding = suggest(self.db,"AUD-408","")
        self.assertEqual(finding["technique"],"AML.T0053")
        for detail in ("ticket-1042","ticket-1043","[APR-408]","[AUD-408]"):
            self.assertIn(detail, finding["sentence"])
        self.assertIsNone(suggest(self.db,"AUD-410","Unauthorized [AUD-410]")["technique"])
        self.assertEqual(suggest(self.db,"AUD-408","Wrong ticket [AUD-408].")["technique"],"AML.T0053")
        ingest(self.db,[dict(self.approval,id="late-evidence",target=self.done["target"])])
        self.assertIsNone(suggest(self.db,"AUD-408","Unauthorized [AUD-408]")["technique"])


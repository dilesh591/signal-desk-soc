# Signal Desk SOC

Signal Desk monitors approval-controlled AI tool actions and stores the analyst's investigation in SQLite. Feed it audit records from an application or load the included synthetic batch. The queue, evidence citations, ATLAS review, disposition history and Markdown export work end to end.

## Run locally

Use Python 3.11 or later. The service uses the standard library.

```shell
python server.py
```

Open http://127.0.0.1:8780. Choose **Load sample events** to import five synthetic records. Open **AUD-408**, compare the approval for ticket-1043 with the completion on ticket-1042, then try this analyst summary:

> The agent closed ticket-1042 without matching approval [AUD-408]. The approval covers ticket-1043 [APR-408].

Choose **Check ATLAS mapping**, decide whether to accept the suggested technique, set a disposition, then save and export the report. The included second completion has a matching approval and raises no case. A denied tool request creates a separate reviewable case.

## Connect an application

Send a JSON array to `POST /api/events` on the same machine, import a JSON file in the UI, or run:

```shell
python server.py --import-events example.json
```

The UI, HTTP endpoint and CLI use the same validation and correlation rules. Return values report inserted and duplicate counts. A conflicting event ID rejects the entire batch. SQLite persists records under `data/`. Supply the same `--db PATH` to server and importer to use a different database.

Each record has seven required strings:

| Field | Meaning |
|---|---|
| id | Stable, unique source event ID |
| kind | approval.granted, tool.completed or tool.denied |
| at | ISO 8601 event time with UTC offset |
| actor | Identity authorized to invoke the tool, or identity that used it |
| action | Tool operation, such as ticket.close |
| target | Resource affected by the operation |
| request_id | Unique operation correlation ID shared by approval and outcome |

Send only actions your application's policy requires approval for. Normalize source identifiers before ingestion. Approvals bind to request, actor, action and target and must be timestamped at or before completion. Late delivery of an earlier valid approval updates the finding and preserves the analyst's review history. Timestamps and identities are supplied by the local exporter. Use one request ID per operation and an authoritative exporter for approvals and outcomes.

## Scope

Single-user, loopback-only service for trusted local processes. Local JSON ingestion is operational. The first triage assistant uses a deterministic rule for [AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053). It checks whether a sentence cites the relevant completion and mentions a discrepancy. The suggestion requires analyst review. Live Wazuh ingestion, semantic ranking across techniques, named analyst accounts and shared deployment are future integrations.

```shell
python -m unittest -v
```


# Signal Desk SOC

Signal Desk monitors approval-controlled AI tool actions and stores the analyst's investigation in SQLite. Feed it audit records from an application or load the included synthetic batch. The queue, evidence citations, ATLAS review, disposition history and Markdown export work end to end.

## Run locally

Use Python 3.11 or later. The service uses the standard library.

```shell
python server.py
```

Open http://127.0.0.1:8780. Choose **Load sample events** to import five synthetic records. Open **AUD-408**, compare the approval for ticket-1043 with the completion on ticket-1042, then try this analyst summary:

> The agent closed ticket-1042 without matching approval [AUD-408]. The approval covers ticket-1043 [APR-408].

Choose **AI investigations → Analyze evidence** to compare the completion and its approvals. You can start with an empty note. **Add finding to summary** inserts the cited records into your draft. Review the suggested technique, set a disposition, then save and export the report. The second sample completion has a matching approval and raises no case. A denied tool request creates a separate reviewable case.

## React interface

The React interface includes a searchable case queue and an audit log for all events, including approved actions that raised no incident. Select an event ID in the timeline to cite it. Unsaved case edits survive switching cases or views within the open page.

The server ships with the compiled frontend. To edit it, install Node.js 24 and the pnpm version listed in `package.json`, edit the JSX under `frontend/`, then run:

```shell
pnpm install --frozen-lockfile
pnpm run build
```

Refresh the browser to load the new bundle.

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

### Wazuh investigations

Open **Wazuh** and choose **Import Wazuh alerts**. Import a JSON alert, an array, or newline-delimited records from the manager's `/var/ossec/logs/alerts/alerts.json`. The browser accepts up to 1 MiB per HTTP request and 2,000 alerts per batch. **Load sample Wazuh alert** imports a synthetic file-change alert into your selected database. Inspect the rule, severity, agent, reported ATT&CK mapping and original log, then save a disposition and export the evidence.

```shell
python server.py --import-wazuh alerts.json
```

Local integrations can POST an alert or array to `/api/wazuh`. An exporter can also pipe one JSON alert per line to `python server.py --wazuh-stream`. Each streamed line commits before the next is read. Importing an identical manager and alert ID twice preserves the existing case and review. Conflicting content for that identity rejects the batch. Refresh the UI to see newly ingested alerts. Native manager JSON is documented in the [Wazuh alert example](https://documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/command-output-analysis.html).

### Deployment

Single-user, loopback-only service for trusted local processes. Live feeds require an exporter or transport from the relevant source. The local assistant compares recorded activity and approvals to support analyst review of [AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053).

### Suricata investigations

Open **Suricata → Import Suricata alerts** to import an EVE JSON object, array, or newline-delimited file. The local API accepts these at `POST /api/suricata` as a JSON object, array, or JSON string containing lines. Each request supports up to 2,000 records and 1 MiB. Only EVE alert records become cases. Signal Desk reports the count of skipped non-alert records and deduplicates identical alert content. The network signature, source and destination addresses, and original evidence are available for review and export. [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-format.html)

```shell
python -m unittest -v
```


import {useState} from "react";
import {downloadReport, eventName, mappings, request, statuses, timestamp} from "./service.js";

export function Status({value}) {
  return <span className={"status " + value.toLowerCase()}>{value}</span>;
}

export default function Investigation({incident, events, history, draft, edit, discard, save, busy, reportError}) {
  const [result, setResult] = useState(null);
  const [checking, setChecking] = useState(false);
  const values = draft || incident;
  const stale = draft && draft.revision !== incident.revision;
  const suggestion = result?.summary === values.note && result.revision === incident.revision ? result.data : null;

  async function checkMapping() {
    setChecking(true);
    try {
      const data = await request("/api/triage", {id:incident.id, summary:values.note});
      setResult({summary:values.note, revision:incident.revision, data});
    } catch (error) {
      reportError(error.message);
    } finally {
      setChecking(false);
    }
  }

  return <article className="panel detail">
    <div className="case-meta"><code>{incident.id}</code><Status value={incident.status}/></div>
    <h2>{incident.finding}</h2>
    <div className="case-facts"><span>Target <b>{incident.target}</b></span>{incident.wazuh ? <span>Source alert <code>{incident.wazuh.id}</code></span> : <span>Request <code>{incident.request_id}</code></span>}</div>
    {incident.wazuh && <WazuhEvidence alert={incident.wazuh}/>}
    <section><h3>Evidence timeline <small>{events.length}</small></h3>
      <ol id="events" className="timeline">{events.map(e => <li key={e.id}>
        <div className="event-line"><strong>{eventName(e.kind)}</strong>
          <button className="cite" disabled={busy} title={"Cite " + e.id} onClick={() => edit({note:(values.note + " [" + e.id + "]").trimStart()})}>{e.id}</button></div>
        <p>{e.actor} <span>·</span> {e.action} <span>·</span> <b>{e.target}</b></p>
        <time dateTime={e.at}>{timestamp(e.at)}</time>
      </li>)}</ol>
    </section>
    <form onSubmit={ev => {ev.preventDefault(); save();}}>
      <h3>Analyst review</h3>
      <label htmlFor="note">Incident summary</label>
      <textarea id="note" disabled={busy} required maxLength={4000} rows="4" value={values.note}
        placeholder="Describe the finding and cite the relevant evidence IDs."
        onChange={e => edit({note:e.target.value})}/>
      {!incident.wazuh && <button className="secondary" type="button" onClick={checkMapping} disabled={checking || !values.note.trim()}>{checking ? "Checking…" : "Check ATLAS mapping"}</button>}
      {suggestion && <div className="suggestion" aria-live="polite">
        {suggestion.technique && <><a href="https://atlas.mitre.org/techniques/AML.T0053" target="_blank" rel="noreferrer">{suggestion.technique} · {suggestion.name}</a><blockquote>{suggestion.sentence}</blockquote></>}
        <p>{suggestion.reason}</p>
      </div>}
      <div className="form-grid"><label>Disposition<select id="status" disabled={busy} value={values.status} onChange={e=>edit({status:e.target.value})}>{statuses.map(s=><option key={s}>{s}</option>)}</select></label>
        {!incident.wazuh && <label>AML.T0053 review<select id="mapping" disabled={busy} value={values.mapping} onChange={e=>edit({mapping:e.target.value})}>{mappings.map(s=><option key={s}>{s}</option>)}</select></label>}</div>
      {stale && <p role="alert">The saved case changed while you were editing. <button className="text-button" type="button" onClick={discard}>Use latest saved review</button></p>}
      <div className="controls"><button className="primary" disabled={busy || stale || !values.note.trim()}>Save review</button>
        <button className="secondary" type="button" onClick={()=>downloadReport(incident, events, history)}>Export saved report</button></div>
    </form>
    <details><summary>Review history <small>{history.length}</small></summary>
      {history.length ? history.map(r => <div className="history" key={r.id}><strong>{r.status} · {r.mapping}</strong><time>{timestamp(r.at)}</time><p>{r.note}</p></div>) : <p className="quiet">No reviews saved yet.</p>}
    </details>
  </article>;
}

function WazuhEvidence({alert}) {
  const techniques = alert.rule.mitre?.id;
  return <section><h3>Wazuh rule {alert.rule.id}</h3>
    <div className="case-facts"><span>Level <b>{alert.rule.level}</b></span><span>Manager <b>{alert.manager.name}</b></span><span>Agent ID <code>{alert.agent.id}</code></span></div>
    {typeof alert.location==="string" && <p>Log source <code>{alert.location}</code></p>}
    {Array.isArray(techniques) && <p>Rule ATT&amp;CK mapping <code>{techniques.filter(t=>typeof t==="string").join(", ")}</code></p>}
    {typeof alert.full_log==="string" && <pre className="raw-log">{alert.full_log}</pre>}
    <details><summary>Original alert JSON</summary><pre className="raw-log">{JSON.stringify(alert,null,2)}</pre></details>
  </section>;
}


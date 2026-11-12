import {useEffect, useRef, useState} from "react";
import {createRoot} from "react-dom/client";
import Investigation, {Status} from "./Investigation.jsx";
import {eventName, request, statuses, timestamp} from "./service.js";

const sources = {
  "AI investigations": {endpoint:"/api/events", sample:"/example.json", label:"AI activity", matches:c=>!c.wazuh && !c.suricata},
  Wazuh: {endpoint:"/api/wazuh", sample:"/wazuh-example.json", label:"Wazuh alerts", matches:c=>!!c.wazuh},
  Suricata: {endpoint:"/api/suricata", sample:"/suricata-example.json", label:"Suricata alerts", matches:c=>!!c.suricata},
};

function AuditLog({events}) {
  const [search, setSearch] = useState("");
  const matching = events.filter(e => Object.values(e).join(" ").toLowerCase().includes(search.trim().toLowerCase())).reverse();
  return <section className="panel log"><div className="panel-heading"><h2>Audit records</h2>
    <input type="search" aria-label="Search audit records" placeholder="Search audit records" value={search} onChange={e=>setSearch(e.target.value)}/></div>
    {matching.length ? <div className="scroll"><table><thead><tr>{["Time (UTC)","Event","Actor","Action","Target","Request"].map(t=><th key={t}>{t}</th>)}</tr></thead>
      <tbody>{matching.map(e=><tr key={e.id}><td>{timestamp(e.at).replace(" UTC","")}</td><td><strong>{eventName(e.kind)}</strong><code>{e.id}</code></td><td>{e.actor}</td><td>{e.action}</td><td>{e.target}</td><td>{e.request_id}</td></tr>)}</tbody></table></div> : <p className="quiet">No matching audit records.</p>}</section>;
}

function App() {
  const [data,setData] = useState({events:[],cases:[],reviews:[]});
  const [view,setView] = useState("Incidents");
  const [selected,setSelected] = useState(null);
  const [filter,setFilter] = useState("All dispositions");
  const [query,setQuery] = useState("");
  const [drafts,setDrafts] = useState(new Map());
  const [message,setMessage] = useState("");
  const [busy,setBusy] = useState(true);
  const upload = useRef();
  const source = sources[view];
  const latest = useRef(0);
  async function refresh() {
    const attempt = ++latest.current;
    const state = await request("/api/state");
    if (attempt === latest.current) setData(state);
  }
  async function perform(fn) {
    setBusy(true);
    try {await fn();} catch (e) {setMessage(e.message);} finally {setBusy(false);}
  }
  useEffect(()=>{perform(refresh);},[]);
  const visible = data.cases.filter(c =>
    (!source || source.matches(c)) &&
    (filter === "All dispositions" || c.status === filter) &&
    [c.id,c.target,c.finding,c.request_id,c.wazuh?.id,c.wazuh?.rule.id,c.wazuh?.manager.name,c.suricata?.src_ip,c.suricata?.alert.signature_id].join(" ").toLowerCase().includes(query.trim().toLowerCase())
  );
  const active = visible.find(c=>c.id===selected) || visible[0];
  const scopedCases = source ? data.cases.filter(source.matches) : data.cases;
  const stats = [
    ["Open cases",scopedCases.filter(c=>c.status==="Open").length,"blue"],
    ["Investigating",scopedCases.filter(c=>c.status==="Investigating").length,"teal"],
    ["Escalated",scopedCases.filter(c=>c.status==="Escalated").length,"amber"],
    [source?"Source cases":"Audit events",source?scopedCases.length:data.events.length,"violet"],
  ];
  function edit(patch) {
    setDrafts(old => new Map(old).set(active.id, {...(old.get(active.id) || active), ...patch}));
  }
  function discard(id) {
    setDrafts(old => {
      const next = new Map(old);
      next.delete(id);
      return next;
    });
  }
  async function save() {
    const id=active.id;
    const values=drafts.get(id) || active;
    await perform(async()=>{
      try {
        await request("/api/review",{id,revision:values.revision,mapping:values.mapping,status:values.status,note:values.note});
      } catch (e) {
        await refresh(); throw e;
      }
      discard(id); await refresh(); setMessage("Analyst review saved.");
    });
  }
  async function ingest(batch, path="/api/events") {
    const result=await request(path,batch);
    await refresh(); setMessage(result.inserted+" events imported · "+result.duplicates+" already present."+(result.skipped?" "+result.skipped+" non-alert records skipped.":""));
  }
  return <div className="shell"><header className="mast"><div className="wrap mast-inner"><div className="brand"><i aria-hidden="true" className="signal"><b/><b/><b/><b/></i>Signal Desk</div>
    <nav aria-label="Workspace">{["Incidents",...Object.keys(sources),"Audit log"].map(v=><button key={v} aria-current={view===v?"page":undefined} onClick={()=>{setView(v);setQuery("");setFilter("All dispositions");}}>{v}</button>)}</nav>
    <span className="local">Local workspace</span></div></header>
    <main className="wrap"><div className="pagehead"><h1>{view==="Incidents"?"Incident queue":source && view!=="AI investigations"?view+" investigations":view}</h1>
      <div className="controls"><button className="secondary" disabled={busy} onClick={()=>perform(async()=>{await refresh();setMessage("Records refreshed.");})}>Refresh</button>
      <button className="primary" disabled={busy} onClick={()=>upload.current.click()}>Import {source?.label || "events"}</button>
      <input type="file" ref={upload} hidden accept=".json,.jsonl,.ndjson,application/json" aria-label={"Import "+(source?.label || "events")+" file"} onChange={e=>{
        const file=e.target.files[0];e.target.value="";
        if(file) perform(async()=>{
          const text=await file.text();
          await ingest(source && source.endpoint!=="/api/events"?text:JSON.parse(text),source?.endpoint);
        });
      }}/></div></div>
    <div className="metrics">{stats.map(([name,value,tone])=><div className={"metric "+tone} key={name}><span>{name}</span><strong>{value}</strong></div>)}</div>
    <div role="status" className={message?"notice":"sr-only"}>{message}</div>
    {view==="Audit log" ? <AuditLog events={data.events}/> : <div className="columns"><aside className="panel queue"><div className="panel-heading"><h2>Cases</h2><small>{visible.length}</small></div>
      <input type="search" aria-label="Search cases" placeholder="Search cases or targets" value={query} onChange={e=>setQuery(e.target.value)}/>
      <select aria-label="Filter by disposition" value={filter} onChange={e=>setFilter(e.target.value)}>{["All dispositions",...statuses].map(s=><option key={s}>{s}</option>)}</select>
      <div className="case-list">{visible.map(c=><button className="case" key={c.id} aria-current={active?.id===c.id} onClick={()=>setSelected(c.id)}>
        <span><code>{c.wazuh ? "Wazuh · "+c.wazuh.rule.id : c.suricata ? "Suricata · "+c.suricata.alert.signature_id : c.id}</code><Status value={c.status}/></span><strong>{c.target}</strong><em>{c.finding}</em></button>)}
        {!visible.length && <p className="quiet">{busy?"Loading…":"No matching cases."}</p>}</div>
      <button className="text-button sample" disabled={busy} onClick={()=>perform(async()=>{
        await ingest(await request(source?.sample || "/example.json"),source?.endpoint);
        if(view==="AI investigations") setSelected("AUD-408");
      })}>{view==="Wazuh" || view==="Suricata"?"Load sample "+view+" alert":"Load sample events"}</button>
      </aside>{active ? <Investigation key={active.id} incident={active} draft={drafts.get(active.id)} edit={edit} discard={()=>discard(active.id)} save={save} busy={busy} reportError={setMessage}
        events={data.events.filter(e=>e.kind.endsWith(".alert")?e.id===active.id:!active.wazuh && !active.suricata && e.request_id===active.request_id)} history={data.reviews.filter(r=>r.incident===active.id)}/> :
      <div className="panel empty"><div className="scope-mark" aria-hidden="true">◎</div><h2>{busy?"Loading incidents":"No matching incidents"}</h2><p>Import {source?.label || "events"}, load the sample, or change your filters to find a case.</p></div>}</div>}
    </main></div>;
}
createRoot(document.getElementById("root")).render(<App/>);


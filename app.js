"use strict";
const el = id => document.getElementById(id);
let data = {cases: [], events: [], reviews: []};
let selected = null;
const drafts = new Map();
function notify(message) { el("notice").textContent = message; }
function node(tag, value) {
  const item = document.createElement(tag);
  item.textContent = value;
  return item;
}
async function api(path, body) {
  const options = body === undefined ? {} : {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)};
  const res = await fetch(path, options);
  if (!res.ok) throw Error((await res.json()).error || res.statusText);
  return res.json();
}
function incident() { return data.cases.find(c => c.id === selected); }
function records(c) { return data.events.filter(e => e.request_id === c.request_id); }
function draft() {
  if (!incident()) return;
  const previous = drafts.get(selected);
  drafts.set(selected, {revision:previous?.revision ?? incident().revision, note:el("note").value,status:el("status").value,mapping:el("mapping").value});
}
function render() {
  const visible = data.cases.filter(c => el("filter").value === "All cases" || c.status === el("filter").value);
  if (!visible.some(c => c.id === selected)) selected = visible[0]?.id;
  el("counts").textContent = data.events.length + " audit events · " + data.cases.length + " cases";
  el("queue").replaceChildren();
  for (const c of visible) {
    const b = node("button", c.target);
    b.setAttribute("aria-current", String(c.id === selected));
    b.append(node("small", c.id + " · " + c.status));
    b.onclick = () => { selected = c.id; render(); };
    el("queue").append(b);
  }
  const c = incident();
  el("detail").hidden = !c;
  el("empty").hidden = !!c;
  el("empty").textContent = data.events.length ? "No cases match this view." : "Import an audit event batch or load the sample to start an investigation.";
  if (!c) return;
  const d = drafts.get(c.id) || c;
  el("caseid").textContent = c.id;
  el("state").textContent = c.status;
  el("finding").textContent = c.finding;
  el("target").textContent = c.target + " · Request " + c.request_id;
  el("events").replaceChildren();
  for (const e of records(c)) {
    const row = node("div",""); row.className = "event";
    const cite = node("button",e.id); cite.title = "Insert evidence reference";
    cite.onclick = () => { el("note").value += " [" + e.id + "]"; draft(); el("note").focus(); };
    row.append(cite,document.createTextNode("  " + e.kind),node("p", e.actor + " · " + e.action + " · " + e.target));
    const t = node("span",e.at.replace(".000000+00:00","Z")); t.className = "meta"; row.append(t);
    el("events").append(row);
  }
  el("note").value = d.note; el("status").value = d.status; el("mapping").value = d.mapping;
  el("suggestion").replaceChildren();
  el("history").replaceChildren(...data.reviews.filter(r => r.incident === c.id).map(r => node("p",r.at + " · " + r.status + " · " + r.mapping + "\n" + r.note)));
}
async function refresh() { data = await api("/api/state"); render(); }
function run(fn) { return async ev => { try { await fn(ev); } catch (err) { notify(err.message); } }; }
el("refresh").onclick = run(async () => {
  if (drafts.size && !window.confirm("Discard unsaved edits and reload saved reviews?")) return;
  drafts.clear(); await refresh(); notify("Queue refreshed.");
});
el("filter").onchange = render;
el("review").oninput = () => { draft(); el("suggestion").replaceChildren(); };
async function ingest(batch) {
  const result = await api("/api/events", batch);
  await refresh();
  notify(result.inserted + " events imported · " + result.duplicates + " already present.");
}
el("sample").onclick = run(async () => ingest(await api("/example.json")));
el("import").onchange = run(async e => {
  const file = e.target.files[0]; e.target.value = "";
  if (file) await ingest(JSON.parse(await file.text()));
});
el("triage").onclick = run(async () => {
  const id = selected, summary = el("note").value;
  const r = await api("/api/triage",{id,summary});
  if (selected !== id || summary !== el("note").value) return;
  const items = [node("p",r.reason)];
  if (r.technique) {
    const a = node("a",r.technique + " · " + r.name);
    a.href = "https://atlas.mitre.org/techniques/AML.T0053"; a.target = "_blank"; a.rel = "noopener";
    items.unshift(a,node("blockquote",r.sentence));
  }
  el("suggestion").replaceChildren(...items);
});
el("review").onsubmit = run(async ev => {
  ev.preventDefault(); draft();
  const id = selected;
  await api("/api/review",{id,...drafts.get(id)});
  drafts.delete(id); await refresh(); notify("Analyst review saved.");
});
el("export").onclick = () => {
  const c = incident();
  const lines = ["# Incident " + c.id,c.finding,"Disposition: " + c.status,"AML.T0053 review: " + c.mapping,"## Analyst summary",c.note || "(No review saved)","## Evidence"];
  for (const e of records(c)) lines.push([e.id,e.at,e.kind,e.actor,e.action,e.target,e.request_id].join(" | "));
  lines.push("## Review history");
  for (const r of data.reviews.filter(r => r.incident === c.id)) lines.push([r.at,r.status,r.mapping,r.note].join(" | "));
  const url = URL.createObjectURL(new Blob([lines.join("\n\n")],{type:"text/markdown"}));
  const a = document.createElement("a"); a.href=url; a.download="incident-"+c.id.replace(/[^a-z0-9_-]/gi,"_")+".md"; a.click();
  setTimeout(() => URL.revokeObjectURL(url),5000);
};
run(refresh)();


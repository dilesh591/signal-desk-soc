export const statuses = ["Open", "Investigating", "Escalated", "Closed"];
export const mappings = ["Pending review", "Accepted", "Rejected", "Insufficient evidence"];

export async function request(path, body) {
  const options = body === undefined ? {} : {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  };
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || response.statusText);
  return result;
}

export function downloadReport(incident, events, history) {
  const lines = [
    "# Incident " + incident.id, incident.finding,
    "Disposition: " + incident.status, ...(incident.wazuh || incident.suricata ? [incident.wazuh?"## Wazuh alert":"## Suricata alert",incident.raw_json || JSON.stringify(incident.wazuh,null,2)] : ["AML.T0053 review: " + incident.mapping]),
    "## Analyst summary", incident.note || "(No review saved)", "## Evidence",
    ...events.map(e => [e.id,e.at,e.kind,e.actor,e.action,e.target,e.request_id].join(" | ")),
    "## Review history", ...history.map(r => [r.at,r.status,r.mapping,r.note].join(" | ")),
  ];
  const url = URL.createObjectURL(new Blob([lines.join("\n\n")], {type:"text/markdown"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = "incident-" + incident.id.replace(/[^a-z0-9_-]/gi, "_") + ".md";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function timestamp(value) {
  return new Date(value).toLocaleString("en-GB", {
    day:"2-digit", month:"short", year:"numeric", hour:"2-digit", minute:"2-digit",
    second:"2-digit", hour12:false, timeZone:"UTC"
  }) + " UTC";
}

export function eventName(kind) {
  return {"wazuh.alert":"Wazuh alert","approval.granted":"Approval granted","tool.completed":"Tool completed","tool.denied":"Tool denied"}[kind] || kind;
}


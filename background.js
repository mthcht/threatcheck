/**
 * ThreatCheck Background Service Worker v1.0.0
 * Handles API auto-checks, context menu, keyboard shortcut
 */

/* Context menu + welcome page on install */
chrome.runtime.onInstalled.addListener((details) => {
  chrome.contextMenus.create({
    id: "threatcheck-lookup",
    title: "Look up \"%s\" on ThreatCheck",
    contexts: ["selection"]
  });

  if (details.reason === "install") {
    chrome.tabs.create({ url: "welcome.html" });
  }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "threatcheck-lookup" && info.selectionText && tab?.id) {
    chrome.tabs.sendMessage(tab.id, {
      action: "contextMenuLookup",
      text: info.selectionText
    });
  }
});

/* Keyboard shortcut - Alt+T to look up selected text */
chrome.commands.onCommand.addListener((command) => {
  if (command === "lookup-selection") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "shortcutLookup" });
      }
    });
  }
});

/* API check message handler */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action !== "apiCheck") return false;

  (async () => {
    try {
      const result = await handleApiCheck(msg);
      sendResponse(result);
    } catch (err) {
      console.error("[ThreatCheck BG] Error:", msg.service, err);
      sendResponse({ error: String(err?.message || err) });
    }
  })();

  return true; /* keep message channel open for async response */
});

async function handleApiCheck(msg) {
  const { service, type, value, config } = msg;

  switch (service) {
    case "recordedfuture": return await rfLookup(type, value, config);
    case "opencti": return await openctiLookup(type, value, config);
    case "dnsdumpster": return await dnsdumpsterLookup(value, config);
    case "validin": return await validinLookup(type, value, config);
    case "spur": return await spurLookup(value, config);
    case "urlscan": return await urlscanLookup(type, value, config);
    case "virustotal": return await vtLookup(type, value, config);
    case "abuseipdb": return await abuseipdbLookup(type, value, config);
    case "leakcheck": return await leakcheckLookup(value, config);
    default: return { error: "Unknown service: " + service };
  }
}

/* ═══════════ Recorded Future /soar/v3/enrichment ═══════════
 * POST {base}/soar/v3/enrichment
 * Body: { ip: [...], domain: [...], hash: [...], url: [...], vulnerability: [...] }
 * Header: X-RFToken
 * Response: { data: { results: [ { entity: {name}, risk: {score, level, rule: {count, mostCritical, evidence: {ruleName: {rule,description,level,timestamp,...}}}, context: [...] } } ] } }
 */
async function rfLookup(type, value, config) {
  const token = config?.rf_token;
  if (!token) return { error: "No RF token in config" };

  const base = (config?.rf_base_url || "https://api.recordedfuture.com").replace(/\/+$/, "");

  /* Build payload - RF expects categorized arrays */
  const typeMap = { ip: "ip", domain: "domain", hash: "hash", url: "url", email: "domain", cve: "vulnerability" };
  const rfType = typeMap[type];
  if (!rfType) return { error: "Unsupported type: " + type };

  const payload = {};
  payload[rfType] = [type === "cve" ? value.toUpperCase() : value];

  const resp = await fetch(`${base}/soar/v3/enrichment`, {
    method: "POST",
    headers: {
      "X-RFToken": token,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (resp.status === 404) return { score: null, label: "Not found", color: "#6b7280" };
  if (!resp.ok) return { error: "RF API HTTP " + resp.status };

  const data = await resp.json();
  const results = data?.data?.results;
  if (!results || !results.length) return { score: null, label: "No data", color: "#6b7280" };

  const r = results[0];
  const risk = r.risk;
  if (!risk) return { score: null, label: "No risk data", color: "#6b7280" };

  const score = (typeof risk.score === "number") ? risk.score : null;
  const level = (typeof risk.level === "number") ? risk.level : null;
  const ruleCount = risk.rule?.count || 0;
  const mostCritical = risk.rule?.mostCritical || risk.rule?.mostCriticalRule || "";

  /* Extract evidence - it's an OBJECT, not an array */
  const evObj = risk.rule?.evidence || {};
  const rules = Object.entries(evObj).map(([key, ev]) => ({
    name: ev?.rule || ev?.description || key,
    crit: (typeof ev?.level === "number") ? ev.level : 0,
    critLabel: ev?.level >= 4 ? "Critical" : ev?.level >= 3 ? "Malicious" : ev?.level >= 2 ? "Suspicious" : ev?.level >= 1 ? "Unusual" : "",
    evidence: ev?.description || "",
    timestamp: ev?.timestamp || "",
    count: ev?.count,
    sightings: ev?.sightings
  })).sort((a, b) => (b.crit - a.crit)).slice(0, 15);

  /* Extract context */
  const ctxArr = Array.isArray(risk.context) ? risk.context : [];
  const contexts = [];
  for (const o of ctxArr) {
    if (!o || typeof o !== "object") continue;
    for (const [ctxName, ctxData] of Object.entries(o)) {
      if (ctxData && typeof ctxData === "object") {
        contexts.push({ name: ctxName, score: ctxData.score, mostCriticalRule: ctxData.mostCriticalRule || "" });
      }
    }
  }

  const critLabel = score >= 80 ? "High" : score >= 65 ? "Medium" : score !== null ? "Low" : "Unknown";

  return {
    score,
    label: score !== null ? `${score}/99 ${critLabel}` : "No score",
    color: score !== null ? scoreColor(score) : "#6b7280",
    context: {
      entity: r.entity?.name || value,
      entityType: type,
      riskSummary: mostCritical ? `${ruleCount} rules · Most critical: ${mostCritical}` : `${ruleCount} rules`,
      rules,
      contexts
    }
  };
}

/* ═══════════ OpenCTI GraphQL ═══════════
 * Two-phase: 1) find the observable/indicator  2) fetch its linked context
 */
async function openctiLookup(type, value, config) {
  const baseUrl = config?.opencti_url;
  const token = config?.opencti_token;
  if (!baseUrl || !token) return { error: "OpenCTI not configured" };

  const url = baseUrl.replace(/\/+$/, "") + "/graphql";
  const t = (token || "").trim().replace(/^Bearer\s+/i, "");

  async function gql(q, vars) {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Authorization": "Bearer " + t, "Content-Type": "application/json" },
      body: JSON.stringify({ query: q.replace(/\s+/g, " "), variables: vars })
    });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const j = await r.json();
    if (j.errors?.length) throw new Error(j.errors[0]?.message || "GraphQL error");
    return j.data;
  }

  /* Phase 1: Find the observable/indicator */
  const findQuery = `query($search:String!,$first:Int!){
    stixCoreObjects(search:$search,first:$first){
      edges{node{
        id entity_type standard_id
        createdBy{name}
        ... on StixCyberObservable { observable_value x_opencti_score x_opencti_description }
        ... on Indicator {
          representative{main} x_opencti_score pattern_type confidence valid_from revoked
        }
        ... on StixDomainObject {
          representative{main} created_at updated_at confidence
          ... on ThreatActor{description}
          ... on IntrusionSet{description}
          ... on Malware{description}
          ... on Campaign{description}
          ... on Vulnerability{description}
          ... on Report{description published}
          ... on Note{content}
          ... on Incident{description severity}
          ... on Identity{description}
          ... on Location{description}
          ... on Case{description}
          ... on AdministrativeArea{description}
        }
      }}
    }
  }`;

  let nodes = [];
  try {
    const d = await gql(findQuery, { search: value, first: 25 });
    nodes = (d?.stixCoreObjects?.edges || []).map(e => e.node).filter(Boolean);
  } catch (err) {
    return { error: err.message };
  }

  if (!nodes.length) return { score: null, label: "Not found", color: "#6b7280" };

  /* Phase 2: For the primary entity, fetch its relationships to get real context */
  const primary = nodes.find(n => n.observable_value || n.entity_type === "Indicator") || nodes[0];
  let relNodes = [];
  if (primary?.id) {
    try {
      const relQuery = `query($id:String!,$first:Int!){
        stixCoreRelationships(fromOrToId:$id,first:$first){
          edges{node{
            relationship_type confidence created_at
            from{...on StixDomainObject{id entity_type representative{main}}...on StixCyberObservable{id entity_type observable_value}}
            to{...on StixDomainObject{id entity_type representative{main}}...on StixCyberObservable{id entity_type observable_value}}
          }}
        }
      }`;
      const rd = await gql(relQuery, { id: primary.id, first: 20 });
      relNodes = (rd?.stixCoreRelationships?.edges || []).map(e => e.node).filter(Boolean);
    } catch (_) { /* relationship query may fail on some versions */ }
  }

  /* Also fetch reports mentioning this value */
  let reportNodes = [];
  try {
    const rq = `query($search:String!,$first:Int!){
      reports(search:$search,first:$first){
        edges{node{id entity_type representative{main} description published created_at confidence createdBy{name}}}
      }
    }`;
    const d2 = await gql(rq, { search: value, first: 10 });
    reportNodes = (d2?.reports?.edges || []).map(e => e.node).filter(Boolean);
  } catch (_) { /* reports query optional */ }

  /* Build score */
  let bestScore = null;
  for (const n of nodes) {
    if (typeof n.x_opencti_score === "number" && (bestScore === null || n.x_opencti_score > bestScore))
      bestScore = n.x_opencti_score;
  }

  /* Build context rules from all sources */
  const rules = [];
  const seenIds = new Set();

  /* Reports - these have the real threat context */
  for (const n of reportNodes) {
    if (seenIds.has(n.id)) continue; seenIds.add(n.id);
    const desc = n.description || "";
    const source = n.createdBy?.name || "";
    const evidenceParts = [];
    if (source) evidenceParts.push("Source: " + source);
    if (desc) evidenceParts.push(desc.slice(0, 1200) + (desc.length > 1200 ? "..." : ""));
    rules.push({
      name: n.representative?.main || "Report",
      crit: n.confidence >= 80 ? 4 : n.confidence >= 60 ? 3 : 2,
      critLabel: "Report" + (source ? " · " + source : ""),
      evidence: evidenceParts.join("\n"),
      timestamp: (n.published || n.created_at || "").toString().split("T")[0],
      count: n.confidence
    });
  }

  /* Relationships - shows linked threat actors, malware, campaigns, etc */
  for (const rel of relNodes) {
    const other = (rel.from?.id === primary.id) ? rel.to : rel.from;
    if (!other || seenIds.has(other.id)) continue; seenIds.add(other.id);
    const otherName = other.representative?.main || other.observable_value || other.entity_type || "-";
    const relType = rel.relationship_type || "related-to";
    rules.push({
      name: `${relType}: ${otherName}`,
      crit: rel.confidence >= 80 ? 4 : rel.confidence >= 60 ? 3 : rel.confidence >= 30 ? 2 : 1,
      critLabel: other.entity_type || "relation",
      evidence: "",
      timestamp: (rel.created_at || "").toString().split("T")[0],
      count: rel.confidence
    });
  }

  /* SDOs, indicators, observables from initial search */
  for (const n of nodes) {
    if (seenIds.has(n.id)) continue; seenIds.add(n.id);
    const desc = n.description || n.x_opencti_description || n.content || "";
    const title = n.representative?.main || n.observable_value || n.standard_id || "-";
    const typ = n.entity_type || "unknown";
    const score = n.x_opencti_score;
    const conf = n.confidence;
    const source = n.createdBy?.name || "";

    let crit = 1;
    if (score >= 75 || conf >= 80) crit = 4;
    else if (score >= 50 || conf >= 60) crit = 3;
    else if (score >= 25 || conf >= 30) crit = 2;

    const evidenceParts = [];
    if (source) evidenceParts.push("Source: " + source);
    if (desc) evidenceParts.push(desc.slice(0, 1200) + (desc.length > 1200 ? "..." : ""));
    if (score != null) evidenceParts.push("Score: " + score + "/100");
    if (conf != null) evidenceParts.push("Confidence: " + conf);
    if (n.pattern_type) evidenceParts.push("Type: " + n.pattern_type + " indicator");
    if (n.severity) evidenceParts.push("Severity: " + n.severity);
    if (n.revoked) evidenceParts.push("⚠ Revoked");
    if (n.x_opencti_detection) evidenceParts.push("Detection rule: enabled");

    rules.push({
      name: title,
      crit,
      critLabel: typ + (source ? " · " + source : ""),
      evidence: evidenceParts.join("\n"),
      timestamp: (n.created_at || n.valid_from || n.published || "").toString().split("T")[0],
      count: conf
    });
  }

  /* Sort: entries with descriptions first, then by criticality */
  rules.sort((a, b) => {
    if (b.evidence.length !== a.evidence.length) return b.evidence.length - a.evidence.length;
    return b.crit - a.crit;
  });

  const types = [...new Set([
    ...nodes.map(n => n.entity_type),
    ...relNodes.map(r => (r.from?.id === primary?.id ? r.to : r.from)?.entity_type)
  ].filter(Boolean))];

  const summaryParts = [];
  if (reportNodes.length) summaryParts.push(reportNodes.length + " report" + (reportNodes.length > 1 ? "s" : ""));
  if (relNodes.length) summaryParts.push(relNodes.length + " relationship" + (relNodes.length > 1 ? "s" : ""));
  summaryParts.push(nodes.length + " object" + (nodes.length > 1 ? "s" : ""));

  return {
    score: bestScore,
    label: bestScore != null ? `${bestScore}/100` : `${rules.length} hit${rules.length > 1 ? "s" : ""}`,
    color: bestScore != null ? scoreColor(bestScore) : "#60a5fa",
    context: {
      entity: value,
      entityType: type,
      riskSummary: summaryParts.join(" · "),
      rules: rules.slice(0, 20),
      contexts: types.map(t => ({ name: t, score: null }))
    }
  };
}

/* ═══════════ DNSDumpster API ═══════════
 * GET https://api.dnsdumpster.com/domain/{domain}
 * Header: X-API-Key
 * Returns: a[] (host records), mx[], ns[], txt[], cname[], map (base64 PNG)
 */
async function dnsdumpsterLookup(value, config) {
  const key = (config?.dnsdumpster_key || "").trim();
  if (!key) return { error: "No DNSDumpster key" };

  /* Clean domain - strip protocol, path, port, trailing dots */
  const domain = value.replace(/^https?:\/\//i, "").replace(/[:\/].*/, "").replace(/\.+$/, "").toLowerCase().trim();
  if (!domain || !domain.includes(".")) return { error: "Invalid domain: " + domain };


  const apiUrl = "https://api.dnsdumpster.com/domain/" + domain;
  const hdrs = { "X-API-Key": key, "Accept": "application/json" };

  let resp = await fetch(apiUrl, { headers: hdrs });

  if (resp.status === 429) {
    await new Promise(r => setTimeout(r, 3000));
    resp = await fetch(apiUrl, { headers: hdrs });
  }

  if (resp.status === 401 || resp.status === 403) {
    const body = await resp.text().catch(() => "");
    console.error("[ThreatCheck BG] DNSDumpster auth:", resp.status, body);
    return { error: resp.status + " - check API key" };
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    console.error("[ThreatCheck BG] DNSDumpster error:", resp.status, body);
    return { error: "HTTP " + resp.status + (body ? ": " + body.slice(0, 200) : "") };
  }

  const data = await resp.json();

  /* Handle potential response wrapper */
  const src = data.dns_records || data;
  const aRecs = src.a || [];
  const mxRecs = src.mx || [];
  const nsRecs = src.ns || [];
  const txtRecs = src.txt || [];
  const cnameRecs = src.cname || [];
  const totalA = src.total_a_recs || aRecs.length;

  const rules = [];

  /* Host records (A) */
  for (const rec of aRecs.slice(0, 15)) {
    const host = rec.host || "";
    const ips = rec.ips || [];
    const parts = [];
    for (const ipObj of ips) {
      if (ipObj.ip) parts.push("IP: " + ipObj.ip);
      if (ipObj.ptr) parts.push("PTR: " + ipObj.ptr);
      if (ipObj.asn) parts.push("ASN: AS" + ipObj.asn + " " + (ipObj.asn_name || ""));
      if (ipObj.asn_range) parts.push("Range: " + ipObj.asn_range);
      if (ipObj.country || ipObj.country_code) parts.push("Country: " + (ipObj.country || ipObj.country_code));
      /* Banners */
      const b = ipObj.banners || {};
      for (const proto of Object.keys(b)) {
        if (proto === "ip" || typeof b[proto] !== "object") continue;
        const info = b[proto];
        const bParts = [proto.toUpperCase()];
        if (info.server) bParts.push("Server: " + info.server);
        if (info.title) bParts.push("Title: " + info.title);
        if (info.apps?.length) bParts.push("Apps: " + info.apps.join(", "));
        if (info.cn) bParts.push("CN: " + info.cn);
        if (info.o) bParts.push("Org: " + info.o);
        if (info.tlsver) bParts.push("TLS: " + info.tlsver);
        if (info.status) bParts.push("Status: " + info.status);
        parts.push(bParts.join(" | "));
      }
    }
    rules.push({
      name: host,
      crit: 2,
      critLabel: "A",
      evidence: parts.join("\n"),
      timestamp: "",
      count: ips.length
    });
  }

  /* MX records */
  for (const rec of mxRecs) {
    const firstIp = (rec.ips || [])[0] || {};
    const parts = [];
    if (firstIp.ip) parts.push("IP: " + firstIp.ip);
    if (firstIp.ptr) parts.push("PTR: " + firstIp.ptr);
    if (firstIp.asn_name) parts.push("ASN: " + firstIp.asn_name);
    rules.push({
      name: rec.host || "MX",
      crit: 1,
      critLabel: "MX",
      evidence: parts.join("\n"),
      timestamp: "",
      count: null
    });
  }

  /* NS records */
  for (const rec of nsRecs) {
    const firstIp = (rec.ips || [])[0] || {};
    const parts = [];
    if (firstIp.ip) parts.push("IP: " + firstIp.ip);
    if (firstIp.asn_name) parts.push("ASN: " + firstIp.asn_name);
    if (firstIp.country_code) parts.push("Country: " + firstIp.country_code);
    rules.push({
      name: rec.host || "NS",
      crit: 1,
      critLabel: "NS",
      evidence: parts.join("\n"),
      timestamp: "",
      count: null
    });
  }

  /* TXT records */
  if (txtRecs.length) {
    const txtParts = txtRecs.slice(0, 20).map(t => {
      const clean = (typeof t === "string" ? t : String(t)).replace(/^"|"$/g, "");
      if (/spf/i.test(clean)) return "[SPF] " + clean;
      if (/dmarc/i.test(clean)) return "[DMARC] " + clean;
      if (/verification|verify/i.test(clean)) return "[VERIFY] " + clean;
      return clean;
    });
    rules.push({
      name: txtRecs.length + " TXT record" + (txtRecs.length > 1 ? "s" : ""),
      crit: 1,
      critLabel: "TXT",
      evidence: txtParts.join("\n"),
      timestamp: "",
      count: txtRecs.length
    });
  }

  /* CNAME records */
  for (const rec of cnameRecs) {
    rules.push({
      name: (rec.host || rec) + (rec.target ? " -> " + rec.target : ""),
      crit: 1,
      critLabel: "CNAME",
      evidence: "",
      timestamp: "",
      count: null
    });
  }

  const summaryParts = [];
  summaryParts.push(totalA + " host" + (totalA !== 1 ? "s" : ""));
  if (mxRecs.length) summaryParts.push(mxRecs.length + " MX");
  if (nsRecs.length) summaryParts.push(nsRecs.length + " NS");
  if (txtRecs.length) summaryParts.push(txtRecs.length + " TXT");
  if (cnameRecs.length) summaryParts.push(cnameRecs.length + " CNAME");

  const totalRecords = totalA + mxRecs.length + nsRecs.length + txtRecs.length + cnameRecs.length;

  return {
    score: totalRecords,
    label: summaryParts.join(" / "),
    color: "#60a5fa",
    context: {
      entity: domain,
      entityType: "domain",
      riskSummary: summaryParts.join(" - "),
      rules,
      contexts: [
        { name: "A: " + totalA, score: null },
        { name: "MX: " + mxRecs.length, score: null },
        { name: "NS: " + nsRecs.length, score: null },
        { name: "TXT: " + txtRecs.length, score: null }
      ].filter(c => !c.name.endsWith(": 0"))
    }
  };
}

/* ═══════════ Validin API ═══════════
 * GET https://app.validin.com/api/axon/domain/dns/history/{domain}
 * or  https://app.validin.com/api/axon/ip/dns/history/{ip}
 * Header: Authorization: BEARER <key>
 */
async function validinLookup(type, value, config) {
  const key = config?.validin_key;
  if (!key) return { error: "No Validin key" };

  const path = type === "ip"
    ? `ip/dns/history/${encodeURIComponent(value)}`
    : `domain/dns/history/${encodeURIComponent(value)}`;

  const resp = await fetch(
    `https://app.validin.com/api/axon/${path}`,
    { headers: { "Authorization": "BEARER " + key, "Accept": "application/json" } }
  );

  if (!resp.ok) return { error: "Validin HTTP " + resp.status };

  const data = await resp.json();
  const records = data?.records?.length || data?.data?.length || 0;

  return { score: records, label: `${records} records`, color: "#a29bfe" };
}

/* ═══════════ Helpers ═══════════ */
/* ═══════════ Spur Context API v2 ═══════════
 * GET https://api.spur.us/v2/context/{ip}
 * Header: Token: {api_token}
 * Returns: tunnels, risks, infrastructure, services, client, location
 */
async function spurLookup(value, config) {
  const token = (config?.spur_token || "").trim();
  if (!token) return { error: "No Spur token" };


  const url = `https://api.spur.us/v2/context/${encodeURIComponent(value)}`;
  const hdrs = { "Token": token, "Accept": "application/json" };

  let resp = await fetch(url, { headers: hdrs });

  /* Rate limit retry */
  if (resp.status === 429) {
    await new Promise(r => setTimeout(r, 3000));
    resp = await fetch(url, { headers: hdrs });
  }

  if (resp.status === 404) return { score: null, label: "Not found", color: "#6b7280" };
  if (resp.status === 401) {
    const body = await resp.text().catch(() => "");
    console.error("[ThreatCheck BG] Spur 401:", body);
    return { error: "401 Unauthorized" + (body ? ": " + body.slice(0, 100) : " - check token") };
  }
  if (resp.status === 403) {
    const body = await resp.text().catch(() => "");
    return { error: "403 Forbidden" + (body ? ": " + body.slice(0, 100) : "") };
  }
  if (!resp.ok) return { error: "Spur HTTP " + resp.status };

  const data = await resp.json();

  const tunnels = data.tunnels || [];
  const risks = data.risks || [];
  const services = data.services || [];
  const infra = data.infrastructure || "";
  const client = data.client || {};
  const loc = data.location || {};
  const as = data.as || {};
  const org = data.organization || as.organization || "";

  /* Verdict logic matching user's code */
  let label = "Clean";
  let color = "#22c55e";

  if (tunnels.length) {
    const t = tunnels[0];
    const op = t.operator ? t.operator.replace(/_/g, " ") : "";
    label = t.type + (op ? ": " + op : "");
    color = (t.type === "TOR") ? "#ef4444" : (t.type === "PROXY") ? "#ef4444" : "#f59e0b";
  }
  if (risks.length && !tunnels.length) {
    label = risks[0].replace(/_/g, " ");
    color = "#f59e0b";
  }
  if (risks.some(r => r.includes("CALLBACK_PROXY") || r.includes("MALWARE"))) {
    color = "#ef4444";
  }
  if (tunnels.some(t => t.type === "TOR")) {
    label = "TOR";
    color = "#ef4444";
  }
  if (!tunnels.length && !risks.length) {
    label = infra || "Clean";
    color = infra === "DATACENTER" ? "#3b82f6" : "#22c55e";
  }

  /* Build context rules */
  const rules = [];

  for (const t of tunnels) {
    const parts = [];
    parts.push("Type: " + (t.type || "unknown"));
    if (t.anonymous) parts.push("Anonymous: yes");
    if (t.operator) parts.push("Operator: " + t.operator.replace(/_/g, " "));
    if (t.entries?.length) parts.push("Entry IPs: " + t.entries.join(", "));
    if (t.exits?.length) parts.push("Exit IPs: " + t.exits.join(", "));
    rules.push({
      name: (t.operator || "Unknown tunnel").replace(/_/g, " "),
      crit: (t.type === "TOR" || t.type === "PROXY") ? 4 : t.type === "VPN" ? 3 : 2,
      critLabel: t.type || "tunnel",
      evidence: parts.join("\n"),
      timestamp: "", count: null
    });
  }

  if (client.proxies?.length) {
    rules.push({
      name: "Residential/Malware Proxies",
      crit: 4, critLabel: "proxy",
      evidence: client.proxies.map(p => p.replace(/_/g, " ")).join(", "),
      timestamp: "", count: null
    });
  }

  if (client.behaviors?.length) {
    rules.push({
      name: "Observed Behaviors",
      crit: 2, critLabel: "behavior",
      evidence: client.behaviors.map(b => b.replace(/_/g, " ")).join(", "),
      timestamp: "", count: null
    });
  }

  /* Client concentration */
  if (client.concentration) {
    const cc = client.concentration;
    const concParts = [];
    if (cc.city) concParts.push("City: " + cc.city);
    if (cc.country) concParts.push("Country: " + cc.country);
    if (cc.state) concParts.push("State: " + cc.state);
    if (typeof cc.density === "number") concParts.push("Density: " + cc.density + "%");
    if (typeof cc.skew === "number") concParts.push("Skew: " + cc.skew + " km");
    if (typeof client.count === "number") concParts.push("Device count: " + client.count);
    if (typeof client.countries === "number") concParts.push("Countries: " + client.countries);
    if (typeof client.spread === "number") concParts.push("Spread: " + client.spread);
    if (client.types?.length) concParts.push("Types: " + client.types.join(", "));
    if (concParts.length) {
      rules.push({
        name: "Client Profile",
        crit: 1, critLabel: "client",
        evidence: concParts.join("\n"),
        timestamp: "", count: null
      });
    }
  }

  /* Network info */
  const infoParts = [];
  if (infra) infoParts.push("Infrastructure: " + infra);
  if (services.length) infoParts.push("Services: " + services.map(s => s.replace(/_/g, " ")).join(", "));
  if (org) infoParts.push("Organization: " + org);
  if (as.number) infoParts.push("ASN: AS" + as.number);
  if (loc.city || loc.country) infoParts.push("Location: " + [loc.city, loc.state, loc.country].filter(Boolean).join(", "));

  if (infoParts.length) {
    rules.push({
      name: "Network Context",
      crit: 1, critLabel: "info",
      evidence: infoParts.join("\n"),
      timestamp: "", count: null
    });
  }

  const riskTags = risks.map(r => ({ name: r.replace(/_/g, " "), score: null }));
  if (services.length) riskTags.push(...services.map(s => ({ name: s, score: null })));

  const summaryBits = [];
  if (tunnels.length) summaryBits.push(tunnels.length + " tunnel" + (tunnels.length > 1 ? "s" : ""));
  if (risks.length) summaryBits.push(risks.length + " risk" + (risks.length > 1 ? "s" : ""));
  if (org) summaryBits.push(org);
  if (infra) summaryBits.push(infra);

  return {
    score: null,
    label,
    color,
    context: {
      entity: value,
      entityType: "ip",
      riskSummary: summaryBits.join(" · ") || "No risks detected",
      rules,
      contexts: riskTags
    }
  };
}

/* ═══════════ URLScan.io Search API ═══════════
 * GET https://urlscan.io/api/v1/search/?q={query}&size=1
 * Header: API-Key (optional but helps with rate limits)
 * Search only - no submission/execution
 */
async function urlscanLookup(type, value, config) {
  const key = (config?.urlscan_key || "").trim();
  if (!key) return { error: "No URLScan key" };

  /* Build search query */
  let q;
  if (type === "url") {
    const escaped = value.replace(/"/g, '\\"');
    q = `(page.url:"${escaped}" OR task.url:"${escaped}")`;
  } else if (type === "domain") {
    q = `domain:${value}`;
  } else {
    q = `"${value.replace(/"/g, '\\"')}"`;
  }

  const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=3`;
  const hdrs = { "Accept": "application/json", "API-Key": key };

  const resp = await fetch(url, { headers: hdrs });

  if (resp.status === 429) {
    await new Promise(r => setTimeout(r, 2000));
    const retry = await fetch(url, { headers: hdrs });
    if (!retry.ok) return { error: "Rate limited" };
    const d = await retry.json();
    return parseUrlscanResults(d);
  }

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    return { error: err.message || err.error || "HTTP " + resp.status };
  }

  const data = await resp.json();
  return parseUrlscanResults(data);
}

function parseUrlscanResults(data) {
  const results = data.results || [];
  if (!results.length) return { score: null, label: "No hits", color: "#6b7280" };

  const r = results[0];
  const uuid = r._id || r.uuid || r.task?.uuid || "";
  const resultUrl = uuid ? `https://urlscan.io/result/${uuid}/` : "";
  const submitted = (r.task?.time || r.task?.submitted || r.page?.time || "").toString().split("T")[0];
  const pageUrl = r.page?.url || r.task?.url || "";
  const verdict = r.verdicts?.overall?.malicious;

  const rules = results.slice(0, 3).map(res => {
    const uid = res._id || res.uuid || res.task?.uuid || "";
    const pg = res.page || {};
    const tsk = res.task || {};
    const parts = [];
    if (pg.url) parts.push("URL: " + pg.url);
    if (pg.domain) parts.push("Domain: " + pg.domain);
    if (pg.ip) parts.push("IP: " + pg.ip);
    if (pg.server) parts.push("Server: " + pg.server);
    if (pg.country) parts.push("Country: " + pg.country);
    if (tsk.time) parts.push("Scanned: " + tsk.time.split("T")[0]);
    if (uid) parts.push("Result: https://urlscan.io/result/" + uid + "/");

    return {
      name: pg.url || pg.domain || uid || "Scan result",
      crit: verdict ? 4 : 2,
      critLabel: verdict ? "malicious" : "scanned",
      evidence: parts.join("\n"),
      timestamp: (tsk.time || "").toString().split("T")[0],
      count: null
    };
  });

  return {
    score: null,
    label: `${results.length} scan${results.length > 1 ? "s" : ""}` + (submitted ? ` (${submitted})` : ""),
    color: verdict ? "#ef4444" : "#00cec9",
    context: {
      entity: pageUrl || "",
      entityType: "url",
      riskSummary: `${results.length} scan result${results.length > 1 ? "s" : ""} found on urlscan.io`,
      rules,
      contexts: []
    }
  };
}

/* ═══════════ VirusTotal v3 API ═══════════
 * GET https://www.virustotal.com/api/v3/{type}/{value}
 * Header: x-apikey
 */
async function vtLookup(type, value, config) {
  const key = (config?.vt_key || "").trim();
  if (!key) return { error: "No VT key" };

  const typeMap = { ip: "ip_addresses", domain: "domains", hash: "files", email: "search" };
  let endpoint = typeMap[type];
  let lookupVal = value;

  if (type === "url") {
    /* VT URL lookup requires base64url-encoded URL identifier */
    endpoint = "urls";
    lookupVal = btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  if (!endpoint) return { error: "Unsupported type" };

  const url = type === "email"
    ? `https://www.virustotal.com/api/v3/search?query=${encodeURIComponent(value)}`
    : `https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(lookupVal)}`;

  const resp = await fetch(url, {
    headers: { "x-apikey": key, "Accept": "application/json" }
  });

  if (resp.status === 404) return { score: null, label: "Not found", color: "#6b7280" };
  if (resp.status === 429) return { error: "Rate limited" };
  if (!resp.ok) return { error: "VT HTTP " + resp.status };

  const data = await resp.json();
  const attrs = data.data?.attributes || (data.data?.[0]?.attributes);
  if (!attrs) return { score: null, label: "No data", color: "#6b7280" };

  const stats = attrs.last_analysis_stats || {};
  const mal = stats.malicious || 0;
  const sus = stats.suspicious || 0;
  const und = stats.undetected || 0;
  const har = stats.harmless || 0;
  const total = mal + sus + und + har;

  let color = "#22c55e";
  if (mal >= 5) color = "#ef4444";
  else if (mal >= 1 || sus >= 3) color = "#f59e0b";
  else if (sus >= 1) color = "#3b82f6";

  const label = `${mal}/${total}`;

  /* Build context */
  const rules = [];
  const infoParts = [];
  if (attrs.asn != null) infoParts.push("ASN: AS" + attrs.asn);
  if (attrs.as_owner) infoParts.push("AS Owner: " + attrs.as_owner);
  if (attrs.country) infoParts.push("Country: " + attrs.country);
  if (attrs.network) infoParts.push("Network: " + attrs.network);
  if (attrs.registrar) infoParts.push("Registrar: " + attrs.registrar);
  if (attrs.creation_date) infoParts.push("Created: " + new Date(attrs.creation_date * 1000).toISOString().split("T")[0]);
  if (attrs.whois_date) infoParts.push("WHOIS date: " + new Date(attrs.whois_date * 1000).toISOString().split("T")[0]);
  if (attrs.last_analysis_date) infoParts.push("Last analysis: " + new Date(attrs.last_analysis_date * 1000).toISOString().split("T")[0]);
  if (attrs.reputation != null) infoParts.push("Reputation: " + attrs.reputation);
  if (attrs.total_votes) infoParts.push("Votes: +" + (attrs.total_votes.harmless||0) + " / -" + (attrs.total_votes.malicious||0));
  if (attrs.meaningful_name) infoParts.push("Name: " + attrs.meaningful_name);
  if (attrs.type_description) infoParts.push("Type: " + attrs.type_description);
  if (attrs.size) infoParts.push("Size: " + (attrs.size > 1048576 ? (attrs.size/1048576).toFixed(1)+"MB" : (attrs.size/1024).toFixed(1)+"KB"));
  if (attrs.tags?.length) infoParts.push("Tags: " + attrs.tags.slice(0,10).join(", "));

  if (infoParts.length) {
    rules.push({ name: "Details", crit: 1, critLabel: "info", evidence: infoParts.join("\n"), timestamp: "", count: null });
  }

  rules.unshift({
    name: "Detection",
    crit: mal >= 5 ? 4 : mal >= 1 ? 3 : sus >= 1 ? 2 : 1,
    critLabel: mal >= 5 ? "malicious" : mal >= 1 ? "suspicious" : "clean",
    evidence: `Malicious: ${mal}\nSuspicious: ${sus}\nHarmless: ${har}\nUndetected: ${und}`,
    timestamp: "",
    count: total
  });

  /* Top detections from last_analysis_results */
  const results = attrs.last_analysis_results || {};
  const detections = Object.entries(results)
    .filter(([, r]) => r.category === "malicious" || r.category === "suspicious")
    .slice(0, 8)
    .map(([engine, r]) => `${engine}: ${r.result || r.category}`);

  if (detections.length) {
    rules.push({ name: "Detections", crit: mal >= 5 ? 4 : 3, critLabel: "engines", evidence: detections.join("\n"), timestamp: "", count: detections.length });
  }

  /* Fetch VT comments (separate request) */
  try {
    const commentsEndpoint = type === "url"
      ? `https://www.virustotal.com/api/v3/urls/${encodeURIComponent(lookupVal)}/comments?limit=5`
      : `https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(type === "url" ? lookupVal : value)}/comments?limit=5`;
    const cr = await fetch(commentsEndpoint, { headers: { "x-apikey": key, "Accept": "application/json" } });
    if (cr.ok) {
      const cj = await cr.json();
      const comments = (cj.data || []).slice(0, 5);
      if (comments.length) {
        const commentParts = comments.map(c => {
          const date = c.attributes?.date ? new Date(c.attributes.date * 1000).toISOString().split("T")[0] : "";
          const text = (c.attributes?.text || "").slice(0, 300) + ((c.attributes?.text?.length || 0) > 300 ? "..." : "");
          return (date ? date + ": " : "") + text;
        });
        rules.push({ name: comments.length + " Comment" + (comments.length > 1 ? "s" : ""), crit: 2, critLabel: "community", evidence: commentParts.join("\n\n"), timestamp: "", count: comments.length });
      }
    }
  } catch (_) { /* comments fetch optional */ }

  return {
    score: mal,
    label,
    color,
    context: {
      entity: value,
      entityType: type,
      riskSummary: `${mal} malicious · ${sus} suspicious · ${total} engines`,
      rules,
      contexts: mal > 0 ? [{ name: "MALICIOUS", score: mal }] : sus > 0 ? [{ name: "SUSPICIOUS", score: sus }] : []
    }
  };
}

/* ═══════════ AbuseIPDB v2 API ═══════════
 * GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose
 * Header: Key, Accept
 */
async function abuseipdbLookup(type, value, config) {
  const key = (config?.abuseipdb_key || "").trim();
  if (!key) return { error: "No AbuseIPDB key" };

  /* AbuseIPDB only supports IP lookups via API */
  if (type !== "ip") return { score: null, label: "", color: "#6b7280" };

  const resp = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90&verbose`,
    { headers: { "Key": key, "Accept": "application/json" } }
  );

  if (resp.status === 429) return { error: "Rate limited" };
  if (resp.status === 422) return { error: "Invalid IP" };
  if (!resp.ok) return { error: "AbuseIPDB HTTP " + resp.status };

  const json = await resp.json();
  const d = json.data;
  if (!d) return { score: null, label: "No data", color: "#6b7280" };

  const confidence = d.abuseConfidenceScore || 0;
  const totalReports = d.totalReports || 0;

  let color = "#22c55e";
  if (confidence >= 75) color = "#ef4444";
  else if (confidence >= 40) color = "#f59e0b";
  else if (confidence >= 10) color = "#3b82f6";

  const label = `${confidence}%` + (totalReports ? ` (${totalReports})` : "");

  /* Build context */
  const infoParts = [];
  if (d.isp) infoParts.push("ISP: " + d.isp);
  if (d.domain) infoParts.push("Domain: " + d.domain);
  if (d.usageType) infoParts.push("Usage: " + d.usageType);
  if (d.countryCode) infoParts.push("Country: " + d.countryCode);
  if (d.isWhitelisted) infoParts.push("Whitelisted: yes");
  if (d.isTor) infoParts.push("TOR exit: yes");
  infoParts.push("Reports (90d): " + totalReports);
  infoParts.push("Confidence: " + confidence + "%");
  if (d.lastReportedAt) infoParts.push("Last reported: " + d.lastReportedAt.split("T")[0]);

  const rules = [{
    name: "Abuse Report",
    crit: confidence >= 75 ? 4 : confidence >= 40 ? 3 : confidence >= 10 ? 2 : 1,
    critLabel: confidence >= 75 ? "high abuse" : confidence >= 40 ? "moderate" : confidence >= 10 ? "low" : "clean",
    evidence: infoParts.join("\n"),
    timestamp: d.lastReportedAt ? d.lastReportedAt.split("T")[0] : "",
    count: totalReports
  }];

  /* Recent report categories */
  const reports = d.reports || [];
  if (reports.length) {
    const catCounts = {};
    for (const r of reports.slice(0, 50)) {
      for (const c of (r.categories || [])) {
        const catNames = { 1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS Attack",5:"FTP Brute-Force",6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",11:"Email Spam",12:"Blog Spam",13:"VPN IP",14:"Port Scan",15:"Hacking",16:"SQL Injection",17:"Spoofing",18:"Brute-Force",19:"Bad Web Bot",20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted" };
        const name = catNames[c] || "Cat " + c;
        catCounts[name] = (catCounts[name] || 0) + 1;
      }
    }
    const sorted = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (sorted.length) {
      rules.push({
        name: "Report Categories",
        crit: 2,
        critLabel: "categories",
        evidence: sorted.map(([n, c]) => `${n}: ${c} report${c > 1 ? "s" : ""}`).join("\n"),
        timestamp: "",
        count: sorted.length
      });
    }
  }

  return {
    score: confidence,
    label,
    color,
    context: {
      entity: value,
      entityType: "ip",
      riskSummary: `${confidence}% confidence · ${totalReports} reports`,
      rules,
      contexts: confidence >= 40 ? [{ name: "ABUSIVE", score: confidence }] : []
    }
  };
}

/* ═══════════ LeakCheck API v2 ═══════════
 * GET https://leakcheck.io/api/v2/query/{email}
 * Header: X-API-Key
 * Returns: {success, found, result: [{source:{name,breach_date}, password, username, email, ...}]}
 */
async function leakcheckLookup(value, config) {
  const key = (config?.leakcheck_key || "").trim();
  if (!key) return { error: "No LeakCheck key" };

  const resp = await fetch(
    `https://leakcheck.io/api/v2/query/${encodeURIComponent(value)}`,
    { headers: { "X-API-Key": key, "Accept": "application/json" } }
  );

  if (resp.status === 429) return { error: "Rate limited (3/s)" };
  if (resp.status === 401) return { error: "Invalid API key" };
  if (resp.status === 403) return { error: "Paid plan required" };
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    return { error: body.error || "HTTP " + resp.status };
  }

  const data = await resp.json();
  if (!data.success) return { error: data.error || "API error" };

  const found = data.found || 0;
  const results = data.result || [];
  if (found === 0 || !results.length) return { score: 0, label: "No leaks", color: "#22c55e" };

  /* Build one rule per breach with full data */
  const rules = results.slice(0, 30).map(entry => {
    const src = entry.source || {};
    const breachName = src.name || "Unknown breach";
    const breachDate = src.breach_date || "";
    const parts = [];

    /* Show all available fields per breach */
    if (entry.email) parts.push("Email: " + entry.email);
    if (entry.username) parts.push("Username: " + entry.username);
    if (entry.password) parts.push("Password: " + entry.password);
    if (entry.hash) parts.push("Hash: " + entry.hash);
    if (entry.first_name) parts.push("First name: " + entry.first_name);
    if (entry.last_name) parts.push("Last name: " + entry.last_name);
    if (entry.name) parts.push("Name: " + entry.name);
    if (entry.phone) parts.push("Phone: " + entry.phone);
    if (entry.dob) parts.push("DOB: " + entry.dob);
    if (entry.address) parts.push("Address: " + entry.address);
    if (entry.zip) parts.push("ZIP: " + entry.zip);
    if (entry.ip) parts.push("IP: " + entry.ip);
    if (entry.line) parts.push("Line: " + entry.line);

    /* Source metadata */
    if (src.unverified) parts.push("(unverified source)");
    if (src.compilation) parts.push("(compilation)");
    if (src.passwordless) parts.push("(no password in this breach)");

    const hasPassword = !!entry.password;

    return {
      name: breachName + (breachDate ? " (" + breachDate + ")" : ""),
      crit: hasPassword ? 4 : 2,
      critLabel: hasPassword ? "password" : "data",
      evidence: parts.join("\n"),
      timestamp: breachDate,
      count: null
    };
  });

  /* Sort: breaches with passwords first */
  rules.sort((a, b) => b.crit - a.crit);

  const withPw = results.filter(r => r.password).length;
  let color = "#22c55e";
  if (withPw >= 3) color = "#ef4444";
  else if (withPw >= 1) color = "#f59e0b";
  else if (found >= 3) color = "#f59e0b";
  else if (found >= 1) color = "#3b82f6";

  const allFields = [...new Set(results.flatMap(r => Object.keys(r).filter(k => k !== "source" && r[k])))];

  return {
    score: found,
    label: found + " leak" + (found > 1 ? "s" : "") + (withPw ? " (" + withPw + " pw)" : ""),
    color,
    context: {
      entity: value,
      entityType: "email",
      riskSummary: found + " breach" + (found > 1 ? "es" : "") + (withPw ? " - " + withPw + " with password" : ""),
      rules,
      contexts: withPw ? [{ name: "PASSWORD EXPOSED", score: null }] : allFields.includes("hash") ? [{ name: "HASH EXPOSED", score: null }] : []
    }
  };
}

function scoreColor(score) {
  if (score >= 75) return "#ef4444";
  if (score >= 50) return "#f59e0b";
  if (score >= 25) return "#3b82f6";
  return "#22c55e";
}

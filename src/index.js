// Occultera telemetry collector. Accepts only the structured events of app/telemetry/schema.py (schema 1),
// stores no IP address and no request headers, keeps rows for RETENTION_DAYS, and opens one GitHub issue per new
// crash fingerprint. Source: https://github.com/occultera/telemetry — AGPL-3.0-only.

const KEYS = {
  error: ["schema", "kind", "app", "install", "deploy", "python", "ts", "exception", "category", "frames", "where", "fingerprint"],
  usage: ["schema", "kind", "app", "install", "deploy", "python", "ts", "environments", "wazuh", "llm", "features"],
};
const RE = {
  app: /^\d+\.\d+\.\d+([.+-][0-9A-Za-z.-]{1,20})?$/, install: /^[0-9a-f]{16}$/, fingerprint: /^[0-9a-f]{16}$/,
  deploy: /^(helm|kustomize|compose|docker|kubernetes|other)$/, python: /^\d+\.\d+\.\d+$/, exception: /^[A-Za-z_][A-Za-z0-9_]{0,60}$/,
  category: /^[a-z_]{1,20}$/, frame: /^app(\.[a-z0-9_]+){0,6}:[A-Za-z_<>][A-Za-z0-9_<>]{0,60}$/, where: /^[a-z0-9_.]{0,60}$/,
  llm: /^(anthropic|openai|mock|none|other)$/, wazuh: /^v?\d+\.\d+(\.\d+)?(-[0-9a-z.]{1,10})?$/, feature: /^[a-z_]{1,30}$/,
};

function bad(msg, status = 400) { return new Response(JSON.stringify({ error: msg }), { status, headers: { "content-type": "application/json" } }); }

export function validate(ev) {
  if (!ev || typeof ev !== "object" || Array.isArray(ev)) return "not an object";
  const keys = KEYS[ev.kind];
  if (!keys || ev.schema !== 1) return "unknown kind or schema";
  for (const k of Object.keys(ev)) if (!keys.includes(k)) return `unexpected key ${k}`;
  for (const k of ["app", "install", "deploy", "python"]) if (typeof ev[k] !== "string" || !RE[k].test(ev[k])) return `bad ${k}`;
  if (ev.kind === "error") {
    if (!RE.exception.test(ev.exception || "") || !RE.category.test(ev.category || "") || !RE.fingerprint.test(ev.fingerprint || "")) return "bad error fields";
    if (!Array.isArray(ev.frames) || ev.frames.length > 12 || !ev.frames.every(f => typeof f === "string" && RE.frame.test(f))) return "bad frames";
    if (ev.where !== undefined && !RE.where.test(ev.where)) return "bad where";
  } else {
    if (!Number.isInteger(ev.environments) || ev.environments < 0 || ev.environments > 1000) return "bad environments";
    if (!Array.isArray(ev.wazuh) || ev.wazuh.length > 10 || !ev.wazuh.every(v => RE.wazuh.test(v))) return "bad wazuh";
    if (!RE.llm.test(ev.llm || "")) return "bad llm";
    const f = ev.features || {};
    if (typeof f !== "object" || Object.keys(f).length > 30 || !Object.entries(f).every(([k, v]) => RE.feature.test(k) && typeof v === "boolean")) return "bad features";
  }
  return null;
}

function isoWeek(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7; t.setUTCDate(t.getUTCDate() + 4 - day);
  const y = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  return `${t.getUTCFullYear()}-W${String(Math.ceil(((t - y) / 86400000 + 1) / 7)).padStart(2, "0")}`;
}

async function openIssue(env, ev) {
  if (!env.GITHUB_TOKEN) return null;
  const body = [
    "Automatic crash report from Occultera telemetry (structured data only — no messages, no alert content).", "",
    `- **Exception:** \`${ev.exception}\` · category \`${ev.category}\``, `- **Version:** ${ev.app} · ${ev.deploy} · Python ${ev.python}`,
    `- **Fingerprint:** \`${ev.fingerprint}\``, "", "Frames (innermost last):", "```", ...ev.frames, "```", "",
    "Counts and affected versions are updated in the collector; comment here if you can reproduce it.",
  ].join("\n");
  const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPO}/issues`, {
    method: "POST",
    headers: { authorization: `Bearer ${env.GITHUB_TOKEN}`, "user-agent": "occultera-telemetry", accept: "application/vnd.github+json" },
    body: JSON.stringify({ title: `[crash] ${ev.exception} in ${ev.frames.at(-1) || "?"}`, body, labels: ["crash", "telemetry"] }),
  });
  return r.ok ? (await r.json()).number : null;
}

async function storeError(env, ev, now) {
  const row = await env.DB.prepare("SELECT count, versions, installs, issue FROM errors WHERE fingerprint = ?").bind(ev.fingerprint).first();
  if (!row) {
    await env.DB.prepare("INSERT INTO errors (fingerprint, exception, category, frames, first_seen, last_seen, versions, installs) VALUES (?,?,?,?,?,?,?,?)")
      .bind(ev.fingerprint, ev.exception, ev.category, JSON.stringify(ev.frames), now, now, JSON.stringify([ev.app]), JSON.stringify([ev.install])).run();
    const n = await openIssue(env, ev);
    if (n) await env.DB.prepare("UPDATE errors SET issue = ? WHERE fingerprint = ?").bind(n, ev.fingerprint).run();
    return;
  }
  const versions = [...new Set([...JSON.parse(row.versions), ev.app])].slice(-20);
  const installs = [...new Set([...JSON.parse(row.installs), ev.install])].slice(-50);
  await env.DB.prepare("UPDATE errors SET count = count + 1, last_seen = ?, versions = ?, installs = ? WHERE fingerprint = ?")
    .bind(now, JSON.stringify(versions), JSON.stringify(installs), ev.fingerprint).run();
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/" && req.method === "GET")
      return new Response("Occultera telemetry collector — https://occultera.dev (what is collected: wiki page Telemetry)\n");
    if (url.pathname !== "/v1/events") return bad("not found", 404);
    if (req.method !== "POST") return bad("method not allowed", 405);
    const len = Number(req.headers.get("content-length") || 0);
    if (len > 8192) return bad("too large", 413);
    let ev;
    try { ev = JSON.parse(await req.text()); } catch { return bad("invalid json"); }
    const err = validate(ev);
    if (err) return bad(err);
    const now = new Date().toISOString();
    if (ev.kind === "error") await storeError(env, ev, now);
    else await env.DB.prepare("INSERT OR REPLACE INTO usage (install, week, received, payload) VALUES (?,?,?,?)")
      .bind(ev.install, isoWeek(new Date()), now, JSON.stringify(ev)).run();
    return new Response(null, { status: 204 });
  },
  async scheduled(_event, env) {
    const days = Number(env.RETENTION_DAYS || 90);
    const cut = new Date(Date.now() - days * 86400000).toISOString();
    await env.DB.prepare("DELETE FROM usage WHERE received < ?").bind(cut).run();
    await env.DB.prepare("DELETE FROM errors WHERE last_seen < ?").bind(cut).run();
  },
};

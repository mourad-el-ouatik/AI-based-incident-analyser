import "dotenv/config";
import express from "express";
import cors from "cors";
import axios from "axios";
import { query, audit, hasDb } from "./db.js";

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 8000;
const STATUS_BY_ACTION = { block_ip: "responded", escalate: "escalated", monitor: "closed", false_positive: "closed" };

const rand = (n) => Math.floor(Math.random() * n);
const ref = (p) => `${p}-${Date.now().toString(36).toUpperCase().slice(-5)}${rand(90) + 10}`;

// Parse un champ qui peut etre deja un tableau/objet, ou une chaine (JSON, ou style Python).
function parseMaybe(value, fallback) {
  if (value == null) return fallback;
  if (typeof value !== "string") return value;
  const s = value.trim();
  if (!s) return fallback;
  try {
    return JSON.parse(s);
  } catch {
    try {
      return JSON.parse(s.replace(/'/g, '"'));
    } catch {
      return fallback;
    }
  }
}

const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
  console.error("[err]", req.method, req.path, e.message);
  res.status(500).json({ error: e.message });
});

// --- Health -----------------------------------------------------------------
app.get("/health", (_req, res) => res.json({ ok: true, db: hasDb(), at: new Date().toISOString() }));

// --- Incidents : lecture (dashboard) ----------------------------------------
app.get("/incidents", wrap(async (_req, res) => {
  if (!hasDb()) return res.status(503).json({ error: "DATABASE_URL non configure" });
  const { rows } = await query(
    `SELECT * FROM incidents WHERE COALESCE(archived, false) = false ORDER BY timestamp DESC`
  );
  res.json(rows.map((r) => ({
    ...r,
    mitre_techniques: parseMaybe(r.mitre_techniques, []),
    raw_alerts: parseMaybe(r.raw_alerts, []),
    archived: r.archived ?? false,
  })));
}));

// --- Incidents : INGESTION (pipeline Wazuh -> Ollama -> ici) -----------------
// Le pipeline du modele envoie ici le JSON produit (format = model_system_prompt.md).
app.post("/incidents", wrap(async (req, res) => {
  if (!hasDb()) return res.status(503).json({ error: "DATABASE_URL non configure" });
  const b = req.body || {};
  if (!b.incident_id) return res.status(400).json({ error: "incident_id requis" });

  const v = {
    incident_id: b.incident_id,
    timestamp: b.timestamp || new Date().toISOString(),
    is_attack: !!b.is_attack,
    attack_type: b.attack_type || "Unknown",
    confidence: b.confidence ?? 0.5,
    summary: b.summary || "",
    score_wazuh: b.score_wazuh ?? 0,
    score_ia: b.score_ia ?? 0,
    score_final: b.score_final ?? 0,
    recommended_action: b.recommended_action || "monitor",
    mitre_techniques: JSON.stringify(b.mitre_techniques || []),
    source_ip: b.source_ip ?? null,
    target_user: b.target_user ?? null,
    target_host: b.target_host ?? null,
    affected_service: b.affected_service ?? null,
    priority: b.priority || "LOW",
    batch_size: b.batch_size ?? null,
    raw_alerts: JSON.stringify(b.raw_alerts || []),
  };

  const { rows } = await query(
    `INSERT INTO incidents
       (incident_id, "timestamp", is_attack, attack_type, confidence, summary,
        score_wazuh, score_ia, score_final, recommended_action, mitre_techniques,
        source_ip, target_user, target_host, affected_service, priority, batch_size, raw_alerts)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18::jsonb)
     ON CONFLICT (incident_id) DO NOTHING
     RETURNING id`,
    [v.incident_id, v.timestamp, v.is_attack, v.attack_type, v.confidence, v.summary,
     v.score_wazuh, v.score_ia, v.score_final, v.recommended_action, v.mitre_techniques,
     v.source_ip, v.target_user, v.target_host, v.affected_service, v.priority, v.batch_size, v.raw_alerts]
  );
  res.json({ ok: true, inserted: rows.length > 0, id: rows[0]?.id ?? null, incident_id: v.incident_id });
}));

// --- Ollama : interroger le modele ------------------------------------------
app.post("/model/ask", wrap(async (req, res) => {
  const { incident_id, question } = req.body || {};
  if (process.env.OLLAMA_URL) {
    const { data } = await axios.post(
      `${process.env.OLLAMA_URL.replace(/\/$/, "")}/api/generate`,
      { model: process.env.OLLAMA_MODEL || "llama3", prompt: `Incident ${incident_id}. Question analyste: ${question}`, stream: false },
      { timeout: 30000 }
    );
    return res.json({ answer: data?.response || "(reponse vide)" });
  }
  res.json({ answer: `(simulation) Analyse de ${incident_id} : ${question} — configurez OLLAMA_URL pour une vraie reponse.` });
}));

// --- pfSense : blocage d'IP + persistance -----------------------------------
app.post("/pfsense/block", wrap(async (req, res) => {
  const { ip, incident_id } = req.body || {};
  const pfsense_rule_id = ref("FW");
  if (process.env.PFSENSE_URL && ip) {
    try {
      // TODO: adapter au paquet API de votre pfSense (chemin + format exact).
      await axios.post(
        `${process.env.PFSENSE_URL.replace(/\/$/, "")}/firewall/rule`,
        { type: "block", source: ip, descr: `SOC ${incident_id || ""}` },
        { headers: process.env.PFSENSE_TOKEN ? { Authorization: `Bearer ${process.env.PFSENSE_TOKEN}` } : {}, timeout: 6000 }
      );
    } catch (e) {
      console.error("[pfsense] appel reel echoue, id genere conserve:", e.message);
    }
  }
  if (hasDb() && incident_id) {
    await query(
      `UPDATE incidents SET status='responded', analyst_action='block_ip', decided_at=now(),
              pfsense_rule_id=$2, blocked_ip=$3 WHERE incident_id=$1`,
      [incident_id, pfsense_rule_id, ip || null]
    );
    await audit({ incident_id, action: "block_ip", target: "pfSense", detail: `Regle ${pfsense_rule_id} - IP ${ip || "n/c"}` });
  }
  res.json({ pfsense_rule_id, blocked_ip: ip || null });
}));

// --- TheHive : creation de case (stub par defaut) ---------------------------
app.post("/thehive/case", wrap(async (req, res) => {
  const { sourceRef, incident } = req.body || {};
  const incident_id = sourceRef || incident?.incident_id;
  let thehive_case_id = `CASE-${ref("H")}`;
  if (process.env.THEHIVE_URL) {
    try {
      const { data } = await axios.post(
        `${process.env.THEHIVE_URL.replace(/\/$/, "")}/api/v1/case`,
        { title: `${incident?.attack_type || "Incident"} ${incident_id}`, description: incident?.summary || "", sourceRef: incident_id },
        { headers: process.env.THEHIVE_TOKEN ? { Authorization: `Bearer ${process.env.THEHIVE_TOKEN}` } : {}, timeout: 6000 }
      );
      thehive_case_id = data?._id || data?.id || thehive_case_id;
    } catch (e) {
      console.error("[thehive] appel reel echoue, stub conserve:", e.message);
    }
  }
  if (hasDb() && incident_id) {
    await query(`UPDATE incidents SET thehive_case_id=$2 WHERE incident_id=$1`, [incident_id, thehive_case_id]);
    await audit({ incident_id, action: "escalate", target: "TheHive", detail: `Case ${thehive_case_id}` });
  }
  res.json({ thehive_case_id });
}));

// --- Decision : persiste toute decision analyste ----------------------------
app.post("/decision", wrap(async (req, res) => {
  const { incident_id, action, analyst = "analyste", thehive_case_id = null, pfsense_rule_id = null, blocked_ip = null } = req.body || {};
  if (!incident_id || !action) return res.status(400).json({ error: "incident_id et action requis" });
  if (hasDb()) {
    await query(
      `UPDATE incidents SET status=$2, analyst_action=$3, analyst_user=$4, decided_at=now(),
              thehive_case_id=COALESCE($5, thehive_case_id),
              pfsense_rule_id=COALESCE($6, pfsense_rule_id),
              blocked_ip=COALESCE($7, blocked_ip) WHERE incident_id=$1`,
      [incident_id, STATUS_BY_ACTION[action] || "new", action, analyst, thehive_case_id, pfsense_rule_id, blocked_ip]
    );
    await audit({ incident_id, action, analyst_user: analyst, detail: "Decision analyste enregistree" });
  }
  res.json({ ok: true });
}));

app.listen(PORT, () => {
  console.log(`SOC backend sur http://0.0.0.0:${PORT}  (db: ${hasDb() ? "connectee" : "non configuree"})`);
});

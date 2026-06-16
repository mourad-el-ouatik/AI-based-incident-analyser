import pg from "pg";

// Pool Postgres. Si DATABASE_URL est absent, le backend tourne en mode degrade
// (les endpoints simulent au lieu de planter). Des qu'une URL est fournie, c'est reel.
const { Pool } = pg;

let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5, idleTimeoutMillis: 30000 });
  pool.on("error", (err) => console.error("[db] pool error:", err.message));
}

export const hasDb = () => pool !== null;

export async function query(text, params) {
  if (!pool) throw new Error("DATABASE_URL non configure");
  return pool.query(text, params);
}

// INSERT dans le journal d'audit (best-effort : ne bloque jamais la reponse a l'analyste).
export async function audit({ incident_id, action, target = null, detail = null, analyst_user = "analyste" }) {
  if (!pool) return;
  try {
    await pool.query(
      `INSERT INTO audit_log (incident_id, action, target, detail, analyst_user)
       VALUES ($1, $2, $3, $4, $5)`,
      [incident_id, action, target, detail, analyst_user]
    );
  } catch (e) {
    console.error("[db] audit insert failed:", e.message);
  }
}

import { pool } from "./db.js";

// Append-only audit trail for management + security actions. record() never
// throws — an audit-write failure must not break the action it describes.

export interface RecordOpts {
  actor?: string;        // acting user id
  actorEmail?: string;   // denormalized for display (survives user deletion)
  orgId?: string;        // company the action belongs to (null for platform-wide)
  targetType?: string;   // "user" | "company" | "project" | "apikey" | "member" | "event"
  target?: string;       // id/email of the thing acted on
  metadata?: Record<string, unknown>;
  ip?: string;
}

export async function record(action: string, opts: RecordOpts = {}): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO audit_log (actor, actor_email, action, target_type, target, org_id, metadata, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        opts.actor ?? null, opts.actorEmail ?? null, action,
        opts.targetType ?? null, opts.target ?? null, opts.orgId ?? null,
        JSON.stringify(opts.metadata ?? {}), opts.ip ?? null,
      ],
    );
  } catch {
    /* audit failures are swallowed on purpose */
  }
}

export interface AuditEntry {
  id: string;
  at: string;
  actorEmail: string | null;
  action: string;
  targetType: string | null;
  target: string | null;
  metadata: Record<string, unknown>;
  orgId?: string | null;
  orgName?: string | null;
}

function fmt(r: {
  id: string | number; at: Date; actor_email: string | null; action: string;
  target_type: string | null; target: string | null; metadata: Record<string, unknown>;
}): AuditEntry {
  return {
    id: String(r.id), at: r.at.toISOString(), actorEmail: r.actor_email, action: r.action,
    targetType: r.target_type, target: r.target, metadata: r.metadata || {},
  };
}

const cap = (n: unknown, max: number, def: number) => Math.min(Number(n) || def, max);

/** One company's audit trail. */
export async function listByOrg(orgId: string, limit = 100): Promise<AuditEntry[]> {
  const { rows } = await pool.query(
    `SELECT id, at, actor_email, action, target_type, target, metadata
     FROM audit_log WHERE org_id = $1 ORDER BY at DESC LIMIT $2`,
    [orgId, cap(limit, 500, 100)],
  );
  return rows.map(fmt);
}

/** Platform-wide audit trail (all companies + platform actions). */
export async function listAll(limit = 200): Promise<AuditEntry[]> {
  const { rows } = await pool.query(
    `SELECT a.id, a.at, a.actor_email, a.action, a.target_type, a.target, a.metadata,
            a.org_id, o.name AS org_name
     FROM audit_log a LEFT JOIN organizations o ON o.id = a.org_id
     ORDER BY a.at DESC LIMIT $1`,
    [cap(limit, 1000, 200)],
  );
  return rows.map((r) => ({ ...fmt(r), orgId: r.org_id, orgName: r.org_name }));
}

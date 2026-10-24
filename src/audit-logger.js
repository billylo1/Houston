import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_AUDIT_LOG_PATH = path.resolve(process.cwd(), 'houston_audit.jsonl');

export const RISK_LEVELS = {
  low: 1,
  medium: 2,
  high: 3,
};

/**
 * Check if an assessed risk level is within the configured maximum allowed risk threshold.
 */
export function isRiskAllowed(assessedRisk = 'high', maxAllowedRisk = 'low') {
  const assessedRank = RISK_LEVELS[String(assessedRisk).toLowerCase()] ?? RISK_LEVELS.high;
  const allowedRank = RISK_LEVELS[String(maxAllowedRisk).toLowerCase()] ?? RISK_LEVELS.low;
  return assessedRank <= allowedRank;
}

/**
 * Append a structured self-healing recovery event to the JSONL audit log.
 */
export function appendAuditEntry(entry, auditLogPath = DEFAULT_AUDIT_LOG_PATH) {
  const record = {
    timestamp: new Date().toISOString(),
    stepId: entry.stepId || null,
    error: entry.error || null,
    action: entry.action || 'unknown',
    riskLevel: entry.riskLevel || 'unknown',
    maxAllowedRisk: entry.maxAllowedRisk || 'low',
    riskJustification: entry.riskJustification || null,
    originalValue: entry.originalValue ?? null,
    fixedValue: entry.fixedValue ?? null,
    reason: entry.reason || entry.summary || null,
    filesPatched: entry.filesPatched || [],
  };

  try {
    const resolvedPath = path.resolve(auditLogPath);
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
    fs.appendFileSync(resolvedPath, `${JSON.stringify(record)}\n`, 'utf8');
  } catch (err) {
    console.warn(`[Houston Audit] Failed to write audit entry: ${err.message}`);
  }

  return record;
}

/**
 * Read and parse all JSONL entries from the audit log.
 */
export function readAuditLog(auditLogPath = DEFAULT_AUDIT_LOG_PATH) {
  const resolvedPath = path.resolve(auditLogPath);
  if (!fs.existsSync(resolvedPath)) {
    return [];
  }
  const lines = fs.readFileSync(resolvedPath, 'utf8').split('\n').filter(Boolean);
  return lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

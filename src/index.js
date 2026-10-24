import { executeWithHoustonTrap, closeInspector } from './inspector-trap.js';
import { appendAuditEntry, readAuditLog, DEFAULT_AUDIT_LOG_PATH } from './audit-logger.js';
import { connectCDP } from './agent-runner.js';

export class Houston {
  constructor(config = {}) {
    this.config = {
      mode: config.mode || process.env.HOUSTON_MODE || 'auto',
      model: config.model || process.env.HOUSTON_MODEL || 'gemini-3.8-flash',
      maxRetries: config.maxRetries ?? 2,
      timeoutMs: config.timeoutMs ?? 180000,
      port: config.port ?? 9229,
      auditLogPath: config.auditLogPath || DEFAULT_AUDIT_LOG_PATH,
      context: config.context || {},
      relevantFiles: config.relevantFiles || [],
      onTrap: config.onTrap || null,
      silent: config.silent ?? false,
    };
  }

  /**
   * Wrap a batch step or operation with a self-healing V8 inspector trap.
   *
   * @param {string} stepId - Identifier for this step or item
   * @param {Function} fn - Async or sync function `(item, context) => result`
   * @param {Object} [stepOptions] - Per-step overrides (`item`, `relevantFiles`, `onTrap`, etc.)
   */
  async trap(stepId, fn, stepOptions = {}) {
    return executeWithHoustonTrap(stepId, fn, {
      ...this.config,
      ...stepOptions,
      context: { ...this.config.context, ...(stepOptions.context || {}) },
      relevantFiles: stepOptions.relevantFiles || this.config.relevantFiles,
    });
  }

  /**
   * Read all logged self-healing events from the JSONL audit file.
   */
  getAuditHistory() {
    return readAuditLog(this.config.auditLogPath);
  }

  /**
   * Close the V8 inspector session cleanly.
   */
  close() {
    closeInspector();
  }
}

/**
 * Functional helper for one-off trapped steps.
 */
export async function withHouston(stepId, fn, options = {}) {
  const instance = new Houston(options);
  try {
    return await instance.trap(stepId, fn, options);
  } finally {
    if (options.closeOnFinish) {
      instance.close();
    }
  }
}

export { appendAuditEntry, readAuditLog, connectCDP, closeInspector };
export default Houston;

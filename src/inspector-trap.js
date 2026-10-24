import inspector from 'node:inspector';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { appendAuditEntry, isRiskAllowed } from './audit-logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_INCIDENT_FILE = '/tmp/houston_incident.json';
export const DEFAULT_ACTION_FILE = '/tmp/houston_action.json';
export const DEFAULT_INSPECTOR_URL_FILE = '/tmp/houston_inspector_url.txt';

// Expose global runtime namespace for deterministic CDP evaluation
if (!globalThis.__houston) {
  globalThis.__houston = {
    context: {},
    currentStep: null,
    currentItem: null,
    lastError: null,
    maxAllowedRisk: 'low',
    __mutationAuthorized: false,
    history: [],
  };
}

/**
 * Safe clone that never throws `DataCloneError` when an item contains functions or class instances.
 */
export function safeClone(value) {
  if (value === null || typeof value !== 'object') return value;
  try {
    return structuredClone(value);
  } catch {
    try {
      return JSON.parse(JSON.stringify(value));
    } catch {
      return null;
    }
  }
}

/**
 * Wraps an object in a recursive V8 Proxy that prevents accidental property mutation
 * during read-only `inspectRuntime()` calls unless unlocked by `mutateRuntime()`.
 */
export function createRiskGuardedProxy(target) {
  if (target === null || typeof target !== 'object') {
    return target;
  }
  return new Proxy(target, {
    get(obj, prop, receiver) {
      const value = Reflect.get(obj, prop, receiver);
      if (typeof value === 'function') {
        return value.bind(obj);
      }
      if (value !== null && typeof value === 'object') {
        return createRiskGuardedProxy(value);
      }
      return value;
    },
    set(obj, prop, value, receiver) {
      if (!globalThis.__houston.__mutationAuthorized) {
        throw new Error(
          `[Houston Risk Guard] Mutation of "${String(prop)}" prevented: mutations must be executed via mutateRuntime() with an assessed riskLevel <= "${globalThis.__houston.maxAllowedRisk}".`,
        );
      }
      return Reflect.set(obj, prop, value, receiver);
    },
    deleteProperty(obj, prop) {
      if (!globalThis.__houston.__mutationAuthorized) {
        throw new Error(
          `[Houston Risk Guard] Deletion of "${String(prop)}" prevented: mutations must be executed via mutateRuntime() with an assessed riskLevel <= "${globalThis.__houston.maxAllowedRisk}".`,
        );
      }
      return Reflect.deleteProperty(obj, prop);
    },
  });
}

let inspectorOpened = false;

/**
 * Open the V8 inspector on the requested port (or dynamic port 0 on conflict).
 */
export function ensureInspector(port = 9229, inspectorUrlFile = DEFAULT_INSPECTOR_URL_FILE) {
  if (inspectorOpened && inspector.url()) {
    return inspector.url();
  }
  try {
    inspector.open(port, '127.0.0.1', false);
    inspectorOpened = true;
  } catch {
    try {
      inspector.open(0, '127.0.0.1', false);
      inspectorOpened = true;
    } catch (err) {
      console.warn(`[Houston] Could not open V8 inspector: ${err.message}`);
      return null;
    }
  }
  const url = inspector.url();
  if (url && inspectorUrlFile) {
    try {
      fs.writeFileSync(inspectorUrlFile, url, { encoding: 'utf8', mode: 0o600 });
    } catch {
      // ignore
    }
  }
  return url;
}

/**
 * Close the V8 inspector cleanly when no longer needed.
 */
export function closeInspector() {
  if (inspectorOpened) {
    try {
      inspector.close();
    } catch {
      // ignore
    }
    inspectorOpened = false;
  }
}

export function clearFile(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch {
    // ignore
  }
}

export function readAndConsumeAction(actionFile = DEFAULT_ACTION_FILE) {
  try {
    if (fs.existsSync(actionFile)) {
      const raw = fs.readFileSync(actionFile, 'utf8').trim();
      if (raw) {
        const parsed = JSON.parse(raw);
        fs.unlinkSync(actionFile);
        return parsed;
      }
    }
  } catch (err) {
    console.warn(`[Houston] Failed to parse action file: ${err.message}`);
  }
  return null;
}

export function writeIncident({
  stepId,
  error,
  attempt,
  maxRetries,
  maxAllowedRisk = 'low',
  allowCodePatches = false,
  relevantFiles = [],
  inspectorUrl,
  auditLogPath,
  incidentFile = DEFAULT_INCIDENT_FILE,
  actionFile = DEFAULT_ACTION_FILE,
  itemSnapshot = null,
}) {
  const incident = {
    timestamp: new Date().toISOString(),
    stepId,
    attempt,
    maxRetries,
    maxAllowedRisk,
    allowCodePatches,
    error: {
      name: error?.name || 'Error',
      message: error?.message || String(error),
      stack: error?.stack || null,
    },
    relevantFiles: relevantFiles.map((f) => path.resolve(f)),
    inspectorUrl: inspectorUrl || inspector.url() || null,
    auditLogPath,
    actionFile,
    currentItemPreview: itemSnapshot,
  };

  fs.writeFileSync(incidentFile, JSON.stringify(incident, null, 2), { encoding: 'utf8', mode: 0o600 });
  return incident;
}

export function printHoustonBanner({ stepId, error, inspectorUrl, incidentFile, mode, maxAllowedRisk = 'low' }) {
  console.log('\n' + '═'.repeat(78));
  console.log('🚀 HOUSTON, WE HAVE A PROBLEM... Investigate it live and fix it for me!');
  console.log('─'.repeat(78));
  console.log(`  Step        : ${stepId}`);
  console.log(`  Error       : ${error?.message || error}`);
  console.log(`  Mode        : ${mode} (Max Auto-Heal Risk: ${maxAllowedRisk.toUpperCase()})`);
  if (inspectorUrl) {
    console.log(`  V8 CDP URL  : ${inspectorUrl}`);
  }
  console.log(`  Incident    : ${incidentFile}`);
  console.log('═'.repeat(78) + '\n');
}

export async function spawnAgentRunner({
  mode,
  model = 'gemini-4-argon',
  thinkingLevel = 'high',
  maxAllowedRisk = 'low',
  allowCodePatches = false,
  incidentFile,
  actionFile,
  auditLogPath,
  spawnAgent = true,
}) {
  if (!spawnAgent) return;

  const runnerScript = path.join(__dirname, 'agent-runner.js');
  const args = [
    runnerScript,
    '--incident', incidentFile,
    '--action-file', actionFile,
    '--audit-log', auditLogPath,
    '--model', model,
    '--thinking-level', thinkingLevel,
    '--max-risk', maxAllowedRisk,
  ];

  if (mode === 'auto') {
    args.push('--auto');
  }
  if (allowCodePatches) {
    args.push('--allow-code-patches');
  }

  if (process.stdin.isTTY || mode === 'auto') {
    const child = spawn(process.execPath, args, {
      stdio: 'inherit',
      env: process.env,
    });
    await new Promise((resolve) => {
      child.on('exit', resolve);
      child.on('error', () => resolve());
    });
  } else {
    const child = spawn(process.execPath, [...args, '--auto'], {
      stdio: 'inherit',
      env: process.env,
    });
    child.unref();
  }
}

export async function waitForResolution({
  actionFile = DEFAULT_ACTION_FILE,
  timeoutMs = 180000,
  pollIntervalMs = 100,
} = {}) {
  const immediate = readAndConsumeAction(actionFile);
  if (immediate) return immediate;

  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await new Promise((r) => setTimeout(r, pollIntervalMs));
    const action = readAndConsumeAction(actionFile);
    if (action) {
      return action;
    }
  }
  return { action: 'timeout', riskLevel: 'low', reason: `Timed out after ${timeoutMs / 1000}s` };
}

/**
 * Core trap execution loop.
 */
export async function executeWithHoustonTrap(stepId, fn, options = {}) {
  const {
    mode = 'auto',
    model = 'gemini-4-argon',
    thinkingLevel = 'high',
    maxAllowedRisk = 'low',
    onRiskExceeded = 'skip',
    allowCodePatches = false,
    maxRetries = 2,
    timeoutMs = 180000,
    port = 9229,
    item = null,
    context = {},
    relevantFiles = [],
    auditLogPath,
    incidentFile = DEFAULT_INCIDENT_FILE,
    actionFile = DEFAULT_ACTION_FILE,
    inspectorUrlFile = DEFAULT_INSPECTOR_URL_FILE,
    spawnAgent = true,
    onTrap = null,
    silent = false,
  } = options;

  Object.assign(globalThis.__houston.context, context);
  globalThis.__houston.currentStep = stepId;
  globalThis.__houston.maxAllowedRisk = maxAllowedRisk;
  globalThis.__houston.__mutationAuthorized = false;
  globalThis.__houston.currentItem = createRiskGuardedProxy(item);

  let attempts = 0;

  while (attempts <= maxRetries) {
    try {
      const result = await fn(item, globalThis.__houston.context);
      return result;
    } catch (error) {
      attempts++;
      globalThis.__houston.lastError = {
        message: error.message,
        stack: error.stack,
      };

      if (mode === 'off' || attempts > maxRetries) {
        throw error;
      }

      const originalSnapshot = safeClone(item);
      const inspectorUrl = ensureInspector(port, inspectorUrlFile);
      clearFile(actionFile);

      const incident = writeIncident({
        stepId,
        error,
        attempt: attempts,
        maxRetries,
        maxAllowedRisk,
        allowCodePatches,
        relevantFiles,
        inspectorUrl,
        auditLogPath,
        incidentFile,
        actionFile,
        itemSnapshot: originalSnapshot,
      });

      if (!silent) {
        printHoustonBanner({ stepId, error, inspectorUrl, incidentFile, mode, maxAllowedRisk });
      }

      debugger;

      if (typeof onTrap === 'function') {
        const customDecision = await onTrap({
          stepId,
          error,
          incident,
          inspectorUrl,
          maxAllowedRisk,
          item: globalThis.__houston.currentItem,
          context: globalThis.__houston.context,
        });
        if (customDecision && customDecision.action) {
          fs.writeFileSync(actionFile, JSON.stringify(customDecision, null, 2), { encoding: 'utf8', mode: 0o600 });
        }
      } else {
        await spawnAgentRunner({
          mode,
          model,
          thinkingLevel,
          maxAllowedRisk,
          allowCodePatches,
          incidentFile,
          actionFile,
          auditLogPath,
          spawnAgent,
        });
      }

      const resolution = await waitForResolution({ actionFile, timeoutMs });
      // Fail-closed: if `riskLevel` is omitted on a retry/blocked resolution, default to 'high'
      const defaultRisk = resolution.action === 'skip' || resolution.action === 'timeout' ? 'low' : 'high';
      const assessedRisk = String(resolution.riskLevel || defaultRisk).toLowerCase();
      const riskJustification = resolution.riskJustification || null;

      // Enforce Risk Guardrail: block any healing action whose assessed risk exceeds maxAllowedRisk
      if (
        (resolution.action === 'retry' || resolution.action === 'blocked') &&
        !isRiskAllowed(assessedRisk, maxAllowedRisk)
      ) {
        const blockedReason =
          resolution.reason ||
          `Blocked ${assessedRisk}-risk healing action (maxAllowedRisk="${maxAllowedRisk}")`;

        const auditRecord = appendAuditEntry({
          stepId,
          error: error.message,
          action: 'blocked',
          riskLevel: assessedRisk,
          maxAllowedRisk,
          riskJustification,
          originalValue: originalSnapshot,
          fixedValue: null,
          reason: blockedReason,
          filesPatched: [],
        }, auditLogPath);

        globalThis.__houston.history.push(auditRecord);

        if (!silent) {
          console.warn(
            `🛑 [Houston Risk Guard] Prevented ${assessedRisk.toUpperCase()}-risk action on "${stepId}" (maxAllowedRisk="${maxAllowedRisk}"): ${riskJustification || blockedReason}`,
          );
        }

        if (onRiskExceeded === 'throw') {
          throw error;
        }
        return null;
      }

      const auditRecord = appendAuditEntry({
        stepId,
        error: error.message,
        action: resolution.action,
        riskLevel: assessedRisk,
        maxAllowedRisk,
        riskJustification,
        originalValue: resolution.originalValue ?? originalSnapshot,
        fixedValue:
          resolution.action === 'retry'
            ? (item !== null ? safeClone(item) : resolution.fixedValue)
            : null,
        reason: resolution.reason || resolution.summary || `Resolved with ${resolution.action}`,
        filesPatched: resolution.filesPatched || [],
      }, auditLogPath);

      globalThis.__houston.history.push(auditRecord);

      if (resolution.action === 'retry') {
        if (!silent) {
          console.log(
            `🔧 [Houston] Live fix applied [risk=${assessedRisk.toUpperCase()} <= ${maxAllowedRisk.toUpperCase()}] (${auditRecord.reason}). Retrying "${stepId}"...`,
          );
        }
        continue;
      }

      if (resolution.action === 'skip' || resolution.action === 'blocked') {
        if (!silent) {
          console.warn(`⏭️  [Houston] Skipping "${stepId}": ${auditRecord.reason}`);
        }
        return null;
      }

      throw error;
    }
  }

  return null;
}

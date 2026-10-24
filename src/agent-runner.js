#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { parseArgs } from 'node:util';
import { DEFAULT_INCIDENT_FILE, DEFAULT_ACTION_FILE } from './inspector-trap.js';
import { isRiskAllowed } from './audit-logger.js';

const { values: flags } = parseArgs({
  options: {
    incident: { type: 'string', default: DEFAULT_INCIDENT_FILE },
    'action-file': { type: 'string', default: DEFAULT_ACTION_FILE },
    'audit-log': { type: 'string' },
    model: { type: 'string', default: 'gemini-3.8-flash' },
    'max-risk': { type: 'string', default: 'low' },
    auto: { type: 'boolean', default: false },
    retry: { type: 'boolean', default: false },
    skip: { type: 'boolean', default: false },
    status: { type: 'boolean', default: false },
    eval: { type: 'string' },
    reason: { type: 'string' },
    risk: { type: 'string' },
  },
  strict: false,
});

function loadIncident(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function writeAction(actionFile, payload) {
  fs.writeFileSync(actionFile, JSON.stringify(payload, null, 2), 'utf8');
}

export async function connectCDP(wsUrl) {
  if (!wsUrl) return null;
  try {
    const ws = new WebSocket(wsUrl);
    let msgId = 1;
    const send = (method, params = {}) =>
      new Promise((resolve, reject) => {
        const id = msgId++;
        const timer = setTimeout(() => {
          ws.removeEventListener('message', onMessage);
          reject(new Error(`CDP command ${method} timed out`));
        }, 5000);
        const onMessage = (evt) => {
          const msg = JSON.parse(evt.data);
          if (msg.id === id) {
            clearTimeout(timer);
            ws.removeEventListener('message', onMessage);
            resolve(msg.result);
          }
        };
        ws.addEventListener('message', onMessage);
        ws.send(JSON.stringify({ id, method, params }));
      });

    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP WebSocket open timeout')), 3000);
      ws.addEventListener('open', () => {
        clearTimeout(timer);
        resolve();
      }, { once: true });
      ws.addEventListener('error', (err) => {
        clearTimeout(timer);
        reject(err);
      }, { once: true });
    });

    await send('Debugger.enable');
    return {
      ws,
      send,
      async evalRuntime(expression) {
        const res = await send('Runtime.evaluate', {
          expression,
          returnByValue: true,
          awaitPromise: true,
        });
        if (res?.exceptionDetails) {
          return { error: res.result?.description || res.exceptionDetails.text };
        }
        return res?.result?.value !== undefined ? res.result.value : res?.result;
      },
      async resumeAndClose() {
        try {
          await send('Debugger.resume');
        } catch {
          // ignore if not paused
        }
        try {
          ws.close();
        } catch {
          // ignore
        }
      },
    };
  } catch (err) {
    console.warn(`[Houston Agent] CDP connection warning: ${err.message}`);
    return null;
  }
}

const GEMINI_TOOLS = [
  {
    functionDeclarations: [
      {
        name: 'eval_runtime',
        description:
          'Evaluate a JavaScript expression in the live V8 runtime. Inspect or mutate `globalThis.__houston.currentItem` or `globalThis.__houston.context`.',
        parameters: {
          type: 'OBJECT',
          properties: {
            expression: {
              type: 'STRING',
              description: 'JavaScript expression to evaluate in the paused Node.js process',
            },
          },
          required: ['expression'],
        },
      },
      {
        name: 'read_code_file',
        description: 'Read a source code file on disk to understand validation or scraper logic.',
        parameters: {
          type: 'OBJECT',
          properties: {
            filePath: { type: 'STRING', description: 'Path to the file' },
          },
          required: ['filePath'],
        },
      },
      {
        name: 'patch_code_file',
        description:
          'Patch a source code file on disk by replacing an exact string. Requires self-assessing the risk level first.',
        parameters: {
          type: 'OBJECT',
          properties: {
            filePath: { type: 'STRING', description: 'Path to the file' },
            search: { type: 'STRING', description: 'Exact string to search for' },
            replace: { type: 'STRING', description: 'Replacement string' },
            riskLevel: {
              type: 'STRING',
              enum: ['low', 'medium', 'high'],
              description: 'Self-assessed risk level of this code change',
            },
            riskJustification: {
              type: 'STRING',
              description: 'Why this patch carries this risk level',
            },
          },
          required: ['filePath', 'search', 'replace', 'riskLevel', 'riskJustification'],
        },
      },
      {
        name: 'complete_healing',
        description:
          'Finish the live investigation, self-assess the risk level of the healing action, record the audit reason, and resume the job.',
        parameters: {
          type: 'OBJECT',
          properties: {
            action: {
              type: 'STRING',
              enum: ['retry', 'skip', 'blocked', 'abort'],
              description:
                '"retry" if state/code was safely fixed within allowed risk, "blocked" if the required fix exceeds maxAllowedRisk, "skip" to bypass item, or "abort"',
            },
            riskLevel: {
              type: 'STRING',
              enum: ['low', 'medium', 'high'],
              description:
                'Self-assessed risk level of the healing action: "low" (formatting, date normalization, whitespace trimming), "medium" (defaulting optional metadata, selector tweaks), or "high" (financial amounts, prices, balances, quantities, auth/permissions, core business logic)',
            },
            riskJustification: {
              type: 'STRING',
              description:
                'Justification for the chosen riskLevel (why this fix is low, medium, or high risk)',
            },
            reason: {
              type: 'STRING',
              description: 'Concise explanation of what was investigated and fixed (or blocked) for the human audit log',
            },
          },
          required: ['action', 'riskLevel', 'riskJustification', 'reason'],
        },
      },
    ],
  },
];

async function runGeminiLoop({ incident, cdp, model, maxAllowedRisk = 'low', actionFile }) {
  const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return false;
  }

  console.log(
    `🛰️  [Houston AI] Investigating "${incident.stepId}" live with ${model} (maxAllowedRisk="${maxAllowedRisk}")...`,
  );
  const filesPatched = [];

  const systemPrompt = [
    'You are Houston ("Houston, we have a problem... Investigate it live and fix it for me!"), an autonomous V8 runtime debugger for Node.js.',
    'A batch step just threw an error and is paused.',
    'The current item being processed is stored at `globalThis.__houston.currentItem` and shared context at `globalThis.__houston.context`.',
    '',
    'CRITICAL RISK SELF-ASSESSMENT POLICY:',
    `The maximum allowed risk level for automatic execution is "${maxAllowedRisk.toUpperCase()}".`,
    'Before mutating any state or code, you MUST self-assess the risk level ("low", "medium", or "high"):',
    '- "low": Safe, non-destructive formatting fixes (e.g., converting DD/MM/YYYY date strings to ISO-8601 YYYY-MM-DD, trimming whitespace, normalizing case).',
    '- "medium": Filling in missing optional non-financial metadata or updating a non-destructive CSS/DOM selector.',
    '- "high": Modifying financial amounts, prices, royalty fees, account balances, inventory quantities, user/account IDs, permissions, or bypassing security/business validation rules.',
    '',
    `If the required fix has a risk level higher than "${maxAllowedRisk}", DO NOT mutate \`globalThis.__houston.currentItem\` or patch files! Instead, immediately call \`complete_healing\` with action="blocked", the assessed \`riskLevel\`, \`riskJustification\`, and \`reason\`.`,
    `If the fix is within the "${maxAllowedRisk}" threshold, apply the fix via \`eval_runtime\` (or \`patch_code_file\`) and call \`complete_healing\` with action="retry", \`riskLevel\`, \`riskJustification\`, and \`reason\`.`,
  ].join('\n');

  const userPrompt = [
    `Step ID: ${incident.stepId}`,
    `Max Allowed Risk: ${maxAllowedRisk}`,
    `Error: ${incident.error?.message}`,
    `Stack:\n${incident.error?.stack}`,
    `Current Item Preview: ${JSON.stringify(incident.currentItemPreview)}`,
    `Relevant Files: ${JSON.stringify(incident.relevantFiles)}`,
  ].join('\n\n');

  const contents = [{ role: 'user', parts: [{ text: `${systemPrompt}\n\n${userPrompt}` }] }];
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

  for (let turn = 1; turn <= 8; turn++) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents, tools: GEMINI_TOOLS }),
    });

    if (!res.ok) {
      console.warn(`[Houston AI] Gemini API returned ${res.status}: ${await res.text()}`);
      return false;
    }

    const data = await res.json();
    const parts = data.candidates?.[0]?.content?.parts;
    if (!parts?.length) break;

    contents.push({ role: 'model', parts });
    const callPart = parts.find((p) => p.functionCall);
    if (!callPart) break;

    const { name, args, id } = callPart.functionCall;
    console.log(`  ↳ [Houston Tool] ${name}(${JSON.stringify(args)})`);

    if (name === 'complete_healing') {
      const updatedItem = cdp ? await cdp.evalRuntime('globalThis.__houston.currentItem') : null;
      writeAction(actionFile, {
        action: args.action,
        riskLevel: args.riskLevel || 'low',
        riskJustification: args.riskJustification || null,
        reason: args.reason,
        originalValue: incident.currentItemPreview,
        fixedValue: updatedItem,
        filesPatched,
      });
      await cdp?.resumeAndClose();
      return true;
    }

    let output = {};
    if (name === 'eval_runtime') {
      output = cdp ? await cdp.evalRuntime(args.expression) : { error: 'No CDP connection' };
    } else if (name === 'read_code_file') {
      const target = path.resolve(args.filePath);
      output = fs.existsSync(target)
        ? { content: fs.readFileSync(target, 'utf8') }
        : { error: `File not found: ${args.filePath}` };
    } else if (name === 'patch_code_file') {
      if (!isRiskAllowed(args.riskLevel || 'medium', maxAllowedRisk)) {
        output = {
          error: `Risk Guardrail Blocked: patch assessed as "${args.riskLevel}" risk, which exceeds maxAllowedRisk="${maxAllowedRisk}".`,
        };
      } else {
        const target = path.resolve(args.filePath);
        if (fs.existsSync(target)) {
          const content = fs.readFileSync(target, 'utf8');
          if (content.includes(args.search)) {
            fs.writeFileSync(target, content.replace(args.search, args.replace), 'utf8');
            filesPatched.push(target);
            output = { success: true };
          } else {
            output = { error: 'Search string not found' };
          }
        } else {
          output = { error: 'File not found' };
        }
      }
    }

    contents.push({
      role: 'user',
      parts: [{ functionResponse: { name, id, response: { output } } }],
    });
  }

  return false;
}

const HIGH_RISK_KEY_PATTERN = /(price|amount|balance|royalty|fee|cost|total|salary|payout|usd|cents|quantity|role|permission|auth)/i;

/**
 * Built-in live heuristic healer when running offline or without an LLM API key.
 * Inspects `globalThis.__houston.currentItem` via V8 CDP, self-assesses the risk level of
 * potential repairs, and only executes mutations permitted by `maxAllowedRisk`.
 */
async function runBuiltInLiveHealer({ incident, cdp, maxAllowedRisk = 'low', actionFile }) {
  if (!cdp) return false;
  console.log(
    `🛰️  [Houston Live Healer] Inspecting V8 runtime memory via CDP (maxAllowedRisk="${maxAllowedRisk}")...`,
  );

  const currentItem = await cdp.evalRuntime('globalThis.__houston.currentItem');
  if (!currentItem || typeof currentItem !== 'object') {
    return false;
  }

  const errMsg = incident.error?.message || '';

  // 1. Check if the failure involves a high-risk financial / sensitive field
  for (const [key, val] of Object.entries(currentItem)) {
    const isSensitiveField = HIGH_RISK_KEY_PATTERN.test(key);
    const isInvalidNumber =
      isSensitiveField && (typeof val !== 'number' || Number.isNaN(val) || val < 0);
    const errorMentionsKey =
      isSensitiveField && errMsg.toLowerCase().includes(key.toLowerCase());

    if (isInvalidNumber || errorMentionsKey) {
      const assessedRisk = 'high';
      const riskJustification = `Field "${key}" (${JSON.stringify(val)}) is a sensitive financial/business value; mutating or defaulting it carries HIGH data-integrity risk.`;

      console.log(
        `⚖️  [Houston Risk Assessment] Assessed RISK=${assessedRisk.toUpperCase()} for "${key}": ${riskJustification}`,
      );

      if (!isRiskAllowed(assessedRisk, maxAllowedRisk)) {
        writeAction(actionFile, {
          action: 'blocked',
          riskLevel: assessedRisk,
          riskJustification,
          reason: `Refused to auto-mutate sensitive field "${key}" (${JSON.stringify(val)}) under maxAllowedRisk="${maxAllowedRisk}"`,
          originalValue: incident.currentItemPreview,
          fixedValue: null,
        });
        await cdp.resumeAndClose();
        return true;
      }

      // Only reached if user explicitly configured maxAllowedRisk: 'high'
      const safeNumeric = typeof val === 'number' && !Number.isNaN(val) ? Math.abs(val) : 0;
      await cdp.evalRuntime(
        `globalThis.__houston.currentItem[${JSON.stringify(key)}] = ${JSON.stringify(safeNumeric)}`,
      );
      const updatedItem = await cdp.evalRuntime('globalThis.__houston.currentItem');
      writeAction(actionFile, {
        action: 'retry',
        riskLevel: assessedRisk,
        riskJustification,
        reason: `Normalized high-risk field "${key}" from ${JSON.stringify(val)} to ${JSON.stringify(safeNumeric)} (permitted by maxAllowedRisk="${maxAllowedRisk}")`,
        originalValue: incident.currentItemPreview,
        fixedValue: updatedItem,
      });
      await cdp.resumeAndClose();
      return true;
    }
  }

  // 2. Check for low-risk formatting issues (date format conversion, whitespace trimming)
  let fixed = false;
  const reasons = [];
  const assessedRisk = 'low';
  const riskJustification =
    'Lossless string/date format normalization (converting DD/MM/YYYY to ISO-8601 or trimming whitespace) without altering semantic business values.';

  for (const [key, val] of Object.entries(currentItem)) {
    if (typeof val === 'string' && /^\d{2}\/\d{2}\/\d{4}$/.test(val.trim())) {
      const [dd, mm, yyyy] = val.trim().split('/');
      const iso = `${yyyy}-${mm}-${dd}`;
      if (isRiskAllowed(assessedRisk, maxAllowedRisk)) {
        await cdp.evalRuntime(
          `globalThis.__houston.currentItem[${JSON.stringify(key)}] = ${JSON.stringify(iso)}`,
        );
      }
      fixed = true;
      reasons.push(`Normalized ${key} from DD/MM/YYYY ("${val}") to ISO-8601 ("${iso}")`);
    } else if (typeof val === 'string' && val !== val.trim()) {
      const trimmed = val.trim();
      if (isRiskAllowed(assessedRisk, maxAllowedRisk)) {
        await cdp.evalRuntime(
          `globalThis.__houston.currentItem[${JSON.stringify(key)}] = ${JSON.stringify(trimmed)}`,
        );
      }
      fixed = true;
      reasons.push(`Trimmed extraneous whitespace on ${key}`);
    }
  }

  if (fixed) {
    console.log(
      `⚖️  [Houston Risk Assessment] Assessed RISK=${assessedRisk.toUpperCase()}: ${riskJustification}`,
    );
    const updatedItem = await cdp.evalRuntime('globalThis.__houston.currentItem');
    const reason = reasons.join('; ');
    console.log(`✅ [Houston Live Healer] Fixed in V8 memory: ${reason}`);
    writeAction(actionFile, {
      action: 'retry',
      riskLevel: assessedRisk,
      riskJustification,
      reason,
      originalValue: incident.currentItemPreview,
      fixedValue: updatedItem,
    });
    await cdp.resumeAndClose();
    return true;
  }

  return false;
}

async function main() {
  const incidentFile = flags.incident || DEFAULT_INCIDENT_FILE;
  const actionFile = flags['action-file'] || DEFAULT_ACTION_FILE;
  const incident = loadIncident(incidentFile);

  if (!incident) {
    console.log(`No active Houston incident found at ${incidentFile}`);
    process.exit(0);
  }

  if (flags.status) {
    console.log(JSON.stringify(incident, null, 2));
    process.exit(0);
  }

  const cdp = await connectCDP(incident.inspectorUrl);

  if (flags.eval && cdp) {
    const val = await cdp.evalRuntime(flags.eval);
    console.log(JSON.stringify(val, null, 2));
    await cdp.resumeAndClose();
    process.exit(0);
  }

  const maxAllowedRisk = flags['max-risk'] || incident.maxAllowedRisk || 'low';

  if (flags.retry) {
    const updatedItem = cdp ? await cdp.evalRuntime('globalThis.__houston.currentItem') : null;
    writeAction(actionFile, {
      action: 'retry',
      riskLevel: flags.risk || 'low',
      riskJustification: 'Manual CLI retry',
      reason: flags.reason || 'Manual CLI retry',
      originalValue: incident.currentItemPreview,
      fixedValue: updatedItem,
    });
    await cdp?.resumeAndClose();
    process.exit(0);
  }

  if (flags.skip) {
    writeAction(actionFile, {
      action: 'skip',
      riskLevel: 'low',
      riskJustification: 'Manual CLI skip',
      reason: flags.reason || 'Manual CLI skip',
    });
    await cdp?.resumeAndClose();
    process.exit(0);
  }

  if (flags.auto) {
    const aiHealed = await runGeminiLoop({
      incident,
      cdp,
      model: flags.model,
      maxAllowedRisk,
      actionFile,
    });
    if (aiHealed) process.exit(0);

    const heuristicHealed = await runBuiltInLiveHealer({
      incident,
      cdp,
      maxAllowedRisk,
      actionFile,
    });
    if (heuristicHealed) process.exit(0);

    writeAction(actionFile, {
      action: 'skip',
      riskLevel: 'low',
      riskJustification: 'No automated fix applied',
      reason: 'Autonomous healer could not repair item; skipping step.',
    });
    await cdp?.resumeAndClose();
    process.exit(0);
  }

  // Interactive REPL
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const promptUser = () => {
    rl.question(
      '\n🛰️  Houston Action: [r]etry | [s]kip | [u] auto-fix live | [e]val JS | [q]uit: ',
      async (ans) => {
        const cmd = ans.trim().toLowerCase();
        if (cmd === 'r' || cmd === 'retry') {
          const updatedItem = cdp ? await cdp.evalRuntime('globalThis.__houston.currentItem') : null;
          writeAction(actionFile, {
            action: 'retry',
            riskLevel: 'low',
            riskJustification: 'Interactive operator retry',
            reason: 'Interactive retry',
            originalValue: incident.currentItemPreview,
            fixedValue: updatedItem,
          });
          await cdp?.resumeAndClose();
          rl.close();
          process.exit(0);
        } else if (cmd === 's' || cmd === 'skip') {
          writeAction(actionFile, {
            action: 'skip',
            riskLevel: 'low',
            riskJustification: 'Interactive operator skip',
            reason: 'Interactive skip',
          });
          await cdp?.resumeAndClose();
          rl.close();
          process.exit(0);
        } else if (cmd === 'u' || cmd === 'auto') {
          rl.close();
          const healed =
            (await runGeminiLoop({ incident, cdp, model: flags.model, maxAllowedRisk, actionFile })) ||
            (await runBuiltInLiveHealer({ incident, cdp, maxAllowedRisk, actionFile }));
          if (!healed) {
            writeAction(actionFile, {
              action: 'skip',
              riskLevel: 'low',
              riskJustification: 'Auto-fix unsuccessful',
              reason: 'Auto-fix unsuccessful',
            });
            await cdp?.resumeAndClose();
          }
          process.exit(0);
        } else if (cmd === 'e' || cmd === 'eval') {
          rl.question('JS Expression (e.g. globalThis.__houston.currentItem): ', async (expr) => {
            const out = cdp ? await cdp.evalRuntime(expr) : 'No CDP connection';
            console.log('Result:', out);
            promptUser();
          });
        } else {
          await cdp?.resumeAndClose();
          rl.close();
          process.exit(0);
        }
      },
    );
  };

  promptUser();
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isDirectRun) {
  main().catch((err) => {
    console.error('[Houston Agent Error]:', err);
    process.exit(1);
  });
}

# 🚀 Houston (`houston-js`)

> *"Houston, we have a problem... Investigate it live and fix it for me!"*

**Houston** is a zero-dependency self-healing runtime framework for Node.js batch jobs, ETL pipelines, and scrapers.

When a step fails, Houston prevents your process from crashing: it opens Node's native `node:inspector` (Chrome DevTools Protocol), pauses on the failure, and dispatches an AI agent (or interactive REPL) to **inspect live V8 variables, sanitize broken state in place or patch code on disk, record an audit trail, and resume execution without restarting the pipeline.**

---

## Features

- **Zero External Dependencies**: Built strictly on Node.js native primitives (`node:inspector`, `node:child_process`, `node:fs`, and standard `WebSocket` / `fetch`).
- **Live V8 Memory Inspection & Mutation**: Connects over CDP (`Runtime.evaluate`) to read and repair `globalThis.__houston.currentItem` and context in place.
- **Autonomous AI & Offline Heuristic Modes**:
  - With `GOOGLE_API_KEY` or `GEMINI_API_KEY`, Gemini autonomously calls `eval_runtime`, `read_code_file`, `patch_code_file`, and `complete_healing`.
  - Without an API key, Houston's built-in CDP live healer still inspects V8 memory and repairs common date/string formatting issues automatically.
- **Risk Self-Assessment & Guardrails (`maxAllowedRisk`)**: The agent is required to self-assess the risk level (`low`, `medium`, or `high`) and justification of every proposed fix. By default (`maxAllowedRisk: 'low'`), only low-risk formatting normalizations are automatically executed; medium or high-risk mutations (e.g., financial amounts, balances, permissions) are blocked, rolled back in V8 memory if touched, and logged as `"action": "blocked"` for human review.
- **Human-in-the-Loop Audit Log (`houston_audit.jsonl`)**: Every autonomous fix or blocked high-risk action is logged as structured JSONL (original value, fixed value, assessed risk level, risk justification, error, and reasoning) so engineers can review and harden upstream validators the next morning.

---

## Quickstart

### 1. Install

```bash
npm install houston-js
```

### 2. Wrap Batch Steps with `houston.trap()`

```javascript
import { Houston } from 'houston-js';

const houston = new Houston({
  mode: 'auto', // 'auto' | 'interactive' | 'off'
  model: 'gemini-3.8-flash',
  maxAllowedRisk: 'low', // 'low' (default) | 'medium' | 'high'
  onRiskExceeded: 'skip', // 'skip' (default) | 'throw'
  auditLogPath: './houston_audit.jsonl',
  maxRetries: 2,
});

const articles = [
  { id: 101, title: 'Release Notes', publishedAt: '2026-10-20' },
  { id: 102, title: 'Deep Dive', publishedAt: '24/10/2026' }, // Malformed UK date
];

for (const article of articles) {
  const result = await houston.trap(
    `ingest-article-${article.id}`,
    (liveItem) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(liveItem.publishedAt)) {
        throw new Error(`Invalid ISO date: ${liveItem.publishedAt}`);
      }
      return { ...liveItem, ok: true };
    },
    { item: article },
  );

  console.log('Processed:', result);
}

houston.close();
```

---

## Try the Included Example App

Clone the repo and run the example batch pipeline:

```bash
cd ~/web/Houston
npm run example
```

### What happens when you run `npm run example`:
1. Article `#101` ingests cleanly.
2. Article `#102` (`"24/10/2026"`) and `#103` (`"  2026-10-22  "`) throw ISO-8601 date validation errors.
3. Houston catches each error, opens the V8 inspector on `127.0.0.1:9229`, and launches the agent:
   ```text
   ══════════════════════════════════════════════════════════════════════════════
   🚀 HOUSTON, WE HAVE A PROBLEM... Investigate it live and fix it for me!
   ──────────────────────────────────────────────────────────────────────────────
     Step        : ingest-article-102
     Error       : Invalid ISO-8601 date for article #102 ("Telemetry Deep Dive"): "24/10/2026"
     Mode        : auto (Max Auto-Heal Risk: LOW)
     V8 CDP URL  : ws://127.0.0.1:9229/...
   ══════════════════════════════════════════════════════════════════════════════
   ```
4. The agent inspects `globalThis.__houston.currentItem` over CDP, self-assesses the date/whitespace normalization as **`LOW` risk** (`<= maxAllowedRisk`), mutates `publishedAt` in live memory, logs the audit record, and retries.
5. Article `#104` throws an error on a corrupt financial field (`royaltyFee: -450`). The agent self-assesses mutating a monetary value as **`HIGH` risk** (`> maxAllowedRisk="low"`), **blocks** the automatic mutation, logs `"action": "blocked"` to `houston_audit.jsonl` for human review, and safely skips to `#105`.

---

## Risk Self-Assessment Levels

| Risk Level | Examples | Default Behavior (`maxAllowedRisk: 'low'`) |
| :--- | :--- | :--- |
| **`low`** | Date format conversion (`DD/MM/YYYY` → `YYYY-MM-DD`), trimming whitespace, casing normalization | ✅ **Auto-executed in V8 memory** |
| **`medium`** | Defaulting optional non-financial metadata (e.g., missing category tag), updating non-destructive CSS selectors | 🛑 **Blocked & logged** (unless `maxAllowedRisk: 'medium'` or `'high'`) |
| **`high`** | Modifying financial amounts (`royaltyFee`, `price`, `balance`), inventory quantities, user IDs, or auth permissions | 🛑 **Blocked, rolled back & logged** (unless `maxAllowedRisk: 'high'`) |

---

## CLI Companion (`npx houston`)

When running in `mode: 'interactive'` (or attaching from another terminal), you can use the `houston` CLI:

```bash
# View current trapped incident details
npx houston --status

# Evaluate a JavaScript expression in the paused V8 process
npx houston --eval "globalThis.__houston.currentItem"

# Trigger an autonomous live repair
npx houston --auto

# Retry or skip the current trapped step manually
npx houston --retry --reason "Patched selector in scraper"
npx houston --skip --reason "Upstream record deprecated"
```

---

## Running Tests

```bash
npm test
```

---

## License

MIT

# Security Policy & Threat Model

## Overview

**Houston (`houston-js`)** attaches to a live Node.js process over the built-in V8 Inspector (`node:inspector` / Chrome DevTools Protocol) on `127.0.0.1` to diagnose and recover from runtime failures in batch jobs, ETL pipelines, and scrapers.

### Built-In Safeguards
1. **Fail-Closed Risk Guardrail (`maxAllowedRisk`)**:
   - Every proposed mutation (`mutate_runtime`, `patch_code_file`, and `complete_healing`) requires a `riskLevel` (`low` | `medium` | `high`).
   - If `riskLevel` is omitted or invalid, Houston **fails closed** by treating the action as `high` risk.
   - By default (`maxAllowedRisk: 'low'`), `medium` and `high` risk actions are blocked and recorded as `"action": "blocked"` in `houston_audit.jsonl`.
2. **File Access Allowlist (`relevantFiles`) & Opt-In Code Patching (`allowCodePatches`)**:
   - `read_code_file` and `patch_code_file` can **only** access files explicitly passed in `relevantFiles` for that step. Any attempt to read or modify files outside `relevantFiles` (such as `.env` or SSH keys) is rejected.
   - Modifying source files on disk is disabled by default (`allowCodePatches: false`).
3. **Header-Based API Key Authentication**:
   - Gemini API keys (`GOOGLE_API_KEY` / `GEMINI_API_KEY`) are sent via the `x-goog-api-key` HTTP header and are never placed in URLs.

### Limitations & Operational Guidance
- **Cooperative In-Process Guardrail**: Because V8 CDP `Runtime.evaluate` executes inside the target Node.js process, Houston's `Proxy` and `maxAllowedRisk` checks are designed to prevent accidental or over-eager LLM mutations, not to sandbox untrusted arbitrary code execution. Do not feed untrusted user-controlled prompts into `currentItem` without sanitization.
- **Localhost Inspector Port**: `inspector.open()` binds to `127.0.0.1` (loopback only). Run `houston.close()` when your batch job finishes so the inspector port does not remain open.
- **Audit Log Sensitivity**: `houston_audit.jsonl` records `originalValue` and `fixedValue` for human review. Avoid passing raw credentials or unredacted PII inside `item`.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Houston, connectCDP } from '../src/index.js';

test('Houston traps failure, mutates live variable over V8 CDP, logs audit trail, and retries step', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-test-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    auditLogPath,
    silent: true,
  });

  const brokenArticle = { id: 42, publishedAt: '24/10/2026' };

  const result = await houston.trap(
    'test-article-42',
    (item) => {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(item.publishedAt)) {
        throw new Error(`Invalid ISO date: ${item.publishedAt}`);
      }
      return { id: item.id, iso: item.publishedAt };
    },
    {
      item: brokenArticle,
      incidentFile,
      actionFile,
    },
  );

  houston.close();

  assert.deepEqual(result, { id: 42, iso: '2026-10-24' });
  assert.equal(brokenArticle.publishedAt, '2026-10-24');

  const auditEntries = houston.getAuditHistory();
  assert.equal(auditEntries.length, 1);
  assert.equal(auditEntries[0].stepId, 'test-article-42');
  assert.equal(auditEntries[0].action, 'retry');
  assert.deepEqual(auditEntries[0].originalValue, { id: 42, publishedAt: '24/10/2026' });
  assert.deepEqual(auditEntries[0].fixedValue, { id: 42, publishedAt: '2026-10-24' });
});

test('Houston supports custom onTrap handler with direct CDP inspection and skip action', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-skip-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    auditLogPath,
    silent: true,
    onTrap: async ({ inspectorUrl }) => {
      const cdp = await connectCDP(inspectorUrl);
      const liveStep = await cdp.evalRuntime('globalThis.__houston.currentStep');
      assert.equal(liveStep, 'unrecoverable-step');
      await cdp.resumeAndClose();
      return {
        action: 'skip',
        reason: 'Corrupted payload; skipping record safely',
      };
    },
  });

  const outcome = await houston.trap(
    'unrecoverable-step',
    () => {
      throw new Error('Corrupt binary header');
    },
    {
      item: { id: 99 },
      incidentFile,
      actionFile,
    },
  );

  houston.close();

  assert.equal(outcome, null);
  const audit = houston.getAuditHistory();
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'skip');
  assert.match(audit[0].reason, /Corrupted payload/);
});

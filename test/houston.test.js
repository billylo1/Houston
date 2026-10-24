import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { Houston, connectCDP } from '../src/index.js';

test('Houston traps failure, self-assesses low risk, mutates live variable over V8 CDP, logs audit trail, and retries step', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-test-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    maxAllowedRisk: 'low',
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
  assert.equal(auditEntries[0].riskLevel, 'low');
  assert.equal(auditEntries[0].maxAllowedRisk, 'low');
  assert.deepEqual(auditEntries[0].originalValue, { id: 42, publishedAt: '24/10/2026' });
  assert.deepEqual(auditEntries[0].fixedValue, { id: 42, publishedAt: '2026-10-24' });
});

test('Houston prevents high-risk mutations before execution and blocks direct writes via V8 Proxy', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-risk-prevent-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    maxAllowedRisk: 'low',
    auditLogPath,
    silent: true,
    onTrap: async ({ inspectorUrl, maxAllowedRisk }) => {
      const cdp = await connectCDP(inspectorUrl, { maxAllowedRisk });

      // 1. Attempt a direct write during read-only inspection -> blocked by V8 Proxy
      const directWriteAttempt = await cdp.inspectRuntime(
        'globalThis.__houston.currentItem.royaltyFee = 0',
      );
      assert.match(directWriteAttempt.error, /Mutation of "royaltyFee" prevented/);

      // 2. Attempt a high-risk mutation via mutateRuntime -> prevented BEFORE sending CDP command
      const gatedAttempt = await cdp.mutateRuntime(
        'globalThis.__houston.currentItem.royaltyFee = 0',
        {
          riskLevel: 'high',
          riskJustification: 'Mutating financial royaltyFee alters monetary payout values',
          maxAllowedRisk,
        },
      );
      assert.equal(gatedAttempt.blocked, true);

      // Verify V8 memory was never modified at any point
      const liveValue = await cdp.inspectRuntime('globalThis.__houston.currentItem.royaltyFee');
      assert.equal(liveValue, -450.0);

      await cdp.resumeAndClose();
      return {
        action: 'blocked',
        riskLevel: 'high',
        riskJustification: 'Mutating financial royaltyFee alters monetary payout values',
        reason: 'Prevented high-risk mutation on royaltyFee',
      };
    },
  });

  const sensitiveItem = { id: 77, royaltyFee: -450.0 };

  const outcome = await houston.trap(
    'sensitive-royalty-step',
    (item) => {
      if (item.royaltyFee < 0) {
        throw new Error(`Negative royaltyFee: ${item.royaltyFee}`);
      }
      return item;
    },
    {
      item: sensitiveItem,
      incidentFile,
      actionFile,
    },
  );

  houston.close();

  assert.equal(outcome, null);
  assert.equal(sensitiveItem.royaltyFee, -450.0);

  const audit = houston.getAuditHistory();
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'blocked');
  assert.equal(audit[0].riskLevel, 'high');
  assert.equal(audit[0].maxAllowedRisk, 'low');
  assert.equal(audit[0].fixedValue, null);
});

test('Houston allows medium/high risk actions when maxAllowedRisk is explicitly configured to allow them', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-risk-allow-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    maxAllowedRisk: 'medium',
    auditLogPath,
    silent: true,
    onTrap: async ({ inspectorUrl, maxAllowedRisk }) => {
      const cdp = await connectCDP(inspectorUrl, { maxAllowedRisk });
      await cdp.mutateRuntime('globalThis.__houston.currentItem.category = "uncategorized"', {
        riskLevel: 'medium',
        riskJustification: 'Defaulting optional non-financial category metadata',
        maxAllowedRisk,
      });
      await cdp.resumeAndClose();
      return {
        action: 'retry',
        riskLevel: 'medium',
        riskJustification: 'Defaulting optional non-financial category metadata',
        reason: 'Defaulted missing category to "uncategorized"',
      };
    },
  });

  const item = { id: 88, category: null };
  const result = await houston.trap(
    'medium-risk-step',
    (liveItem) => {
      if (!liveItem.category) throw new Error('Missing category');
      return liveItem;
    },
    { item, incidentFile, actionFile },
  );

  houston.close();

  assert.equal(result.category, 'uncategorized');
  const audit = houston.getAuditHistory();
  assert.equal(audit.length, 1);
  assert.equal(audit[0].action, 'retry');
  assert.equal(audit[0].riskLevel, 'medium');
  assert.equal(audit[0].maxAllowedRisk, 'medium');
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

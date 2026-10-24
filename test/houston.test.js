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

test('Houston blocks high-risk healing actions when maxAllowedRisk is low and rolls back any in-memory mutation', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'houston-risk-block-'));
  const auditLogPath = path.join(tmpDir, 'audit.jsonl');
  const incidentFile = path.join(tmpDir, 'incident.json');
  const actionFile = path.join(tmpDir, 'action.json');

  const houston = new Houston({
    mode: 'auto',
    maxAllowedRisk: 'low',
    auditLogPath,
    silent: true,
    onTrap: async ({ inspectorUrl }) => {
      // Simulate an over-eager agent attempting to mutate a sensitive financial field over CDP
      const cdp = await connectCDP(inspectorUrl);
      await cdp.evalRuntime('globalThis.__houston.currentItem.royaltyFee = 0');
      await cdp.resumeAndClose();
      return {
        action: 'retry',
        riskLevel: 'high',
        riskJustification: 'Mutating financial royaltyFee alters monetary payout values',
        reason: 'Attempted to zero out negative royaltyFee',
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

  // Step was blocked and skipped rather than retried
  assert.equal(outcome, null);
  // In-memory item was rolled back to its original unmutated snapshot (-450.0, not 0)
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
    onTrap: async ({ inspectorUrl }) => {
      const cdp = await connectCDP(inspectorUrl);
      await cdp.evalRuntime('globalThis.__houston.currentItem.category = "uncategorized"');
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

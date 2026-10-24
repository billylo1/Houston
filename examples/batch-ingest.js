import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Houston } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);

// Simulated batch dataset with:
// - 2 low-risk formatting errors (date format & whitespace) -> auto-healed live
// - 1 high-risk financial anomaly (negative royaltyFee) -> blocked by risk guardrail
const articles = [
  { id: 101, title: 'Launching Orbit v2', publishedAt: '2026-10-20', royaltyFee: 120.0, category: 'engineering' },
  { id: 102, title: 'Telemetry Deep Dive', publishedAt: '24/10/2026', royaltyFee: 85.5, category: 'ops' }, // LOW RISK: DD/MM/YYYY date
  { id: 103, title: 'Zero-Downtime Workers', publishedAt: '  2026-10-22  ', royaltyFee: 95.0, category: 'infra' }, // LOW RISK: Unsanitized whitespace
  { id: 104, title: 'Enterprise Licensing Guide', publishedAt: '2026-10-23', royaltyFee: -450.0, category: 'finance' }, // HIGH RISK: Corrupt financial royaltyFee
  { id: 105, title: 'Q4 Roadmap', publishedAt: '2026-10-24', royaltyFee: 110.0, category: 'product' },
];

/**
 * Strict schema validator for article publishing and author royalty fees.
 */
function ingestArticle(article) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(article.publishedAt)) {
    throw new Error(
      `Invalid ISO-8601 date for article #${article.id} ("${article.title}"): "${article.publishedAt}"`,
    );
  }
  if (typeof article.royaltyFee !== 'number' || article.royaltyFee < 0) {
    throw new Error(
      `Invalid financial royaltyFee for article #${article.id} ("${article.title}"): ${article.royaltyFee}`,
    );
  }
  return {
    id: article.id,
    title: article.title,
    publishedIso: article.publishedAt,
    royaltyFee: article.royaltyFee,
    epochMs: new Date(`${article.publishedAt}T00:00:00Z`).getTime(),
  };
}

async function main() {
  const auditLogPath = path.resolve(process.cwd(), 'houston_audit.jsonl');
  if (fs.existsSync(auditLogPath)) {
    fs.unlinkSync(auditLogPath);
  }

  const houston = new Houston({
    mode: 'auto', // Uses Gemini if GOOGLE_API_KEY is set, or built-in CDP live healer offline
    maxAllowedRisk: 'low', // Only auto-execute 'low' risk fixes; block 'medium' / 'high' risk mutations
    onRiskExceeded: 'skip', // Safely skip & log high-risk items without crashing the whole batch
    auditLogPath,
    maxRetries: 2,
    context: { pipeline: 'article-ingest' },
  });

  console.log(`🛰️  Starting Batch Ingestion Pipeline (${articles.length} records, maxAllowedRisk="low")...\n`);
  const ingested = [];

  for (const article of articles) {
    const record = await houston.trap(
      `ingest-article-${article.id}`,
      (liveItem) => ingestArticle(liveItem),
      {
        item: article,
        relevantFiles: [__filename],
      },
    );

    if (record) {
      console.log(
        `✅ Ingested article #${record.id}: "${record.title}" (${record.publishedIso}, royalty=$${record.royaltyFee})`,
      );
      ingested.push(record);
    }
  }

  houston.close();

  console.log(`\n🎉 Batch Complete: ${ingested.length}/${articles.length} articles ingested (1 high-risk item safely blocked for human review).`);
  console.log('\n📋 Human-in-the-Loop Audit Log (houston_audit.jsonl):');
  for (const entry of houston.getAuditHistory()) {
    console.log(JSON.stringify(entry, null, 2));
  }
}

main().catch((err) => {
  console.error('Fatal pipeline failure:', err);
  process.exit(1);
});

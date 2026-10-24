import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Houston } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);

// Simulated batch dataset with 2 malformed records
const articles = [
  { id: 101, title: 'Launching Orbit v2', publishedAt: '2026-10-20', category: 'engineering' },
  { id: 102, title: 'Telemetry Deep Dive', publishedAt: '24/10/2026', category: 'ops' }, // Malformed DD/MM/YYYY date
  { id: 103, title: 'Zero-Downtime Workers', publishedAt: '  2026-10-22  ', category: 'infra' }, // Unsanitized whitespace
  { id: 104, title: 'Q4 Roadmap', publishedAt: '2026-10-24', category: 'product' },
];

/**
 * Strict schema validator that throws on non-ISO-8601 dates.
 */
function ingestArticle(article) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(article.publishedAt)) {
    throw new Error(
      `Invalid ISO-8601 date for article #${article.id} ("${article.title}"): "${article.publishedAt}"`,
    );
  }
  return {
    id: article.id,
    title: article.title,
    publishedIso: article.publishedAt,
    epochMs: new Date(`${article.publishedAt}T00:00:00Z`).getTime(),
  };
}

async function main() {
  const auditLogPath = path.resolve(process.cwd(), 'houston_audit.jsonl');

  const houston = new Houston({
    mode: 'auto', // Uses Gemini if GOOGLE_API_KEY is set, or built-in CDP live healer offline
    auditLogPath,
    maxRetries: 2,
    context: { pipeline: 'article-ingest' },
  });

  console.log('🛰️  Starting Batch Ingestion Pipeline (4 records)...\n');
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
      console.log(`✅ Ingested article #${record.id}: "${record.title}" (${record.publishedIso})`);
      ingested.push(record);
    }
  }

  houston.close();

  console.log(`\n🎉 Batch Complete: ${ingested.length}/${articles.length} articles ingested.`);
  console.log('\n📋 Human-in-the-Loop Audit Log (houston_audit.jsonl):');
  for (const entry of houston.getAuditHistory()) {
    console.log(JSON.stringify(entry, null, 2));
  }
}

main().catch((err) => {
  console.error('Fatal pipeline failure:', err);
  process.exit(1);
});

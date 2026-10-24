#!/usr/bin/env node

import { main } from '../src/agent-runner.js';

main().catch((err) => {
  console.error('[Houston CLI Error]:', err);
  process.exit(1);
});

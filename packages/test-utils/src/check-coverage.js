#!/usr/bin/env node

const { readFileSync } = require('fs');

const coverage = JSON.parse(
  readFileSync('./coverage/summary/coverage-summary.json', 'utf8')
);

const total = coverage.total;

const required = ['lines', 'statements', 'functions', 'branches'];

for (const key of required) {
  if (!total[key] || total[key].pct !== 100) {
    console.error(
      `Coverage for ${key} is ${total[key]?.pct ?? 'N/A'}%. Must be 100%.`
    );
    process.exit(1);
  }
}

console.log('✅ All coverage metrics are at 100%');

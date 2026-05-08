#!/usr/bin/env node

const args = process.argv.slice(2);
const isSingle = args.includes('-s');

const filePath = isSingle
  ? './coverage/coverage-final.json'
  : './coverage/summary/coverage-summary.json';

const { readFileSync } = require('fs');

let coverage;
try {
  coverage = JSON.parse(readFileSync(filePath, 'utf8'));
} catch (e) {
  console.error(`Could not read coverage file at ${filePath}`);
  process.exit(1);
}

const calculateTotals = data => {
  const stats = {
    statements: { total: 0, covered: 0 },
    functions: { total: 0, covered: 0 },
    branches: { total: 0, covered: 0 },
    lines: { total: 0, covered: 0 },
  };

  Object.values(data).forEach(file => {
    stats.statements.total += Object.keys(file.statementMap || {}).length;
    stats.statements.covered += Object.values(file.s || {}).filter(
      h => h > 0
    ).length;

    stats.functions.total += Object.keys(file.fnMap || {}).length;
    stats.functions.covered += Object.values(file.f || {}).filter(
      h => h > 0
    ).length;

    Object.values(file.b || {}).forEach(branchArray => {
      stats.branches.total += branchArray.length;
      stats.branches.covered += branchArray.filter(h => h > 0).length;
    });

    const uniqueLines = new Set(
      Object.values(file.statementMap || {}).map(s => s.start.line)
    );
    stats.lines.total += uniqueLines.size;

    const coveredLines = new Set();
    Object.entries(file.statementMap || {}).forEach(([id, sm]) => {
      if (file.s[id] > 0) coveredLines.add(sm.start.line);
    });
    stats.lines.covered += coveredLines.size;
  });

  const getPct = type => {
    const { total, covered } = stats[type];
    return total === 0 ? 100 : (covered / total) * 100;
  };

  return {
    statements: { pct: getPct('statements') },
    functions: { pct: getPct('functions') },
    branches: { pct: getPct('branches') },
    lines: { pct: getPct('lines') },
  };
};

const total = isSingle ? calculateTotals(coverage) : coverage.total;

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

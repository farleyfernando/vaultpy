const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();

const pythonCandidates = [
  path.join(repoRoot, '.venv', 'Scripts', 'python.exe'),
  path.join(repoRoot, '.venv', 'bin', 'python'),
  'python',
];

const pythonExecutable = pythonCandidates.find(
  (candidate) => candidate === 'python' || existsSync(candidate),
);

if (!pythonExecutable) {
  console.error('Python executable not found for the pre-push checks.');
  process.exit(1);
}

const checks = [
  { name: 'ruff', args: ['-m', 'ruff', 'check', '.'] },
  { name: 'black --check', args: ['-m', 'black', '--check', '.'] },
  { name: 'isort --check-only', args: ['-m', 'isort', '--check-only', '.'] },
];

for (const check of checks) {
  process.stdout.write(`${check.name}.....................................................................`);
  const result = spawnSync(pythonExecutable, check.args, {
    stdio: 'inherit',
    shell: false,
  });

  if (result.error) {
    console.log('Failed');
    console.error(result.error.message);
    process.exit(1);
  }

  if ((result.status ?? 1) !== 0) {
    console.log('Failed');
    process.exit(result.status ?? 1);
  }

  console.log('Passed');
}

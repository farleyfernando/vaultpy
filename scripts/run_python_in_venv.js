const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();
const commandArgs = process.argv.slice(2);

if (commandArgs.length === 0) {
  console.error('No Python command arguments were provided.');
  process.exit(1);
}

const pythonCandidates = [
  path.join(repoRoot, '.venv', 'Scripts', 'python.exe'),
  path.join(repoRoot, '.venv', 'bin', 'python'),
  'python',
];

const pythonExecutable = pythonCandidates.find(
  (candidate) => candidate === 'python' || existsSync(candidate),
);

if (!pythonExecutable) {
  console.error('Python executable not found for the configured hook command.');
  process.exit(1);
}

const result = spawnSync(pythonExecutable, commandArgs, {
  stdio: 'inherit',
  shell: false,
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
